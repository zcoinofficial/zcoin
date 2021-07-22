#include "lelantusjoinsplitbuilder.h"
#include "walletexcept.h"

#include "../primitives/transaction.h"

#include "validation.h"
#include "../policy/policy.h"


#include "../lelantus.h"

#include <boost/format.hpp>
#include <random>

struct CoinCompare
{
    bool operator()( const std::pair<lelantus::PrivateCoin, uint32_t>& left, const std::pair<lelantus::PrivateCoin, uint32_t>& right ) const {
        return left.second < right.second;
    }
};

LelantusJoinSplitBuilder::LelantusJoinSplitBuilder(CWallet& wallet, CHDMintWallet& mintWallet, const CCoinControl *coinControl) :
    wallet(wallet),
    mintWallet(mintWallet)
{
    cs_main.lock();

    try {
        wallet.cs_wallet.lock();
    } catch (...) {
        cs_main.unlock();
        throw;
    }

    this->coinControl = coinControl;
}

LelantusJoinSplitBuilder::~LelantusJoinSplitBuilder()
{
    wallet.cs_wallet.unlock();
    cs_main.unlock();
}

CWalletTx LelantusJoinSplitBuilder::Build(
    const std::vector<CRecipient>& recipients,
    CAmount &fee,
    const std::vector<CAmount>& newMints,
    std::function<void(CTxOut & , LelantusJoinSplitBuilder const &)> outModifier)
{
    if (recipients.empty() && newMints.empty()) {
        throw std::runtime_error(_("Either recipients or newMints has to be nonempty."));
    }

    // calculate total value to spend
    CAmount vOut = 0;
    CAmount mint = 0;
    unsigned recipientsToSubtractFee = 0;

    for (size_t i = 0; i < recipients.size(); i++) {
        auto& recipient = recipients[i];

        if (!MoneyRange(recipient.nAmount)) {
            throw std::runtime_error(boost::str(boost::format(_("Recipient has invalid amount")) % i));
        }

        vOut += recipient.nAmount;

        if (recipient.fSubtractFeeFromAmount) {
            recipientsToSubtractFee++;
        }
    }

    for(const auto& mintValue : newMints) {
        mint += mintValue;
    }

    CWalletTx result;
    CMutableTransaction tx;

    result.fTimeReceivedIsTxTime = true;
    result.BindWallet(&wallet);


    // Discourage fee sniping.
    //
    // For a large miner the value of the transactions in the best block and
    // the mempool can exceed the cost of deliberately attempting to mine two
    // blocks to orphan the current best block. By setting nLockTime such that
    // only the next block can include the transaction, we discourage this
    // practice as the height restricted and limited blocksize gives miners
    // considering fee sniping fewer options for pulling off this attack.
    //
    // A simple way to think about this is from the wallet's point of view we
    // always want the blockchain to move forward. By setting nLockTime this
    // way we're basically making the statement that we only want this
    // transaction to appear in the next block; we don't want to potentially
    // encourage reorgs by allowing transactions to appear at lower heights
    // than the next block in forks of the best chain.
    //
    // Of course, the subsidy is high enough, and transaction volume low
    // enough, that fee sniping isn't a problem yet, but by implementing a fix
    // now we ensure code won't be written that makes assumptions about
    // nLockTime that preclude a fix later.
    tx.nLockTime = chainActive.Height();

    // Secondly occasionally randomly pick a nLockTime even further back, so
    // that transactions that are delayed after signing for whatever reason,
    // e.g. high-latency mix networks and some CoinJoin implementations, have
    // better privacy.
    if (GetRandInt(10) == 0) {
        tx.nLockTime = std::max(0, static_cast<int>(tx.nLockTime) - GetRandInt(100));
    }

    assert(tx.nLockTime <= static_cast<unsigned>(chainActive.Height()));
    assert(tx.nLockTime < LOCKTIME_THRESHOLD);

    // Start with no fee and loop until there is enough fee;
    uint32_t nCountNextUse;
    if (pwalletMain->zwallet) {
        nCountNextUse = pwalletMain->zwallet->GetCount();
    }

    std::list<CSigmaEntry> sigmaCoins = pwalletMain->GetAvailableCoins(coinControl);
    std::list<CLelantusEntry> coins = pwalletMain->GetAvailableLelantusCoins(coinControl);
    std::tie(fee, std::ignore) = wallet.EstimateJoinSplitFee(vOut + mint, recipientsToSubtractFee, sigmaCoins, coins, coinControl);

    for (;;) {
        // In case of not enough fee, reset mint seed counter
        if (pwalletMain->zwallet) {
            pwalletMain->zwallet->SetCount(nCountNextUse);
        }
        CAmount required = vOut + mint;
        CAmount currentVout = vOut;
        tx.vin.clear();
        tx.vout.clear();

        result.fFromMe = true;
        result.changes.clear();

        // If no any recipients to subtract fee then the sender need to pay by themself.
        if (!recipientsToSubtractFee) {
            required += fee;
        } else {
            currentVout -= fee;
        }
        // fill outputs
        bool remainderSubtracted = false;

        for (size_t i = 0; i < recipients.size(); i++) {
            auto& recipient = recipients[i];
            CTxOut vout(recipient.nAmount, recipient.scriptPubKey);

            if (recipient.fSubtractFeeFromAmount) {
                // Subtract fee equally from each selected recipient.
                vout.nValue -= fee / recipientsToSubtractFee;

                if (!remainderSubtracted) {
                    // First receiver pays the remainder not divisible by output count.
                    vout.nValue -= fee % recipientsToSubtractFee;
                    remainderSubtracted = true;
                }
            }

            if (vout.IsDust(minRelayTxFee)) {
                std::string err;

                if (recipient.fSubtractFeeFromAmount && fee > 0) {
                    if (vout.nValue < 0) {
                        err = boost::str(boost::format(_("Amount for recipient %1% is too small to pay the fee")) % i);
                    } else {
                        err = boost::str(boost::format(_("Amount for recipient %1% is too small to send after the fee has been deducted")) % i);
                    }
                } else {
                    err = boost::str(boost::format(_("Amount for recipient %1% is too small")) % i);
                }

                throw std::runtime_error(err);
            }

            tx.vout.push_back(vout);
        }

        // get coins
        spendCoins.clear();
        sigmaSpendCoins.clear();

        auto& consensusParams = Params().GetConsensus();
        CAmount changeToMint = 0;

        std::vector<sigma::CoinDenomination> denomChanges;
        try {
            CAmount availableBalance(0);
            for (auto coin : sigmaCoins) {
                availableBalance += coin.get_denomination_value();
            }
            if(availableBalance > 0) {
                CAmount inputFromSigma;
                if (required > availableBalance)
                    inputFromSigma = availableBalance;
                else
                    inputFromSigma = required;

                std::list<CSigmaEntry> sigmaCoinsCp = sigmaCoins;
                wallet.GetCoinsToSpend(inputFromSigma, sigmaSpendCoins, denomChanges, sigmaCoinsCp, //try to spend sigma first
                                       consensusParams.nMaxLelantusInputPerTransaction,
                                       consensusParams.nMaxValueLelantusSpendPerTransaction, coinControl);

                required -= inputFromSigma;

                isSigmaToLelantusJoinSplit = true;
            }
        } catch (std::runtime_error const &) {
        }

        if(required > 0) {
            if (!wallet.GetCoinsToJoinSplit(required, spendCoins, changeToMint, coins,
                                            consensusParams.nMaxLelantusInputPerTransaction,
                                            consensusParams.nMaxValueLelantusSpendPerTransaction, coinControl)) {
                throw InsufficientFunds();
            }
        }

        if ((sigmaSpendCoins.size() + spendCoins.size()) > consensusParams.nMaxLelantusInputPerTransaction)
            throw std::invalid_argument(
                    _("Number of inputs is bigger then limit."));

        for(const auto& demon : denomChanges) {
            int64_t intDenom;
            sigma::DenominationToInteger(demon, intDenom);
            changeToMint += intDenom;
        }

        CAmount input(0);
        for (const auto &spend : sigmaSpendCoins) {
            input += spend.get_denomination_value();
        }
        for (const auto &spend : spendCoins) {
            input += spend.amount;
        }

        changeToMint += (input - currentVout - fee - changeToMint - mint);

        if(changeToMint > consensusParams.nMaxValueLelantusMint) {
            throw std::invalid_argument(
                    _("Value of change exceeds the limit"));
        }

        // get outputs
        mintCoins.clear();
        std::vector<CTxOut> outputMints;
        std::vector<lelantus::PrivateCoin> Cout;
        GenerateMints(newMints, changeToMint, Cout, outputMints);

        // shuffle outputs to provide some privacy
        std::vector<std::reference_wrapper<CTxOut>> outputs;
        outputs.reserve(outputMints.size());

        for (auto& output : outputMints) {
            outputs.push_back(std::ref(output));
        }

        std::shuffle(outputs.begin(), outputs.end(), std::random_device());

        // replace outputs with shuffled one
        size_t coinIdx = 0;
        for (size_t i = 0; i < outputs.size(); i++) {
            auto& output = outputs[i];

            result.changes.insert(static_cast<uint32_t>(tx.vout.size() + i));

            CScript script;
            if ((script = output.get().scriptPubKey).IsLelantusJMint()) {
                GroupElement g;
                std::vector<unsigned char> enc;
                lelantus::ParseLelantusJMintScript(script, g, enc);

                for (size_t i = coinIdx; i != Cout.size(); i++) {
                    if (Cout[i].getPublicCoin() == g) {
                        std::swap(Cout[i], Cout[coinIdx++]);
                        break;
                    }
                }
            }
        }

        tx.vout.insert(tx.vout.end(), outputs.begin(), outputs.end());

        // fill inputs
        uint32_t sequence = CTxIn::SEQUENCE_FINAL;
        tx.vin.emplace_back(COutPoint(), CScript(), sequence);

        if(outModifier) {
            for(CTxOut & out : tx.vout) {
                outModifier(out, *this);
            }
        }

        // clear vExtraPayload to calculate metadata hash correctly
        tx.vExtraPayload.clear();

        // set correct type of transaction (this affects metadata hash)
        if (chainActive.Height() >= Params().GetConsensus().nLelantusV3PayloadStartBlock) {
            tx.nVersion = 3;
            tx.nType = TRANSACTION_LELANTUS;
        }

        // now every fields is populated then we can sign transaction
        uint256 sig = tx.GetHash();

        CreateJoinSplit(sig, Cout, currentVout, fee, tx);

        // check fee
        result.SetTx(MakeTransactionRef(tx));

        if (GetTransactionWeight(tx) >= MAX_STANDARD_TX_WEIGHT) {
            throw std::runtime_error(_("Transaction too large"));
        }

        // check fee
        unsigned size = GetVirtualTransactionSize(tx);
        CAmount feeNeeded = CWallet::GetMinimumFee(size, nTxConfirmTarget, mempool);

        // If we made it here and we aren't even able to meet the relay fee on the next pass, give up
        // because we must be at the maximum allowed fee.
        if (feeNeeded < minRelayTxFee.GetFee(size)) {
            throw std::invalid_argument(_("Transaction too large for fee policy"));
        }

        if (fee >= feeNeeded) {
            break;
        }

        fee = feeNeeded;
    }

    if (GetBoolArg("-walletrejectlongchains", DEFAULT_WALLET_REJECT_LONG_CHAINS)) {
        // Lastly, ensure this tx will pass the mempool's chain limits
        LockPoints lp;
        CTxMemPoolEntry entry(MakeTransactionRef(tx), 0, 0, 0, 0, false, 0, lp);
        CTxMemPool::setEntries setAncestors;
        size_t nLimitAncestors = GetArg("-limitancestorcount", DEFAULT_ANCESTOR_LIMIT);
        size_t nLimitAncestorSize = GetArg("-limitancestorsize", DEFAULT_ANCESTOR_SIZE_LIMIT) * 1000;
        size_t nLimitDescendants = GetArg("-limitdescendantcount", DEFAULT_DESCENDANT_LIMIT);
        size_t nLimitDescendantSize = GetArg("-limitdescendantsize", DEFAULT_DESCENDANT_SIZE_LIMIT) * 1000;
        std::string errString;
        if (!mempool.CalculateMemPoolAncestors(entry, setAncestors, nLimitAncestors, nLimitAncestorSize,
                                               nLimitDescendants, nLimitDescendantSize, errString)) {
            throw std::runtime_error(_("Transaction has too long of a mempool chain"));
        }
    }

    return result;

}

void LelantusJoinSplitBuilder::GenerateMints(const std::vector<CAmount>& newMints, const CAmount& changeToMint, std::vector<lelantus::PrivateCoin>& Cout, std::vector<CTxOut>& outputs) {
    mintCoins.clear();
    Cout.clear();
    Cout.reserve(newMints.size() + 1);
    CHDMint hdMint;
    auto params = lelantus::Params::get_default();
    std::vector<CAmount> newMintsAndChange(newMints);
    newMintsAndChange.push_back(changeToMint);
    for (CAmount mintVal : newMintsAndChange) {
        while (true) {
            hdMint.SetNull();
            lelantus::PrivateCoin newCoin(params, mintVal);
            newCoin.setVersion(LELANTUS_TX_VERSION_4);
            CWalletDB walletdb(pwalletMain->strWalletFile);

            uint160 seedID;
            mintWallet.GenerateLelantusMint(walletdb, newCoin, hdMint, seedID, boost::none, true);

            auto &pubCoin = newCoin.getPublicCoin();

            if (!pubCoin.validate()) {
                throw std::runtime_error("Unable to mint a lelantus coin.");
            }

            // Create script for coin
            CScript scriptSerializedCoin;
            scriptSerializedCoin << OP_LELANTUSJMINT;
            std::vector<unsigned char> vch = pubCoin.getValue().getvch();
            scriptSerializedCoin.insert(scriptSerializedCoin.end(), vch.begin(), vch.end());

            std::vector<unsigned char> encryptedValue = pwalletMain->EncryptMintAmount(mintVal, pubCoin.getValue());
            scriptSerializedCoin.insert(scriptSerializedCoin.end(), encryptedValue.begin(), encryptedValue.end());

            auto pubcoin = hdMint.GetPubcoinValue() +
                           lelantus::Params::get_default()->get_h1() * Scalar(hdMint.GetAmount()).negate();
            uint256 hashPub = primitives::GetPubCoinValueHash(pubcoin);
            CDataStream ss(SER_GETHASH, 0);
            ss << hashPub;
            ss << seedID;
            uint256 hashForRecover = Hash(ss.begin(), ss.end());
            // Check if there is a mint with same private data in chain, most likely Hd mint state corruption,
            // If yes, try with new counter
            GroupElement dummyValue;
            if (lelantus::CLelantusState::GetState()->HasCoinTag(dummyValue, hashForRecover))
                continue;

            CDataStream serializedHash(SER_NETWORK, 0);
            serializedHash << hashForRecover;
            scriptSerializedCoin.insert(scriptSerializedCoin.end(), serializedHash.begin(), serializedHash.end());

            Cout.emplace_back(newCoin);
            outputs.push_back(CTxOut(0, scriptSerializedCoin));
            mintCoins.push_back(hdMint);
            break;
        }
    }
}

void LelantusJoinSplitBuilder::CreateJoinSplit(
        const uint256& txHash,
        const std::vector<lelantus::PrivateCoin>& Cout,
        const uint64_t& Vout,
        const uint64_t& fee,
        CMutableTransaction& tx) {

    lelantus::CLelantusState* state = lelantus::CLelantusState::GetState();
    auto params = lelantus::Params::get_default();

    std::vector<std::pair<lelantus::PrivateCoin, uint32_t>> coins;
    coins.reserve(spendCoins.size());
    std::map<uint32_t, std::vector<lelantus::PublicCoin>> anonymity_sets;
    std::map<uint32_t, uint256> groupBlockHashes;
    int version = 0;

    // after nLelantusFixesStartBlock set new transaction version,
    if(!isSigmaToLelantusJoinSplit) {
        if (chainActive.Height() >= Params().GetConsensus().nLelantusFixesStartBlock)
            version = LELANTUS_TX_VERSION_4_5;
        else
            version = LELANTUS_TX_VERSION_4;
    } else {
        if (chainActive.Height() >= Params().GetConsensus().nLelantusFixesStartBlock)
            version = SIGMA_TO_LELANTUS_JOINSPLIT_FIXED;
        else
            version = SIGMA_TO_LELANTUS_JOINSPLIT;
    }

    std::vector<std::vector<unsigned char>> anonymity_set_hashes;
    for (const auto &spend : spendCoins) {
        // construct public part of the mint
        lelantus::PublicCoin pub(spend.value);
        // construct private part of the mint
        lelantus::PrivateCoin priv(params, spend.amount);
        priv.setVersion(version);
        priv.setSerialNumber(spend.serialNumber);
        priv.setRandomness(spend.randomness);
        priv.setEcdsaSeckey(spend.ecdsaSecretKey);
        priv.setPublicCoin(pub);

        // get coin group
        int groupId;

        std::tie(std::ignore, groupId) = state->GetMintedCoinHeightAndId(pub);

        if (groupId < 0) {
            throw std::runtime_error(_("One of the lelantus coins has not been found in the chain!"));
        }

        coins.emplace_back(std::make_pair(priv, groupId));
        std::vector<unsigned char> setHash;
        if (anonymity_sets.count(groupId) == 0) {
            std::vector<lelantus::PublicCoin> set;
            uint256 blockHash;
            if (state->GetCoinSetForSpend(
                    &chainActive,
                    chainActive.Height() - (ZC_MINT_CONFIRMATIONS - 1), // required 2 confirmation for mint to spend
                    groupId,
                    blockHash,
                    set,
                    setHash) < 2)
                throw std::runtime_error(
                        _("Has to have at least two mint coins with at least 2 confirmation in order to spend a coin"));
            groupBlockHashes[groupId] = blockHash;
            anonymity_sets[groupId] = set;
            if (!setHash.empty())
                anonymity_set_hashes.push_back(setHash);
        }
    }


    sigma::CSigmaState* sigmaState = sigma::CSigmaState::GetState();

    for (const auto &spend : sigmaSpendCoins) {
        int64_t denom = spend.get_denomination_value();
        // construct public part of the mint
        sigma::PublicCoin pub(spend.value, spend.get_denomination());
        // construct private part of the mint
        lelantus::PrivateCoin priv(params, denom);
        priv.setVersion(version);
        priv.setSerialNumber(spend.serialNumber);
        priv.setRandomness(spend.randomness);
        priv.setEcdsaSeckey(spend.ecdsaSecretKey);
        lelantus::PublicCoin lPub(spend.value + params->get_h1() * denom);
        priv.setPublicCoin(lPub);

        // get coin group
        int groupId;

        std::tie(std::ignore, groupId) = sigmaState->GetMintedCoinHeightAndId(pub);

        if (groupId < 0) {
            throw std::runtime_error(_("One of the sigma coins has not been found in the chain!"));
        }

        //this way we are remembering denomination and group id in one field as we have no demomination in Lelantus
        // with dividing by 1000 we just making maximum denomiation fit into uint32
        coins.emplace_back(std::make_pair(priv, denom / 1000 + groupId));


        if (anonymity_sets.count(denom / 1000 + groupId) == 0) {
            std::vector<sigma::PublicCoin> group;
            uint256 blockHash;
            if (sigmaState->GetCoinSetForSpend(
                    &chainActive,
                    chainActive.Height() - (ZC_MINT_CONFIRMATIONS - 1), // required 2 confirmation for mint to spend
                    spend.get_denomination(),
                    groupId,
                    blockHash,
                    group) < 2)
                throw std::runtime_error(
                        _("Has to have at least two mint coins with at least 2 confirmation in order to spend a coin"));
            std::vector<lelantus::PublicCoin> set;
            set.reserve(group.size());
            for(auto& coin : group) {
                set.push_back(coin.getValue() + params->get_h1() * denom);
            }
            groupBlockHashes[denom / 1000 + groupId] = blockHash;
            anonymity_sets[denom / 1000 + groupId] = set;
        }

    }

    std::sort(coins.begin(), coins.end(), CoinCompare());

    lelantus::JoinSplit joinSplit(params, coins, anonymity_sets, anonymity_set_hashes, Vout, Cout, fee, groupBlockHashes, txHash, version);

    std::vector<lelantus::PublicCoin>  pCout;
    pCout.reserve(Cout.size());
    for(const auto& coin : Cout)
        pCout.emplace_back(coin.getPublicCoin());

    if (!joinSplit.Verify(anonymity_sets, anonymity_set_hashes, pCout, Vout, txHash)) {
        throw std::runtime_error(_("The joinsplit transaction failed to verify"));
    }

    // construct spend script
    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
    serialized << joinSplit;

    CScript script;

    if (chainActive.Height() >= Params().GetConsensus().nLelantusV3PayloadStartBlock) {
        script << OP_LELANTUSJOINSPLITPAYLOAD;
        tx.nVersion = 3;
        tx.nType = TRANSACTION_LELANTUS;
        tx.vExtraPayload.assign(serialized.begin(), serialized.end());
    }
    else {
        script << OP_LELANTUSJOINSPLIT;
        script.insert(script.end(), serialized.begin(), serialized.end());
    }

    tx.vin[0].scriptSig = script;
}
