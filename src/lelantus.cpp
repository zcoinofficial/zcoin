#include "validation.h"
#include "lelantus.h"
#include "timedata.h"
#include "chainparams.h"
#include "util.h"
#include "base58.h"
#include "definition.h"
#include "txmempool.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#include "crypto/sha256.h"
#include "liblelantus/coin.h"
#include "liblelantus/schnorr_prover.h"
#include "liblelantus/schnorr_verifier.h"
#include "primitives/mint_spend.h"
#include "liblelantus/challenge_generator_impl.h"
#include "policy/policy.h"
#include "coins.h"
#include "batchproof_container.h"

#include <atomic>
#include <sstream>
#include <chrono>

#include <boost/foreach.hpp>
#include <boost/scope_exit.hpp>

#include <ios>

namespace lelantus {

static CLelantusState lelantusState;

static bool CheckLelantusSpendSerial(
        CValidationState &state,
        CLelantusTxInfo *lelantusTxInfo,
        const Scalar &serial,
        int nHeight,
        bool fConnectTip) {
    // check for Lelantus transaction in this block as well
    if (lelantusTxInfo &&
            !lelantusTxInfo->fInfoIsComplete &&
            lelantusTxInfo->spentSerials.find(serial) != lelantusTxInfo->spentSerials.end())
        return state.DoS(0, error("CTransaction::CheckTransaction() : two or more joinsplits with same serial in the same block"));

    // check for used serials in lelantusState
    if (lelantusState.IsUsedCoinSerial(serial)) {
        // Proceed with checks ONLY if we're accepting tx into the memory pool or connecting block to the existing blockchain
        if (nHeight == INT_MAX || fConnectTip) {
            return state.DoS(0, error("CTransaction::CheckTransaction() : The lelantus JoinSplit serial has been used"));
        }
    }
    return true;
}


std::vector<unsigned char> GetAnonymitySetHash(CBlockIndex *index, int group_id, bool generation = false) {
    std::vector<unsigned char> out_hash;

    CLelantusState::LelantusCoinGroupInfo coinGroup;
    if (!lelantusState.GetCoinGroupInfo(group_id, coinGroup))
        return out_hash;

    if ((coinGroup.firstBlock == coinGroup.lastBlock && generation) || (coinGroup.nCoins == 0))
        return out_hash;

    while (index != coinGroup.firstBlock) {
        if (index->anonymitySetHash.count(group_id) > 0) {
            out_hash = index->anonymitySetHash[group_id];
            break;
        }
        index = index->pprev;
    }
    return out_hash;
}

bool IsLelantusAllowed()
{
    LOCK(cs_main);
    return IsLelantusAllowed(chainActive.Height());
}

bool IsLelantusAllowed(int height)
{
	return height >= ::Params().GetConsensus().nLelantusStartBlock;
}

bool IsAvailableToMint(const CAmount& amount)
{
    return amount <= ::Params().GetConsensus().nMaxValueLelantusMint;
}

void GenerateMintSchnorrProof(const lelantus::PrivateCoin& coin, CDataStream&  serializedSchnorrProof)
{
    auto params = lelantus::Params::get_default();

    LOCK(cs_main);
    SchnorrProof schnorrProof;

    // after nLelantusFixesStartBlock block start to pass whole data to transcript
    bool afterFixes = chainActive.Height() >= ::Params().GetConsensus().nLelantusFixesStartBlock;
    SchnorrProver schnorrProver(params->get_g(), params->get_h0(), afterFixes);
    Scalar v = coin.getVScalar();
    secp_primitives::GroupElement commit = coin.getPublicCoin().getValue();
    secp_primitives::GroupElement comm = commit + (params->get_h1() * v.negate());

    std::unique_ptr<ChallengeGenerator> challengeGenerator;
    if (afterFixes) {
        // start to use CHash256 which is more secure
        challengeGenerator = std::make_unique<ChallengeGeneratorImpl<CHash256>>(1);
    }  else {
        challengeGenerator = std::make_unique<ChallengeGeneratorImpl<CSHA256>>(0);
    }

    // commit (G^s*H1^v*H2^r), comm (G^s*H2^r), and H1^v are used in challenge generation if nLelantusFixesStartBlock is passed
    schnorrProver.proof(coin.getSerialNumber(), coin.getRandomness(), comm, commit, (params->get_h1() * v), challengeGenerator, schnorrProof);

    serializedSchnorrProof << schnorrProof;
}

bool VerifyMintSchnorrProof(const uint64_t& v, const secp_primitives::GroupElement& commit, const SchnorrProof& schnorrProof)
{
    auto params = lelantus::Params::get_default();

    LOCK(cs_main);
    // after nLelantusFixesStartBlock block start to pass whole data to transcript
    bool afterFixes = chainActive.Height() >= ::Params().GetConsensus().nLelantusFixesStartBlock;
    secp_primitives::GroupElement comm = commit + (params->get_h1() * Scalar(v).negate());
    SchnorrVerifier verifier(params->get_g(), params->get_h0(), afterFixes);
    std::unique_ptr<ChallengeGenerator> challengeGenerator;
    if (afterFixes) {
        // start to use CHash256 which is more secure
        challengeGenerator = std::make_unique<ChallengeGeneratorImpl<CHash256>>(1);
    }  else {
        challengeGenerator = std::make_unique<ChallengeGeneratorImpl<CSHA256>>(0);
    }

    // commit (G^s*H1^v*H2^r), comm (G^s*H2^r), and H1^v are used in challenge generation if nLelantusFixesStartBlock is passed
    return verifier.verify(comm, commit, (params->get_h1() * Scalar(v)), schnorrProof, challengeGenerator);
}

void ParseLelantusMintScript(const CScript& script, secp_primitives::GroupElement& pubcoin,  SchnorrProof& schnorrProof, uint256& mintTag)
{
    if (script.size() < 1) {
        throw std::invalid_argument("Script is not a valid Lelantus mint");
    }

    std::vector<unsigned char> serialized(script.begin() + 1, script.end());
    if (serialized.size() < (pubcoin.memoryRequired() + schnorrProof.memoryRequired())) {
        throw std::invalid_argument("Script is not a valid Lelantus mint");
    }

    bool skipTag = serialized.size() == (pubcoin.memoryRequired() + schnorrProof.memoryRequired());

    pubcoin.deserialize(serialized.data());

    CDataStream stream(
            std::vector<unsigned char>(serialized.begin() + pubcoin.memoryRequired(), serialized.end()),
            SER_NETWORK,
            PROTOCOL_VERSION
    );

    stream >> schnorrProof;
    if(!skipTag)
        stream >> mintTag;
}

void ParseLelantusJMintScript(const CScript& script, secp_primitives::GroupElement& pubcoin, std::vector<unsigned char>& encryptedValue)
{
    uint256 mintTag;
    ParseLelantusJMintScript(script, pubcoin, encryptedValue, mintTag);
}

void ParseLelantusJMintScript(const CScript& script, secp_primitives::GroupElement& pubcoin, std::vector<unsigned char>& encryptedValue, uint256& mintTag)
{
    if (script.size() < 1) {
        throw std::invalid_argument("Script is not a valid Lelantus jMint");
    }

    std::vector<unsigned char> serialized(script.begin() + 1, script.end());
    // 16 is the size of encrypted mint value, 32 is size of mintTag
    if (serialized.size() < (pubcoin.memoryRequired() + 16)) {
        throw std::invalid_argument("Script is not a valid Lelantus jMint");
    }

    bool skipTag = serialized.size() == (pubcoin.memoryRequired() + 16);

    pubcoin.deserialize(serialized.data());
    encryptedValue.insert(encryptedValue.begin(), serialized.begin() + pubcoin.memoryRequired(), serialized.end());
    CDataStream stream(
            std::vector<unsigned char>(serialized.begin() + pubcoin.memoryRequired() + 16, serialized.end()),
            SER_NETWORK,
            PROTOCOL_VERSION
    );
    if(!skipTag)
        stream >> mintTag;
}


void ParseLelantusMintScript(const CScript& script, secp_primitives::GroupElement& pubcoin)
{
    uint256 mintTag;
    if(script.IsLelantusMint()) {
        SchnorrProof schnorrProof;
        ParseLelantusMintScript(script, pubcoin, schnorrProof, mintTag);
    } else if (script.IsLelantusJMint()) {
        std::vector<unsigned char> encryptedValue;
        ParseLelantusJMintScript(script, pubcoin, encryptedValue, mintTag);
    }
}

std::unique_ptr<JoinSplit> ParseLelantusJoinSplit(const CTransaction &tx)
{
    if (tx.vin.size() != 1 || tx.vin[0].scriptSig.size() < 1) {
        throw CBadTxIn();
    }

    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);

    if (tx.vin[0].scriptSig[0] == OP_LELANTUSJOINSPLIT) {
        serialized.write((const char *)tx.vin[0].scriptSig.data()+1, tx.vin[0].scriptSig.size()-1);
    }
    else if (tx.vin[0].scriptSig[0] == OP_LELANTUSJOINSPLITPAYLOAD && tx.nVersion >= 3 && tx.nType == TRANSACTION_LELANTUS) {
        serialized.write((const char *)tx.vExtraPayload.data(), tx.vExtraPayload.size());
    }
    else
        throw CBadTxIn();

    return std::make_unique<lelantus::JoinSplit>(lelantus::Params::get_default(), serialized);
}

bool CheckLelantusBlock(CValidationState &state, const CBlock& block) {
    auto& consensus = ::Params().GetConsensus();

    size_t blockSpendsAmount = 0;
    CAmount blockSpendsValue(0);

    for (const auto& tx : block.vtx) {
        auto txSpendsValue =  GetSpendTransparentAmount(*tx);
        size_t txSpendNumber = GetSpendInputs(*tx);

        if (txSpendNumber > consensus.nMaxLelantusInputPerTransaction) {
            return state.DoS(100, false, REJECT_INVALID,
                "bad-txns-lelantus-spend-invalid");
        }

        if (txSpendsValue > consensus.nMaxValueLelantusSpendPerTransaction) {
            return state.DoS(100, false, REJECT_INVALID,
                             "bad-txns-lelantus-spend-invalid");
        }

        blockSpendsAmount += txSpendNumber;
        blockSpendsValue += txSpendsValue;
    }

    if (blockSpendsAmount > consensus.nMaxLelantusInputPerBlock) {
        return state.DoS(100, false, REJECT_INVALID,
            "bad-txns-lelantus-spend-invalid");
    }

    if (blockSpendsValue > consensus.nMaxValueLelantusSpendPerBlock) {
        return state.DoS(100, false, REJECT_INVALID,
                         "bad-txns-lelantus-spend-invalid");
    }

    return true;
}

bool CheckLelantusJMintTransaction(
        const CTxOut &txout,
        CValidationState &state,
        uint256 hashTx,
        bool fStatefulSigmaCheck,
        std::vector<PublicCoin>& Cout,
        CLelantusTxInfo* lelantusTxInfo) {

    LogPrintf("CheckLelantusJMintTransaction txHash = %s\n", txout.GetHash().ToString());

    secp_primitives::GroupElement pubCoinValue;
    uint256 mintTag;
    std::vector<unsigned char> encryptedValue;
    try {
        ParseLelantusJMintScript(txout.scriptPubKey, pubCoinValue, encryptedValue, mintTag);
    } catch (std::invalid_argument&) {
        return state.DoS(100,
            false,
            PUBCOIN_NOT_VALIDATE,
            "CTransaction::CheckTransaction() : Mint parsing failure.");
    }

    lelantus::PublicCoin pubCoin(pubCoinValue);

    //checking whether commitment is valid
    if(!pubCoin.validate())
        return state.DoS(100,
                         false,
                         PUBCOIN_NOT_VALIDATE,
                         "CheckLelantusMintTransaction : PubCoin validation failed");

    bool hasCoin = lelantusState.HasCoin(pubCoin);

    if (!hasCoin && lelantusTxInfo && !lelantusTxInfo->fInfoIsComplete) {
        BOOST_FOREACH(const auto& mint, lelantusTxInfo->mints) {
            if (mint.first == pubCoin) {
                hasCoin = true;
                break;
            }
        }
    }

    if (hasCoin && fStatefulSigmaCheck) {
       LogPrintf("CheckLelantusMintTransaction: double mint, tx=%s\n",
                txout.GetHash().ToString());
        return state.DoS(100,
                false,
                PUBCOIN_NOT_VALIDATE,
                "CheckLelantusMintTransaction: double mint");
    }

    uint64_t amount = 0;
#ifdef ENABLE_WALLET
    if (!GetBoolArg("-disablewallet", false)) {
        if (!pwalletMain->DecryptMintAmount(encryptedValue, pubCoinValue, amount))
            amount = 0;
    }
#endif
    if (lelantusTxInfo != NULL && !lelantusTxInfo->fInfoIsComplete) {

        // Update public coin list in the info
        lelantusTxInfo->mints.push_back(std::make_pair(pubCoin, std::make_pair(amount, mintTag)));
        lelantusTxInfo->zcTransactions.insert(hashTx);
    }

    Cout.push_back(pubCoin);

    return true;
}

bool CheckLelantusJoinSplitTransaction(
        const CTransaction &tx,
        CValidationState &state,
        uint256 hashTx,
        bool isVerifyDB,
        int nHeight,
        int realHeight,
        bool isCheckWallet,
        bool fStatefulSigmaCheck,
        sigma::CSigmaTxInfo* sigmaTxInfo,
        CLelantusTxInfo* lelantusTxInfo) {
    std::unordered_set<Scalar, sigma::CScalarHash> txSerials;

    Consensus::Params const & params = ::Params().GetConsensus();

    if(tx.vin.size() != 1 || !tx.vin[0].scriptSig.IsLelantusJoinSplit()) {
        // mixing lelantus spend input with non-lelantus inputs is prohibited
        return state.DoS(100, false,
                         REJECT_MALFORMED,
                         "CheckLelantusJoinSplitTransaction: can't mix lelantus spend input with other tx types or have more than one spend");
    }

    if (!isVerifyDB) {
        int height = nHeight == INT_MAX ? chainActive.Height()+1 : nHeight;
        if (height >= params.nLelantusV3PayloadStartBlock) {
            // data should be moved to v3 payload
            if (tx.nVersion < 3 || tx.nType != TRANSACTION_LELANTUS)
                return state.DoS(100, false, NSEQUENCE_INCORRECT,
                        "CheckLelantusJoinSplitTransaction: lelantus data should reside in transaction payload");
        }
        else {
            if (tx.nVersion >= 3 && tx.nType != TRANSACTION_NORMAL)
                return state.DoS(100, false, NSEQUENCE_INCORRECT,
                        "CheckLelantusJoinSplitTransaction: network hasn't yet switched over to lelantus payload data");
        }
    }

    std::unique_ptr<lelantus::JoinSplit> joinsplit;

    try {
        joinsplit = ParseLelantusJoinSplit(tx);
    }
    catch (CBadTxIn&) {
        return state.DoS(100,
            false,
            REJECT_MALFORMED,
            "CheckLelantusJoinSplitTransaction: invalid joinsplit transaction");
    }

    int jSplitVersion = joinsplit->getVersion();

    if (jSplitVersion < LELANTUS_TX_VERSION_4 ||
        (!isVerifyDB && nHeight >= params.nLelantusFixesStartBlock && jSplitVersion != LELANTUS_TX_VERSION_4_5 && jSplitVersion != SIGMA_TO_LELANTUS_JOINSPLIT_FIXED)) {
        return state.DoS(100,
                         false,
                         NSEQUENCE_INCORRECT,
                         "CTransaction::CheckLelantusJoinSplitTransaction() : Error: incorrect joinsplit transaction verion");
    }

    uint256 txHashForMetadata;

    // Obtain the hash of the transaction sans the zerocoin part
    CMutableTransaction txTemp = tx;
    txTemp.vin[0].scriptSig.clear();
    txTemp.vExtraPayload.clear();

    txHashForMetadata = txTemp.GetHash();

    LogPrintf("CheckLelantusJoinSplitTransaction: tx version=%d, tx metadata hash=%s\n",
              jSplitVersion, txHashForMetadata.ToString());

    if (!fStatefulSigmaCheck) {
        return true;
    }

    bool passVerify = false;
    std::map<uint32_t, std::vector<PublicCoin>> anonymity_sets;
    std::vector<PublicCoin> Cout;
    uint64_t Vout = 0;

    for (const CTxOut &txout : tx.vout) {
        if (!txout.scriptPubKey.empty() && txout.scriptPubKey.IsLelantusJMint()) {
            if (!CheckLelantusJMintTransaction(txout, state, hashTx, fStatefulSigmaCheck, Cout, lelantusTxInfo))
                return false;
        } else if(txout.scriptPubKey.IsLelantusMint()) {
            return false; //putting regular mints at JoinSplit transactions is not allowed
        } else {
            Vout += txout.nValue;
        }
    }

    std::vector<std::vector<unsigned char>> anonymity_set_hashes;

    for (auto& idAndHash : joinsplit->getIdAndBlockHashes()) {
        auto& anonymity_set = anonymity_sets[idAndHash.first];
        int coinGroupId = idAndHash.first % (CENT / 1000);
        int64_t intDenom = (idAndHash.first - coinGroupId);
        intDenom *= 1000;

        sigma::CoinDenomination denomination;
        if (joinsplit->isSigmaToLelantus() && sigma::IntegerToDenomination(intDenom, denomination)) {

            sigma::CSigmaState::SigmaCoinGroupInfo coinGroup;
            sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
            if (!sigmaState->GetCoinGroupInfo(denomination, coinGroupId, coinGroup))
                return state.DoS(100, false, NO_MINT_ZEROCOIN,
                                 "CheckSigmaSpendTransaction: Error: no coins were minted with such parameters");

            CBlockIndex *index = coinGroup.lastBlock;

            // find index for block with hash of accumulatorBlockHash or set index to the coinGroup.firstBlock if not found
            while (index != coinGroup.firstBlock && index->GetBlockHash() != idAndHash.second)
                index = index->pprev;

            std::pair<sigma::CoinDenomination, int> denominationAndId = std::make_pair(denomination, coinGroupId);

            auto lelantusParams = lelantus::Params::get_default();
            while (true) {
                if (index->sigmaMintedPubCoins.count(denominationAndId) > 0) {
                    BOOST_FOREACH(
                    const sigma::PublicCoin &pubCoinValue,
                    index->sigmaMintedPubCoins[denominationAndId]) {
                        if (::Params().GetConsensus().sigmaBlacklist.count(pubCoinValue.getValue()) > 0) {
                            continue;
                        }
                        lelantus::PublicCoin publicCoin(pubCoinValue.getValue() + lelantusParams->get_h1() * intDenom);
                        anonymity_set.push_back(publicCoin);
                    }
                }
                if (index == coinGroup.firstBlock)
                    break;
                index = index->pprev;
            }
        } else {
            CLelantusState::LelantusCoinGroupInfo coinGroup;
            if (!lelantusState.GetCoinGroupInfo(idAndHash.first, coinGroup))
                return state.DoS(100, false, NO_MINT_ZEROCOIN,
                                 "CheckLelantusJoinSplitTransaction: Error: no coins were minted with such parameters");

            CBlockIndex *index = coinGroup.lastBlock;


            // find index for block with hash of accumulatorBlockHash or set index to the coinGroup.firstBlock if not found
            while (index != coinGroup.firstBlock && index->GetBlockHash() != idAndHash.second)
                index = index->pprev;

            // take the hash from last block of anonymity set, it is used at challenge generation if nLelantusFixesStartBlock is passed
            if (nHeight >= params.nLelantusFixesStartBlock) {
                std::vector<unsigned char> set_hash = GetAnonymitySetHash(index, idAndHash.first);
                if (!set_hash.empty())
                    anonymity_set_hashes.push_back(set_hash);
            }
            // Build a vector with all the public coins with given id before
            // the block on which the spend occured.
            // This list of public coins is required by function "Verify" of JoinSplit.

            while (true) {
                if(index->lelantusMintedPubCoins.count(idAndHash.first) > 0) {
                    BOOST_FOREACH(
                    const auto& pubCoinValue,
                    index->lelantusMintedPubCoins[idAndHash.first]) {
                        // skip mints from blacklist if nLelantusFixesStartBlock is passed
                        if (chainActive.Height() >= ::Params().GetConsensus().nLelantusFixesStartBlock) {
                            if (::Params().GetConsensus().lelantusBlacklist.count(pubCoinValue.first.getValue()) > 0) {
                                continue;
                            }
                        }
                        anonymity_set.push_back(pubCoinValue.first);
                    }
                }
                if (index == coinGroup.firstBlock)
                    break;
                index = index->pprev;
            }
        }
        anonymity_sets[idAndHash.first] = anonymity_set;
    }

    BatchProofContainer* batchProofContainer = BatchProofContainer::get_instance();
    bool useBatching = batchProofContainer->fCollectProofs && !isVerifyDB && !isCheckWallet && lelantusTxInfo && !lelantusTxInfo->fInfoIsComplete;

    Scalar challenge;
    // if we are collecting proofs, skip verification and collect proofs
    passVerify = joinsplit->Verify(anonymity_sets, anonymity_set_hashes, Cout, Vout, txHashForMetadata, challenge, useBatching);

    // add proofs into container
    if(useBatching) {
        std::map<uint32_t, size_t> idAndSizes;

        for(auto itr : anonymity_sets)
            idAndSizes[itr.first] = itr.second.size();

        batchProofContainer->add(joinsplit.get(), idAndSizes, challenge, nHeight >= params.nLelantusFixesStartBlock);
    }

    if (passVerify) {
        const std::vector<Scalar>& serials = joinsplit->getCoinSerialNumbers();
        const std::vector<uint32_t> &ids = joinsplit->getCoinGroupIds();

        if (serials.size() != ids.size()) {
            return state.DoS(100,
                             error("CheckLelantusJoinSplitTransaction: sized of serials and group ids don't match."));
        }

        // do not check for duplicates in case we've seen exact copy of this tx in this block before
        if (!(sigmaTxInfo && sigmaTxInfo->zcTransactions.count(hashTx) > 0) && !(lelantusTxInfo && lelantusTxInfo->zcTransactions.count(hashTx) > 0)) {
            for (size_t i = 0; i < serials.size(); ++i) {
                int coinGroupId = ids[i] % (CENT / 1000);
                int64_t intDenom = (ids[i] - coinGroupId);
                intDenom *= 1000;
                sigma::CoinDenomination denomination;

                if (realHeight < params.nLelantusV3PayloadStartBlock || (joinsplit->isSigmaToLelantus() && sigma::IntegerToDenomination(intDenom, denomination))) {
                    if (!sigma::CheckSigmaSpendSerial(
                            state, sigmaTxInfo, serials[i], nHeight, false)) {
                        LogPrintf("CheckSigmaSpendTransaction: serial check failed, serial=%s\n", serials[i]);
                        return false;
                    } else if (!CheckLelantusSpendSerial(
                            state, lelantusTxInfo, serials[i], nHeight, false)) {
                        LogPrintf("CheckLelantusJoinSplitTransaction: serial check failed, serial=%s\n", serials[i]);
                        return false;

                    }
                } else {
                    if (!CheckLelantusSpendSerial(
                            state, lelantusTxInfo, serials[i], nHeight, false)) {
                        LogPrintf("CheckLelantusJoinSplitTransaction: serial check failed, serial=%s\n", serials[i]);
                        return false;
                    }
                }
            }
        }

        // check duplicated serials in same transaction.
        for (const auto &serial : serials) {
            if (!txSerials.insert(serial).second) {
                return state.DoS(100,
                                 error("CheckLelantusJoinSplitTransaction: two or more spends with same serial in the same transaction"));
            }
        }

        if (!isVerifyDB && !isCheckWallet) {
            // add spend information to the index
            if (joinsplit->isSigmaToLelantus()) {
                if (sigmaTxInfo && !sigmaTxInfo->fInfoIsComplete) {
                    for (size_t i = 0; i < serials.size(); i++) {
                        int coinGroupId = ids[i] % (CENT / 1000);
                        int64_t intDenom = (ids[i] - coinGroupId);
                        intDenom *= 1000;
                        sigma::CoinDenomination denomination;
                        if(!sigma::IntegerToDenomination(intDenom, denomination) && lelantusTxInfo && !lelantusTxInfo->fInfoIsComplete)
                            lelantusTxInfo->spentSerials.insert(std::make_pair(serials[i], ids[i]));
                        else
                            sigmaTxInfo->spentSerials.insert(std::make_pair(
                                    serials[i], sigma::CSpendCoinInfo::make(denomination, coinGroupId)));
                    }
                }
            } else {
                if (lelantusTxInfo && !lelantusTxInfo->fInfoIsComplete) {
                    for (size_t i = 0; i < serials.size(); i++) {
                        lelantusTxInfo->spentSerials.insert(std::make_pair(serials[i], ids[i]));
                    }
                }
            }
        }
    }
    else {
        LogPrintf("CheckLelantusJoinSplitTransaction: verification failed at block %d\n", nHeight);
        return false;
    }

    if(!isVerifyDB && !isCheckWallet) {
        if (lelantusTxInfo && !lelantusTxInfo->fInfoIsComplete) {
            lelantusTxInfo->zcTransactions.insert(hashTx);
        }
    }

    return true;
}

bool CheckLelantusMintTransaction(
        const CTxOut &txout,
        CValidationState &state,
        uint256 hashTx,
        bool fStatefulSigmaCheck,
        CLelantusTxInfo* lelantusTxInfo) {
    secp_primitives::GroupElement pubCoinValue;
    uint256 mintTag;
    SchnorrProof schnorrProof;

    LogPrintf("CheckLelantusMintTransaction txHash = %s\n", txout.GetHash().ToString());
    LogPrintf("nValue = %d\n", txout.nValue);
    if(txout.nValue > ::Params().GetConsensus().nMaxValueLelantusMint)
        return state.DoS(100,
                         false,
                         REJECT_INVALID,
                         "CTransaction::CheckTransaction() : Mint is out of limit.");

    try {
        ParseLelantusMintScript(txout.scriptPubKey, pubCoinValue, schnorrProof, mintTag);
    } catch (std::invalid_argument&) {
        return state.DoS(100,
            false,
            PUBCOIN_NOT_VALIDATE,
            "CTransaction::CheckTransaction() : Mint parsing failure.");
    }

    lelantus::PublicCoin pubCoin(pubCoinValue);

    //checking whether commitment is valid
    if(!VerifyMintSchnorrProof(txout.nValue, pubCoinValue, schnorrProof) || !pubCoin.validate())
        return state.DoS(100,
                         false,
                         PUBCOIN_NOT_VALIDATE,
                         "CheckLelantusMintTransaction : PubCoin validation failed");


    bool hasCoin = lelantusState.HasCoin(pubCoin);

    if (!hasCoin && lelantusTxInfo && !lelantusTxInfo->fInfoIsComplete) {
        BOOST_FOREACH(const auto& mint, lelantusTxInfo->mints) {
            if (mint.first == pubCoin) {
                hasCoin = true;
                break;
            }
        }
    }

    if (hasCoin && fStatefulSigmaCheck) {
       LogPrintf("CheckLelantusMintTransaction: double mint, tx=%s\n",
                txout.GetHash().ToString());
        return state.DoS(100,
                false,
                PUBCOIN_NOT_VALIDATE,
                "CheckLelantusMintTransaction: double mint");
    }

    if (lelantusTxInfo != NULL && !lelantusTxInfo->fInfoIsComplete) {
        // Update public coin list in the info
        lelantusTxInfo->mints.push_back(std::make_pair(pubCoin, std::make_pair(txout.nValue, mintTag)));
        lelantusTxInfo->zcTransactions.insert(hashTx);
    }

    return true;
}

bool CheckLelantusTransaction(
        const CTransaction &tx,
        CValidationState &state,
        uint256 hashTx,
        bool isVerifyDB,
        int nHeight,
        bool isCheckWallet,
        bool fStatefulSigmaCheck,
        sigma::CSigmaTxInfo* sigmaTxInfo,
        CLelantusTxInfo* lelantusTxInfo)
{
    Consensus::Params const & consensus = ::Params().GetConsensus();


    if(tx.IsLelantusJoinSplit()) {
        CAmount nFees;
        try {
            nFees = lelantus::ParseLelantusJoinSplit(tx)->getFee();
        }
        catch (CBadTxIn&) {
            return state.DoS(0, false, REJECT_INVALID, "unable to parse joinsplit");
        }

    }

    int realHeight = nHeight;

    if (realHeight == INT_MAX) {
        LOCK(cs_main);
        realHeight = chainActive.Height();
    }

    bool const allowLelantus = (realHeight >= consensus.nLelantusStartBlock);

    if (!isVerifyDB && !isCheckWallet) {
        if (allowLelantus && lelantusState.IsSurgeConditionDetected()) {
            return state.DoS(100, false,
                REJECT_INVALID,
                "Lelantus surge protection is ON.");
        }
    }

    // Check Mint Lelantus Transaction
    if (allowLelantus && !isVerifyDB) {
        for (const CTxOut &txout : tx.vout) {
            if (!txout.scriptPubKey.empty() && txout.scriptPubKey.IsLelantusMint()) {
                if (!CheckLelantusMintTransaction(txout, state, hashTx, fStatefulSigmaCheck, lelantusTxInfo))
                    return false;
            }
        }
    }

    // Check Lelantus JoinSplit Transaction
    if(tx.IsLelantusJoinSplit()) {
        // First check number of inputs does not exceed transaction limit
        if (GetSpendInputs(tx) > consensus.nMaxLelantusInputPerTransaction) {
            return state.DoS(100, false,
                REJECT_INVALID,
                "bad-txns-spend-invalid");
        }

        if (GetSpendTransparentAmount(tx) > consensus.nMaxValueLelantusSpendPerTransaction) {
            return state.DoS(100, false,
                             REJECT_INVALID,
                             "bad-txns-spend-invalid");
        }

        if (!isVerifyDB) {
            if (!CheckLelantusJoinSplitTransaction(
                tx, state, hashTx, isVerifyDB, nHeight, realHeight,
                isCheckWallet, fStatefulSigmaCheck, sigmaTxInfo, lelantusTxInfo)) {
                    return false;
            }
        }
    }

    return true;
}

void RemoveLelantusJoinSplitReferencingBlock(CTxMemPool& pool, CBlockIndex* blockIndex) {
    LOCK2(cs_main, pool.cs);
    std::vector<CTransaction> txn_to_remove;
    for (CTxMemPool::txiter mi = pool.mapTx.begin(); mi != pool.mapTx.end(); ++mi) {
        const CTransaction& tx = mi->GetTx();
        if (tx.IsLelantusJoinSplit()) {
            // Run over all the inputs, check if their CoinGroup block hash is equal to
            // block removed. If any one is equal, remove txn from mempool.
            for (const CTxIn& txin : tx.vin) {
                if (txin.IsLelantusJoinSplit()) {
                    std::unique_ptr<lelantus::JoinSplit> joinsplit;

                    try {
                        joinsplit = ParseLelantusJoinSplit(tx);
                    }
                    catch (const std::ios_base::failure &) {
                        txn_to_remove.push_back(tx);
                        break;
                    }

                    const std::vector<std::pair<uint32_t, uint256>>& coinGroupIdAndBlockHash = joinsplit->getIdAndBlockHashes();
                    for(const auto& idAndHash : coinGroupIdAndBlockHash) {
                        if (idAndHash.second == blockIndex->GetBlockHash()) {
                        // Do not remove transaction immediately, that will invalidate iterator mi.
                        txn_to_remove.push_back(tx);
                        break;
                        }
                    }
                }
            }
        }
    }
    for (const CTransaction& tx: txn_to_remove) {
        // Remove txn from mempool.
        pool.removeRecursive(tx);
        LogPrintf("DisconnectTipLelantus: removed lelantus joinsplit which referenced a removed blockchain tip.");
    }
}

void DisconnectTipLelantus(CBlock& block, CBlockIndex *pindexDelete) {
    lelantusState.RemoveBlock(pindexDelete);

    // Also remove from mempool lelantus joinsplits that reference given block hash.
    RemoveLelantusJoinSplitReferencingBlock(mempool, pindexDelete);
    RemoveLelantusJoinSplitReferencingBlock(txpools.getStemTxPool(), pindexDelete);
}

std::vector<Scalar> GetLelantusJoinSplitSerialNumbers(const CTransaction &tx, const CTxIn &txin) {
    if (!tx.IsLelantusJoinSplit())
        return std::vector<Scalar>();

    try {
        return ParseLelantusJoinSplit(tx)->getCoinSerialNumbers();
    }
    catch (const std::ios_base::failure &) {
        return std::vector<Scalar>();
    }
}

std::vector<uint32_t> GetLelantusJoinSplitIds(const CTransaction &tx, const CTxIn &txin) {
    if (!tx.IsLelantusJoinSplit())
        return std::vector<uint32_t>();

    try {
        return ParseLelantusJoinSplit(tx)->getCoinGroupIds();
    }
    catch (const std::ios_base::failure &) {
        return std::vector<uint32_t>();
    }
}

size_t GetSpendInputs(const CTransaction &tx, const CTxIn& in) {
    return in.IsLelantusJoinSplit() ?
        GetLelantusJoinSplitSerialNumbers(tx, in).size() : 0;
}

size_t GetSpendInputs(const CTransaction &tx) {
    size_t sum = 0;
    for (const auto& vin : tx.vin) {
        sum += GetSpendInputs(tx, vin);
    }
    return sum;
}

CAmount GetSpendTransparentAmount(const CTransaction& tx) {
    CAmount result = 0;
    if(!tx.IsLelantusJoinSplit())
        return 0;

    for (const CTxOut &txout : tx.vout)
        result += txout.nValue;
    return result;
}

/**
 * Connect a new ZCblock to chainActive. pblock is either NULL or a pointer to a CBlock
 * corresponding to pindexNew, to bypass loading it again from disk.
 */
bool ConnectBlockLelantus(
        CValidationState &state,
        const CChainParams &chainparams,
        CBlockIndex *pindexNew,
        const CBlock *pblock,
        bool fJustCheck) {
    // Add lelantus transaction information to index
    if (pblock && pblock->lelantusTxInfo) {
        if (!fJustCheck) {
            pindexNew->lelantusMintedPubCoins.clear();
            pindexNew->lelantusSpentSerials.clear();
            pindexNew->anonymitySetHash.clear();
        }

        if (!CheckLelantusBlock(state, *pblock)) {
            return false;
        }

        BOOST_FOREACH(auto& serial, pblock->lelantusTxInfo->spentSerials) {
            if (!CheckLelantusSpendSerial(
                    state,
                    pblock->lelantusTxInfo.get(),
                    serial.first,
                    pindexNew->nHeight,
                    true /* fConnectTip */
                    )) {
                return false;
            }

            if (!fJustCheck) {
                pindexNew->lelantusSpentSerials.insert(serial);
                lelantusState.AddSpend(serial.first, serial.second);
            }
        }

        if (fJustCheck)
            return true;

        auto& params = ::Params().GetConsensus();
        CHash256 hash;
        std::vector<unsigned char> data(GroupElement::serialize_size);
        bool updateHash = false;

        // create first anonymity set hash with whole existing set, at HF block
        if (pindexNew->nHeight == params.nLelantusFixesStartBlock) {
            updateHash = true;
            std::vector<lelantus::PublicCoin> coins;
            lelantusState.GetAnonymitySet(1, false, coins);
            for (auto &coin : coins) {
                coin.getValue().serialize(data.data());
                hash.Write(data.data(), data.size());
            }
        }

        if (!pblock->lelantusTxInfo->mints.empty()) {
            lelantusState.AddMintsToStateAndBlockIndex(pindexNew, pblock);
            int latestCoinId  = lelantusState.GetLatestCoinID();
            // add  coins into hasher, for generating set hash
            // if this is HF block just add mint from this block too,
            // else hasher is supposed to be empty, so add previous hash first, then coins
            if (pindexNew->nHeight >= params.nLelantusFixesStartBlock) {
                updateHash = true;

                if (pindexNew->nHeight > params.nLelantusFixesStartBlock) {
                    // get previous hash of the set, if there is no such, don't write anything
                    std::vector<unsigned char> prev_hash = GetAnonymitySetHash(pindexNew->pprev, latestCoinId, true);
                    if (!prev_hash.empty())
                        hash.Write(prev_hash.data(), 32);
                }

                for (auto &coin : pindexNew->lelantusMintedPubCoins[latestCoinId]) {
                    coin.first.getValue().serialize(data.data());
                    hash.Write(data.data(), data.size());
                }
            }
        }

        // generate hash if we need it
        if (updateHash) {
            unsigned char hash_result[CSHA256::OUTPUT_SIZE];
            hash.Finalize(hash_result);
            auto &out_hash = pindexNew->anonymitySetHash[lelantusState.GetLatestCoinID()];
            out_hash.clear();
            out_hash.insert(out_hash.begin(), std::begin(hash_result), std::end(hash_result));
        }
    }
    else if (!fJustCheck) {
        lelantusState.AddBlock(pindexNew);
    }
    return true;
}

bool GetOutPointFromBlock(COutPoint& outPoint, const GroupElement &pubCoinValue, const CBlock &block) {
    secp_primitives::GroupElement txPubCoinValue;
    // cycle transaction hashes, looking for this pubcoin.
    BOOST_FOREACH(CTransactionRef tx, block.vtx){
        uint32_t nIndex = 0;
        for (const CTxOut &txout: tx->vout) {
            if (txout.scriptPubKey.IsLelantusMint() || txout.scriptPubKey.IsLelantusJMint()) {
                ParseLelantusMintScript(txout.scriptPubKey, txPubCoinValue);
                if(pubCoinValue==txPubCoinValue){
                    outPoint = COutPoint(tx->GetHash(), nIndex);
                    return true;
                }
            }
            nIndex++;
        }
    }

    return false;
}

bool GetOutPoint(COutPoint& outPoint, const lelantus::PublicCoin &pubCoin) {

    lelantus::CLelantusState *lelantusState = lelantus::CLelantusState::GetState();
    auto mintedCoinHeightAndId = lelantusState->GetMintedCoinHeightAndId(pubCoin);
    int mintHeight = mintedCoinHeightAndId.first;
    int coinId = mintedCoinHeightAndId.second;

    if(mintHeight==-1 && coinId==-1)
        return false;

    // get block containing mint
    CBlockIndex *mintBlock = chainActive[mintHeight];
    CBlock block;
    if(!ReadBlockFromDisk(block, mintBlock, ::Params().GetConsensus()))
        LogPrintf("can't read block from disk.\n");

    return GetOutPointFromBlock(outPoint, pubCoin.getValue(), block);
}

bool GetOutPoint(COutPoint& outPoint, const GroupElement &pubCoinValue) {
    lelantus::PublicCoin pubCoin(pubCoinValue);

    return GetOutPoint(outPoint, pubCoin);
}

bool GetOutPoint(COutPoint& outPoint, const uint256 &pubCoinValueHash) {
    GroupElement pubCoinValue;
    lelantus::CLelantusState *lelantusState = lelantus::CLelantusState::GetState();
    if(!lelantusState->HasCoinHash(pubCoinValue, pubCoinValueHash)){
        return false;
    }

    return GetOutPoint(outPoint, pubCoinValue);
}

bool GetOutPointFromMintTag(COutPoint& outPoint, const uint256 &pubCoinTag) {
    GroupElement pubCoinValue;
    lelantus::CLelantusState *lelantusState = lelantus::CLelantusState::GetState();
    if(!lelantusState->HasCoinTag(pubCoinValue, pubCoinTag)){
        return false;
    }

    return GetOutPoint(outPoint, pubCoinValue);
}

bool BuildLelantusStateFromIndex(CChain *chain) {
    for (CBlockIndex *blockIndex = chain->Genesis(); blockIndex; blockIndex=chain->Next(blockIndex))
    {
        lelantusState.AddBlock(blockIndex);
    }
    // DEBUG
    LogPrintf(
        "Latest ID for Lelantus coin group  %d\n",
        lelantusState.GetLatestCoinID());
    return true;
}

// CLelantusTxInfo
void CLelantusTxInfo::Complete() {
    // We need to sort mints lexicographically by serialized value of pubCoin. That's the way old code
    // works, we need to stick to it.
    sort(mints.begin(), mints.end(),
            [](decltype(mints)::const_reference m1, decltype(mints)::const_reference m2)->bool {
            CDataStream ds1(SER_DISK, CLIENT_VERSION), ds2(SER_DISK, CLIENT_VERSION);
            ds1 << m1;
            ds2 << m2;
            return ds1.str() < ds2.str();
            });

    // Mark this info as complete
    fInfoIsComplete = true;
}

/*
 * Util funtions
 */
size_t CountCoinInBlock(CBlockIndex *index, int id) {
    return index->lelantusMintedPubCoins.count(id) > 0
        ? index->lelantusMintedPubCoins[id].size() : 0;
}

/******************************************************************************/
// CLelantusState::Containers
/******************************************************************************/

CLelantusState::Containers::Containers(std::atomic<bool> & surgeCondition)
: surgeCondition(surgeCondition)
{}

void CLelantusState::Containers::AddMint(lelantus::PublicCoin const & pubCoin, CMintedCoinInfo const & coinInfo, const uint256& tag) {
    mintedPubCoins.insert(std::make_pair(pubCoin, coinInfo));
    tagToPublicCoin.insert(std::make_pair(tag, pubCoin));
    mintMetaInfo[coinInfo.coinGroupId] += 1;
    CheckSurgeCondition();
}

void CLelantusState::Containers::RemoveMint(lelantus::PublicCoin const & pubCoin) {
    mint_info_container::const_iterator iter = mintedPubCoins.find(pubCoin);
    if (iter != mintedPubCoins.end()) {
        for(auto hashPair =  tagToPublicCoin.begin(); hashPair !=  tagToPublicCoin.end(); hashPair++)
            if(hashPair->second == pubCoin) {
                tagToPublicCoin.erase(hashPair);
                break;
            }

        mintMetaInfo[iter->second.coinGroupId] -= 1;
        mintedPubCoins.erase(iter);
        CheckSurgeCondition();
    }
}

void CLelantusState::Containers::AddSpend(Scalar const & serial, int coinGroupId) {
    if (!mintMetaInfo.count(coinGroupId)) {
        throw std::invalid_argument("group id doesn't exist");
    }

    usedCoinSerials[serial] = coinGroupId;
    spendMetaInfo[coinGroupId] += 1;
    CheckSurgeCondition();
}

void CLelantusState::Containers::RemoveSpend(Scalar const & serial) {
    auto iter = usedCoinSerials.find(serial);
    if (iter != usedCoinSerials.end()) {
        spendMetaInfo[iter->second] -= 1;
        usedCoinSerials.erase(iter);
        CheckSurgeCondition();
    }
}

void CLelantusState::Containers::AddExtendedMints(int group, size_t mints) {
    extendedMintMetaInfo[group] = mints;
    CheckSurgeCondition();
}

void CLelantusState::Containers::RemoveExtendedMints(int group) {
    extendedMintMetaInfo.erase(group);
    CheckSurgeCondition();
}

mint_info_container const & CLelantusState::Containers::GetMints() const {
    return mintedPubCoins;
}

std::unordered_map<uint256, lelantus::PublicCoin>&  CLelantusState::Containers::GetTagToPublicCoin() {
    return tagToPublicCoin;
}

std::unordered_map<Scalar, int> const & CLelantusState::Containers::GetSpends() const {
    return usedCoinSerials;
}

bool CLelantusState::Containers::IsSurgeCondition() const {
    return surgeCondition;
}

void CLelantusState::Containers::Reset() {
    mintedPubCoins.clear();
    usedCoinSerials.clear();
    mintMetaInfo.clear();
    spendMetaInfo.clear();
    tagToPublicCoin.clear();
    surgeCondition = false;
}

void CLelantusState::Containers::CheckSurgeCondition() {
    bool result = false;

    // find a range of groups that sum of serials larger than sum of mints
    size_t serials = 0;
    size_t mints = 0;
    int start = 0;

    for (auto it = mintMetaInfo.begin(); it != mintMetaInfo.end(); it++) {
        auto id = it->first;

        // include serials and mints to accumulators
        serials += spendMetaInfo.count(id) ? spendMetaInfo[id] : 0;
        mints += it->second;

        // serials exceed mints then trigger
        if (serials > mints) {
            result = true;

            std::ostringstream ostr;
            ostr << "Turning Lelantus surge protection ON: in group range: " << start << " - " << id << '\n';
            error(ostr.str().c_str());

            break;
        }

        auto extendedMints = extendedMintMetaInfo.count(id + 1) ?
            extendedMintMetaInfo[id + 1] : 0;

        if (serials <= mints - extendedMints) {
            start = id + 1;
            serials = 0;
            mints = extendedMints;
        }
    }

    surgeCondition = result;
}

/******************************************************************************/
// CLelantusState
/******************************************************************************/

CLelantusState::CLelantusState(
    size_t maxCoinInGroup,
    size_t startGroupSize)
    :containers(surgeCondition),
    maxCoinInGroup(maxCoinInGroup),
    startGroupSize(startGroupSize)
{
    Reset();
}

void CLelantusState::AddMintsToStateAndBlockIndex(
        CBlockIndex *index,
        const CBlock* pblock) {

    std::vector<std::pair<lelantus::PublicCoin, uint256>> blockMints;
    for (const auto& mint : pblock->lelantusTxInfo->mints) {
        blockMints.push_back(std::make_pair(mint.first, mint.second.second));
    }

    latestCoinId = std::max(1, latestCoinId);

    auto &coinGroup = coinGroups[latestCoinId];

    if (coinGroup.nCoins + blockMints.size() <= maxCoinInGroup) {
        if (coinGroup.nCoins == 0) {
            // first group of coins
            assert(coinGroup.firstBlock == nullptr);
            assert(coinGroup.lastBlock == nullptr);

            coinGroup.firstBlock = coinGroup.lastBlock = index;
        } else {
            assert(coinGroup.firstBlock != nullptr);
            assert(coinGroup.lastBlock != nullptr);
            assert(coinGroup.lastBlock->nHeight <= index->nHeight);

            coinGroup.lastBlock = index;
        }
        coinGroup.nCoins += blockMints.size();
    } else {
        auto& newCoinGroup = coinGroups[++latestCoinId];

        CBlockIndex *first;
        auto coins = CountLastNCoins(latestCoinId - 1, startGroupSize, first);
        newCoinGroup.firstBlock = first ? first : index;
        newCoinGroup.lastBlock = index;
        newCoinGroup.nCoins = coins + blockMints.size();

        containers.AddExtendedMints(latestCoinId, coins);
    }

    for (const auto& mint : blockMints) {
        containers.AddMint(mint.first, CMintedCoinInfo::make(latestCoinId, index->nHeight), mint.second);

        LogPrintf("AddMintsToStateAndBlockIndex: Lelantus mint added id=%d\n", latestCoinId);
        index->lelantusMintedPubCoins[latestCoinId].push_back(mint);
    }
}

void CLelantusState::AddSpend(const Scalar &serial, int coinGroupId) {
    containers.AddSpend(serial, coinGroupId);
}

void CLelantusState::AddBlock(CBlockIndex *index) {
    for (auto const &pubCoins : index->lelantusMintedPubCoins) {

        if (pubCoins.second.empty())
            continue;

        auto &coinGroup = coinGroups[pubCoins.first];

        if (coinGroup.firstBlock == nullptr) {
            coinGroup.firstBlock = index;

            if (pubCoins.first > 1) {
                CBlockIndex *first;
                coinGroup.nCoins = CountLastNCoins(pubCoins.first - 1, startGroupSize, first);
                coinGroup.firstBlock = first ? first : index;

                containers.AddExtendedMints(pubCoins.first, coinGroup.nCoins);
            }
        }
        coinGroup.lastBlock = index;
        coinGroup.nCoins += pubCoins.second.size();

        latestCoinId = pubCoins.first;
        for (auto const &coin : pubCoins.second) {
            containers.AddMint(coin.first, CMintedCoinInfo::make(pubCoins.first, index->nHeight), coin.second);
        }
    }

    for (auto const &serial : index->lelantusSpentSerials) {
        AddSpend(serial.first, serial.second);
    }
}

void CLelantusState::RemoveBlock(CBlockIndex *index) {
    // roll back coin group updates
    for (auto &coins : index->lelantusMintedPubCoins)
    {
        if (coinGroups.count(coins.first) == 0) {
            throw std::invalid_argument("Group Id does not exist");
        }

        LelantusCoinGroupInfo& coinGroup = coinGroups[coins.first];
        auto nMintsToForget = coins.second.size();

        if (nMintsToForget == 0)
            continue;

        assert(coinGroup.nCoins >= nMintsToForget);
        auto isExtended = coins.first > 1;
        coinGroup.nCoins -= nMintsToForget;

        // if `index` is edged block we need to erase group
        auto isEdgedBlock = false;
        if (isExtended) {
            auto prevBlockContainMints = index;
            size_t prevGroupCount = 0;

            // find block that contain some Lelantus mints
            do {
                prevBlockContainMints = prevBlockContainMints->pprev;
            } while (prevBlockContainMints
                && CountCoinInBlock(prevBlockContainMints, coins.first) == 0
                && (prevGroupCount = CountCoinInBlock(prevBlockContainMints, coins.first - 1)) == 0);

            isEdgedBlock = prevGroupCount > 0 && (coinGroup.nCoins - prevGroupCount) < startGroupSize;
        }

        if ((!isExtended && coinGroup.nCoins == 0) || (isExtended && isEdgedBlock)) {
            // all the coins of this group have been erased, remove the group altogether
            coinGroups.erase(coins.first);
            // decrease pubcoin id
            latestCoinId--;
            // erase from containers
            containers.RemoveExtendedMints(coins.first);
        } else {
            // roll back lastBlock to previous position
            assert(coinGroup.lastBlock == index);

            do {
                assert(coinGroup.lastBlock != coinGroup.firstBlock);
                coinGroup.lastBlock = coinGroup.lastBlock->pprev;
            } while (coinGroup.lastBlock->lelantusMintedPubCoins.count(coins.first) == 0);
        }
    }

    // roll back mints
    for (auto const &pubCoins : index->lelantusMintedPubCoins) {
        for (auto const &coin : pubCoins.second) {
            auto coins = containers.GetMints().equal_range(coin.first);
            auto coinIt = find_if(
                coins.first, coins.second,
                [&pubCoins](const mint_info_container::value_type &v) {
                    return v.second.coinGroupId == pubCoins.first;
                });
            assert(coinIt != coins.second);
            containers.RemoveMint(coinIt->first);
        }
    }

    // roll back spends
    for (auto const &serial : index->lelantusSpentSerials) {
        containers.RemoveSpend(serial.first);
    }
}

bool CLelantusState::GetCoinGroupInfo(
        int group_id,
        LelantusCoinGroupInfo& result) {
    if (coinGroups.count(group_id) == 0)
        return false;

    result = coinGroups[group_id];
    return true;
}

bool CLelantusState::IsUsedCoinSerial(const Scalar &coinSerial) {
    return containers.GetSpends().count(coinSerial) != 0;
}

bool CLelantusState::IsUsedCoinSerialHash(Scalar &coinSerial, const uint256 &coinSerialHash) {
    for ( auto it = GetSpends().begin(); it != GetSpends().end(); ++it ){
        if(primitives::GetSerialHash(it->first)==coinSerialHash){
            coinSerial = it->first;
            return true;
        }
    }
    return false;
}

bool CLelantusState::HasCoin(const lelantus::PublicCoin& pubCoin) {
    return containers.GetMints().find(pubCoin) != containers.GetMints().end();
}

bool CLelantusState::HasCoinHash(GroupElement &pubCoinValue, const uint256 &pubCoinValueHash) {
    for ( auto it = GetMints().begin(); it != GetMints().end(); ++it ){
        const lelantus::PublicCoin & pubCoin = (*it).first;
        if(pubCoin.getValueHash()==pubCoinValueHash){
            pubCoinValue = pubCoin.getValue();
            return true;
        }
    }
    return false;
}

bool CLelantusState::HasCoinTag(GroupElement& pubCoinValue, const uint256& pubCoinTag) {
    auto const& mints = containers.GetTagToPublicCoin();
    if(mints.count(pubCoinTag) > 0) {
        pubCoinValue = mints.at(pubCoinTag).getValue();
        return true;
    }
    return false;
}

int CLelantusState::GetCoinSetForSpend(
    CChain *chain,
    int maxHeight,
    int coinGroupID,
    uint256& blockHash_out,
    std::vector<lelantus::PublicCoin>& coins_out,
    std::vector<unsigned char>& setHash_out) {

    coins_out.clear();

    if (coinGroups.count(coinGroupID) == 0) {
        return 0;
    }

    LelantusCoinGroupInfo &coinGroup = coinGroups[coinGroupID];

    int numberOfCoins = 0;
    for (CBlockIndex *block = coinGroup.lastBlock;; block = block->pprev) {

        // ignore block heigher than max height
        if (block->nHeight > maxHeight) {
            continue;
        }

        // check coins in group coinGroupID - 1 in the case that using coins from prev group.
        int id = 0;
        if (CountCoinInBlock(block, coinGroupID)) {
            id = coinGroupID;
        } else if (CountCoinInBlock(block, coinGroupID - 1)) {
            id = coinGroupID - 1;
        }

        if (id) {
            if (numberOfCoins == 0) {
                // latest block satisfying given conditions
                // remember block hash and set hash
                blockHash_out = block->GetBlockHash();
                setHash_out =  GetAnonymitySetHash(block, id);
            }
            numberOfCoins += block->lelantusMintedPubCoins[id].size();
            if (block->lelantusMintedPubCoins.count(id) > 0) {
                for (const auto &coin : block->lelantusMintedPubCoins[id]) {
                    LOCK(cs_main);
                    // skip mints from blacklist if nLelantusFixesStartBlock is passed
                    if (chainActive.Height() >= ::Params().GetConsensus().nLelantusFixesStartBlock) {
                        if (::Params().GetConsensus().lelantusBlacklist.count(coin.first.getValue()) > 0) {
                            continue;
                        }
                    }
                    coins_out.push_back(coin.first);
                }
            }
        }

        if (block == coinGroup.firstBlock) {
            break ;
        }
    }

    return numberOfCoins;
}

void CLelantusState::GetAnonymitySet(
        int coinGroupID,
        bool fStartLelantusBlacklist,
        std::vector<lelantus::PublicCoin>& coins_out) {

    coins_out.clear();

    if (coinGroups.count(coinGroupID) == 0) {
        return;
    }

    LelantusCoinGroupInfo &coinGroup = coinGroups[coinGroupID];
    auto params = ::Params().GetConsensus();
    LOCK(cs_main);
    int maxHeight = fStartLelantusBlacklist ? (chainActive.Height() - (ZC_MINT_CONFIRMATIONS - 1)) : (params.nLelantusFixesStartBlock - 1);

    for (CBlockIndex *block = coinGroup.lastBlock;; block = block->pprev) {

        // ignore block heigher than max height
        if (block->nHeight > maxHeight) {
            continue;
        }

        // check coins in group coinGroupID - 1 in the case that using coins from prev group.
        int id = 0;
        if (CountCoinInBlock(block, coinGroupID)) {
            id = coinGroupID;
        } else if (CountCoinInBlock(block, coinGroupID - 1)) {
            id = coinGroupID - 1;
        }

        if (id) {
            if(block->lelantusMintedPubCoins.count(id) > 0) {
                for (const auto &coin : block->lelantusMintedPubCoins[id]) {
                    if (fStartLelantusBlacklist &&
                        chainActive.Height() >= ::Params().GetConsensus().nLelantusFixesStartBlock) {
                        std::vector<unsigned char> vch = coin.first.getValue().getvch();
                        if (::Params().GetConsensus().lelantusBlacklist.count(coin.first.getValue()) > 0) {
                            continue;
                        }
                    }
                    coins_out.push_back(coin.first);
                }
            }
        }

        if (block == coinGroup.firstBlock) {
            break ;
        }
    }
}

std::pair<int, int> CLelantusState::GetMintedCoinHeightAndId(
        const lelantus::PublicCoin& pubCoin) {
    auto coinIt = containers.GetMints().find(pubCoin);

    if (coinIt != containers.GetMints().end()) {
        return std::make_pair(coinIt->second.nHeight, coinIt->second.coinGroupId);
    }
    return std::make_pair(-1, -1);
}

bool CLelantusState::AddSpendToMempool(const std::vector<Scalar> &coinSerials, uint256 txHash) {
    LOCK(mempool.cs);
    BOOST_FOREACH(const Scalar& coinSerial, coinSerials){
        if (IsUsedCoinSerial(coinSerial) || mempool.lelantusState.HasCoinSerial(coinSerial))
            return false;

        mempool.lelantusState.AddSpendToMempool(coinSerial, txHash);
    }

    return true;
}

void CLelantusState::RemoveSpendFromMempool(const std::vector<Scalar> &coinSerials) {
    LOCK(mempool.cs);
    BOOST_FOREACH(const Scalar& coinSerial, coinSerials) {
        mempool.lelantusState.RemoveSpendFromMempool(coinSerial);
    }
}

void CLelantusState::AddMintsToMempool(const std::vector<GroupElement>& pubCoins) {
    LOCK(mempool.cs);
    BOOST_FOREACH(const GroupElement& pubCoin, pubCoins) {
        mempool.lelantusState.AddMintToMempool(pubCoin);
    }
}

void CLelantusState::RemoveMintFromMempool(const GroupElement& pubCoin) {
    LOCK(mempool.cs);
    mempool.lelantusState.RemoveMintFromMempool(pubCoin);
}

uint256 CLelantusState::GetMempoolConflictingTxHash(const Scalar& coinSerial) {
    LOCK(mempool.cs);
    return mempool.lelantusState.GetMempoolConflictingTxHash(coinSerial);
}

bool CLelantusState::CanAddSpendToMempool(const Scalar& coinSerial) {
    LOCK(mempool.cs);    
    return !IsUsedCoinSerial(coinSerial) && !mempool.lelantusState.HasCoinSerial(coinSerial);
}

bool CLelantusState::CanAddMintToMempool(const GroupElement& pubCoin){
    LOCK(mempool.cs);
    return !HasCoin(pubCoin) && !mempool.lelantusState.HasMint(pubCoin);
}

void CLelantusState::Reset() {
    coinGroups.clear();
    latestCoinId = 0;
    containers.Reset();
}

CLelantusState* CLelantusState::GetState() {
    return &lelantusState;
}

int CLelantusState::GetLatestCoinID() const {
    return latestCoinId;
}

bool CLelantusState::IsSurgeConditionDetected() const {
    return surgeCondition;
}

mint_info_container const & CLelantusState::GetMints() const {
    return containers.GetMints();
}

std::unordered_map<Scalar, int> const & CLelantusState::GetSpends() const {
    return containers.GetSpends();
}

std::unordered_map<int, CLelantusState::LelantusCoinGroupInfo> const & CLelantusState::GetCoinGroups() const {
    return coinGroups;
}

std::unordered_map<Scalar, uint256, sigma::CScalarHash> const & CLelantusState::GetMempoolCoinSerials() const {
    LOCK(mempool.cs);
    return mempool.lelantusState.GetMempoolCoinSerials();
}

// private
size_t CLelantusState::CountLastNCoins(int groupId, size_t required, CBlockIndex* &first) {
    first = nullptr;
    size_t coins = 0;

    if (coinGroups.count(groupId)) {
        auto &group = coinGroups[groupId];

        for (auto block = group.lastBlock
            ; coins < required && block
            ; block = block->pprev) {

            size_t inBlock;
            if (block->lelantusMintedPubCoins.count(groupId)
                && (inBlock = block->lelantusMintedPubCoins[groupId].size())) {

                coins += inBlock;
                first = block;
            }
        }
    }

    return coins;
}

// CLelantusMempoolState

bool CLelantusMempoolState::HasCoinSerial(const Scalar& coinSerial) {
    return mempoolCoinSerials.count(coinSerial) > 0;
}

bool CLelantusMempoolState::HasMint(const GroupElement& pubCoin) {
    return mempoolMints.count(pubCoin) > 0;
}

bool CLelantusMempoolState::AddSpendToMempool(const Scalar &coinSerial, uint256 txHash) {
    return mempoolCoinSerials.insert({coinSerial, txHash}).second;
}

void CLelantusMempoolState::AddMintToMempool(const GroupElement& pubCoin) {
    mempoolMints.insert(pubCoin);
}

void CLelantusMempoolState::RemoveMintFromMempool(const GroupElement& pubCoin) {
    mempoolMints.erase(pubCoin);
}

uint256 CLelantusMempoolState::GetMempoolConflictingTxHash(const Scalar& coinSerial) {
    if (mempoolCoinSerials.count(coinSerial) == 0)
        return uint256();

    return mempoolCoinSerials[coinSerial];
}

void CLelantusMempoolState::RemoveSpendFromMempool(const Scalar &coinSerial) {
    mempoolCoinSerials.erase(coinSerial);
}

void CLelantusMempoolState::Reset() {
    mempoolCoinSerials.clear();
    mempoolMints.clear();
}


} // end of namespace lelantus.
