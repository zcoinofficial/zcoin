#include "txprocessor.h"

#include "rules.h"
#include "lelantus.h"
#include "lelantusdb.h"
#include "lelantusutils.h"

#include "../base58.h"

namespace elysium {

TxProcessor *txProcessor;

int TxProcessor::ProcessTx(CMPTransaction& tx)
{
    LOCK(cs_main);

    tx.unlockLogic();

    auto result = tx.interpretPacket();

    if (result == (PKT_ERROR - 100)) {
        // Unknow transaction type.
        switch (tx.getType()) {
        case ELYSIUM_TYPE_LELANTUS_MINT:
            result = ProcessLelantusMint(tx);
            break;

        case ELYSIUM_TYPE_LELANTUS_JOINSPLIT:
            result = ProcessLelantusJoinSplit(tx);
            break;

        case ELYSIUM_TYPE_CHANGE_LELANTUS_STATUS:
            result = ProcessChangeLelantusStatus(tx);
            break;
        }
    }

    if (result) {
        return result; // Error.
    }

    TransactionProcessed(tx);

    return 0;
}

int TxProcessor::ProcessLelantusMint(const CMPTransaction& tx)
{
    auto block = tx.getBlock();
    auto type = tx.getType();
    auto version = tx.getVersion();
    auto property = tx.getProperty();

    if (!IsTransactionTypeAllowed(block, property, type, version)) {
        PrintToLog("%s(): rejected: type %d or version %d not permitted for property %d at block %d\n",
            __func__,
            type,
            version,
            property,
            block
        );
        return PKT_ERROR_LELANTUS - 22;
    }

    int64_t mintValue = tx.getLelantusMintValue();
    if (mintValue <= 0) {
        PrintToLog("%s(): mintValue <= 0 ", __func__);
        return PKT_ERROR_LELANTUS - 23;
    }

    if (!IsPropertyIdValid(property)) {
        PrintToLog("%s(): rejected: property %d does not exist\n", __func__, property);
        return PKT_ERROR_LELANTUS - 24;
    }

    if (!IsLelantusEnabled(property)) {
        PrintToLog("%s(): rejected: property %d does not enable lelantus\n", __func__, property);
        return PKT_ERROR_LELANTUS - 901;
    }

    auto coin = tx.getLelantusMint();
    auto rawProof = tx.getLelantusSchnorrProof();

    if (rawProof.size() != 98) {
        PrintToLog("%s(): rejected: schnorr proof size is invalid\n", __func__);
        return PKT_ERROR_LELANTUS - 907;
    }

    CDataStream ss(rawProof, SER_DISK, CLIENT_VERSION);
    lelantus::SchnorrProof proof;
    ss >> proof;

    if (!lelantus::VerifyMintSchnorrProof(mintValue, coin.getValue(), proof)) {
        PrintToLog("%s(): rejected: schnorr proof is not exist\n", __func__);
        return PKT_ERROR_LELANTUS - 907;
    }

    if (lelantusDb->HasMint(property, coin)) {
        PrintToLog("%s(): rejected: public coin are already found on chain\n", __func__);
        return PKT_ERROR_LELANTUS - 907;
    }

    auto& sender = tx.getSender();
    int64_t balance = getMPbalance(sender, property, BALANCE);

    if (balance < mintValue) {
        PrintToLog("%s(): rejected: sender %s has insufficient balance of property %d [%s < %s]\n",
            __func__,
            tx.getSender(),
            property,
            FormatMP(property, balance),
            FormatMP(property, mintValue)
        );
        return PKT_ERROR_LELANTUS - 25;
    }

    // subtract balance
    assert(update_tally_map(sender, property, -mintValue, BALANCE));
    if (!lelantusDb->WriteMint(property, coin, tx.getBlock(), tx.getLelantusMintId(), mintValue, rawProof)) {
        PrintToLog("%s(): rejected: fail to write mint to database\n", __func__);
        return PKT_ERROR_LELANTUS - 907;
    }

    PrintToLog("%s(): Lelantus mint for Elysium property %d accepted from %s: %d\n", __func__, property, sender, tx.getLelantusMintValue());

    return 0;
}

int TxProcessor::ProcessLelantusJoinSplit(const CMPTransaction& tx)
{
    auto block = tx.getBlock();
    if (block < 0) {
        PrintToLog("%s(): rejected unconfirmed transaction %s\n", __func__, tx.getHash().GetHex());
        return PKT_ERROR_LELANTUS - 907;
    }

    auto type = tx.getType();
    auto version = tx.getVersion();
    auto property = tx.getProperty();

    if (!IsTransactionTypeAllowed(block, property, type, version)) {
        PrintToLog("%s(): rejected: type %d or version %d not permitted for property %d at block %d\n",
            __func__,
            type,
            version,
            property,
            block);
        return PKT_ERROR_LELANTUS - 22;
    }

    if (!IsPropertyIdValid(property)) {
        PrintToLog("%s(): rejected: property %d does not exist\n", __func__, property);
        return PKT_ERROR_LELANTUS - 24;
    }

    if (!IsLelantusEnabled(property)) {
        PrintToLog("%s(): rejected: property %d does not enable lelantus\n", __func__, property);
        return PKT_ERROR_LELANTUS - 901;
    }

    lelantus::JoinSplit joinSplit = tx.getLelantusJoinSplit();

    CBitcoinAddress receiver(tx.getReceiver());
    if (!receiver.IsValid()) {
        PrintToLog("%s(): rejected: receiver address is invalid\n", __func__);
        return PKT_ERROR_LELANTUS - 45;
    }

    auto metadata = PrepareSpendMetadata(receiver, tx.getReferenceAmount().get());

    // check serials
    auto serials = joinSplit.getCoinSerialNumbers();
    std::unordered_set<secp_primitives::Scalar> txSerials;
    for (auto const &s : serials) {
        uint256 spendTx;
        if (txSerials.count(s) || lelantusDb->HasSerial(property, s, spendTx)) {
            PrintToLog("%s(): rejected: serial is duplicated\n", __func__);
            return PKT_ERROR_LELANTUS - 907;
        }

        txSerials.insert(s);
    }

    // get anons
    auto idAndBlockHashes = joinSplit.getIdAndBlockHashes();

    uint256 highestBlock;
    int highestBlockHeight = 0;

    std::map<uint32_t, std::vector<lelantus::PublicCoin>> anonss;
    for (auto const &idAndBlockHash : idAndBlockHashes) {
        auto coinBlock = mapBlockIndex.find(idAndBlockHash.second);
        if (coinBlock == mapBlockIndex.end()) {
            PrintToLog("%s(): rejected: joinsplit has unknown block as an input\n", __func__);
            return PKT_ERROR_LELANTUS - 907;
        }
        anonss[idAndBlockHash.first] = lelantusDb->GetAnonymityGroup(property, idAndBlockHash.first, SIZE_MAX, coinBlock->second->nHeight);

        if (coinBlock->second->nHeight > highestBlockHeight) {
            highestBlockHeight = coinBlock->second->nHeight;
            highestBlock = coinBlock->second->GetBlockHash();
        }
    }

    // It is safe to use the hashes of blocks instead of the hashes of anonymity sets because blocks hashes are
    // necessarily dependent on anonymity set hashes.
    std::vector<std::vector<unsigned char>> anonymitySetHashes;
    std::vector<unsigned char> anonymitySetHash(highestBlock.begin(), highestBlock.end());
    anonymitySetHashes.push_back(anonymitySetHash);

    auto spendAmount = tx.getLelantusSpendAmount();
    auto joinSplitMint = tx.getLelantusJoinSplitMint();

    std::vector<lelantus::PublicCoin> cout;
    if (joinSplitMint.get_ptr() != nullptr) {
        cout.push_back(joinSplitMint->publicCoin);
    }

    // verify
    if (!joinSplit.VerifyElysium(anonss, anonymitySetHashes, cout, spendAmount, metadata)) {
        PrintToLog("%s(): rejected: joinsplit is invalid\n", __func__);
        return PKT_ERROR_LELANTUS - 907;
    }

    // record serial and change
    for (auto const &s : serials) {
        if (!lelantusDb->WriteSerial(property, s, block, tx.getHash())) {
            PrintToLog("%s(): rejected: serial is duplicated\n", __func__);
            return PKT_ERROR_LELANTUS - 907;
        }
    }

    if (joinSplitMint.get_ptr() != nullptr) {
        if (!lelantusDb->WriteMint(property, joinSplitMint.get(), block)) {
            PrintToLog("%s(): error writing mint\n", __func__);
            // Accept the spend even if the mint is invalid. The mint will be unusable though.
        }
    }

    assert(update_tally_map(tx.getReceiver(), property, spendAmount, BALANCE));

    PrintToLog("%s(): Lelantus joinsplit for Elysium property %d accepted to %s: %d\n", __func__, property, tx.getReceiver(), spendAmount);

    return 0;
}

int TxProcessor::ProcessChangeLelantusStatus(const CMPTransaction& tx)
{
    auto block = tx.getBlock();
    auto type = tx.getType();
    auto version = tx.getVersion();
    auto property = tx.getProperty();
    auto status = tx.getLelantusStatus();
    auto sender = tx.getSender();

    uint256 blockHash;
    {
        LOCK(cs_main);

        CBlockIndex* pindex = chainActive[block];
        if (pindex == NULL) {
            PrintToLog("%s(): ERROR: block %d not in the active chain\n", __func__, block);
            return (PKT_ERROR_TOKENS -20);
        }
        blockHash = pindex->GetBlockHash();
    }

    if (!IsTransactionTypeAllowed(block, property, type, version)) {
        PrintToLog("%s(): rejected: type %d or version %d not permitted for property %d at block %d\n",
            __func__,
            type,
            version,
            property,
            block);
        return PKT_ERROR_LELANTUS - 22;
    }

    if (!IsPropertyIdValid(property)) {
        PrintToLog("%s(): rejected: property %d does not exist\n", __func__, property);
        return (PKT_ERROR_TOKENS -24);
    }

    if (!IsLelantusStatusUpdatable(property)) {
        PrintToLog("%s(): rejected: lelantus status of property %d is unupdatable\n", __func__, property);
        return (PKT_ERROR_TOKENS -43);
    }

    CMPSPInfo::Entry sp;
    assert(_my_sps->getSP(property, sp));

    if (sender != sp.issuer) {
        PrintToLog("%s(): rejected: sender %s is not issuer of property %d [issuer=%s]\n", __func__, sender, property, sp.issuer);
        return (PKT_ERROR_TOKENS -43);
    }

    sp.lelantusStatus = status;
    sp.update_block = blockHash;

    assert(_my_sps->updateSP(property, sp));

    return 0;
}

}
