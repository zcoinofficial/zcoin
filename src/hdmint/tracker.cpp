// Copyright (c) 2019 The Firo Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hdmint/hdmint.h>
#include "hdmint/tracker.h"
#include "util.h"
#include "sync.h"
#include "txdb.h"
#include "wallet/wallet.h"
#include "hdmint/wallet.h"
#include "validation.h"
#include "sigma.h"
#include "lelantus.h"
#include "txmempool.h"

using namespace sigma;

/**
 * CHDMintTracker constructor.
 *
 * Sets the wallet file string and clears the in-memory map of serial hashes -> CMintMeta objects
 * and the map of serial hashes -> pending spend txids.
 *
 * @param strWalletFile wallet file string
 */
CHDMintTracker::CHDMintTracker(std::string strWalletFile)
{
    this->strWalletFile = strWalletFile;
    mapSerialHashes.clear();
    mapLelantusSerialHashes.clear();
    mapPendingSpends.clear();
    fInitialized = false;
}

/**
 * Destroy the CHDMintTracker object.
 *
 * clears the in-memory map of serial hashes -> CMintMeta objects and the map of
 * serial hashes -> pending spend txids.
 *
 */
CHDMintTracker::~CHDMintTracker()
{
    mapSerialHashes.clear();
    mapLelantusSerialHashes.clear();
    mapPendingSpends.clear();
}

/**
 * Initialize the CHDMintTracker object.
 *
 * Calls ListMints, which loads all CSigmaEntries and CHDMints from the database.
 *
 * @return void
 */
void CHDMintTracker::Init()
{
    if (!fInitialized) {
        ListMints(false, false, false, true);
        ListLelantusMints(false, false, false, true);
        fInitialized = true;
    }
}

/**
 * Archive a mint.
 *
 * Ensures the mint exists in the database and then adds it to the archive.
 *
 * @param meta mint meta object
 * @return success
 */
bool CHDMintTracker::Archive(CMintMeta& meta)
{
    uint256 hashPubcoin = meta.GetPubCoinValueHash();

    if (HasSerialHash(meta.hashSerial))
        mapSerialHashes.at(meta.hashSerial).isArchived = true;

   CWalletDB walletdb(strWalletFile);
    CHDMint dMint;
    if (!walletdb.ReadHDMint(hashPubcoin, false, dMint))
        return error("%s: could not find pubcoinhash %s in db", __func__, hashPubcoin.GetHex());
    if (!walletdb.ArchiveDeterministicOrphan(dMint))
        return error("%s: failed to archive deterministic ophaned mint", __func__);

    LogPrintf("%s: archived pubcoinhash %s\n", __func__, hashPubcoin.GetHex());
    return true;
}

bool CHDMintTracker::Archive(CLelantusMintMeta& meta)
{
    uint256 hashPubcoin = meta.GetPubCoinValueHash();

    if (HasLelantusSerialHash(meta.hashSerial))
        mapLelantusSerialHashes.at(meta.hashSerial).isArchived = true;

    CWalletDB walletdb(strWalletFile);
    CHDMint dMint;
    if (!walletdb.ReadHDMint(hashPubcoin, true, dMint))
        return error("%s: could not find pubcoinhash %s in db", __func__, hashPubcoin.GetHex());
    if (!walletdb.ArchiveDeterministicOrphan(dMint))
        return error("%s: failed to archive deterministic ophaned mint", __func__);

    LogPrintf("%s: archived pubcoinhash %s\n", __func__, hashPubcoin.GetHex());
    return true;
}

/**
 * Unarchives a mint.
 *
 * @param hashPubcoin reference to mint pubcoin hash
 * @return success
 */
bool CHDMintTracker::UnArchive(const uint256& hashPubcoin, bool isDeterministic)
{
    CWalletDB walletdb(strWalletFile);
    if (isDeterministic) {
        CHDMint dMint;
        if (!walletdb.UnarchiveHDMint(hashPubcoin, false, dMint))
            return error("%s: failed to unarchive deterministic mint", __func__);
        Add(walletdb, dMint, false);
    } else {
        CSigmaEntry sigma;
        if (!walletdb.UnarchiveSigmaMint(hashPubcoin, sigma))
            return error("%s: failed to unarchivesigma mint", __func__);
        Add(walletdb, sigma, false);
    }

    LogPrintf("%s: unarchived %s\n", __func__, hashPubcoin.GetHex());
    return true;
}

/**
 * Get a CMintMeta object from memory using mint serial hash
 *
 * @param hashSerial mint serial hash used to retrieve object
 * @param mMeta reference to CMintMeta object
 * @return success
 */
bool CHDMintTracker::GetMetaFromSerial(const uint256 &hashSerial, CMintMeta& mMeta)
{
    auto it = mapSerialHashes.find(hashSerial);
    if(it == mapSerialHashes.end())
        return false;

    mMeta = mapSerialHashes.at(hashSerial);
    return true;
}

bool CHDMintTracker::GetMetaFromSerial(const uint256 &hashSerial, CLelantusMintMeta& mMeta)
{
    auto it = mapLelantusSerialHashes.find(hashSerial);
    if(it == mapLelantusSerialHashes.end())
        return false;

    mMeta = mapLelantusSerialHashes.at(hashSerial);
    return true;
}

/**
 * Get a CMintMeta object from memory using mint pubcoin hash
 *
 * @param hashPubcoin mint pubcoin hash used to retrieve object
 * @param mMeta reference to CMintMeta object
 * @return success
 */
bool CHDMintTracker::GetMetaFromPubcoin(const uint256& hashPubcoin, CMintMeta& mMeta)
{
    for (auto it : mapSerialHashes) {
        if (it.second.GetPubCoinValueHash() == hashPubcoin){
            mMeta = it.second;
            return true;
        }
    }

    return false;
}

bool CHDMintTracker::GetLelantusMetaFromPubcoin(const uint256& hashPubcoin, CLelantusMintMeta& mMeta)
{
    for (auto it : mapLelantusSerialHashes) {
        if (it.second.GetPubCoinValueHash() == hashPubcoin){
            mMeta = it.second;
            return true;
        }
    }

    return false;
}

/**
 * Get the list of non-archiveed, in-memory mint serial hashes.
 *
 * @return vHashes vector of serial hashes
 */
std::vector<uint256> CHDMintTracker::GetSerialHashes()
{
    std::vector<uint256> vHashes;
    for (auto it : mapSerialHashes) {
        if (it.second.isArchived)
            continue;

        vHashes.emplace_back(it.first);
    }


    return vHashes;
}

/**
 * Does this mint pubcoin hash exist in a CMintMeta object in memory
 *
 * @param hashPubcoin mint pubcoin hash
 * @return success
 */
bool CHDMintTracker::HasSigmaPubcoinHash(const uint256& hashPubcoin, CWalletDB& walletdb) const
{
    for (auto const & it : mapSerialHashes) {
        CMintMeta meta = it.second;
        if (meta.GetPubCoinValueHash() == hashPubcoin)
            return true;
    }

    return false;
}

bool CHDMintTracker::HasLelantusPubcoinHash(const uint256& hashPubcoin, CWalletDB& walletdb) const
{
    for (auto const & it : mapLelantusSerialHashes) {
        CLelantusMintMeta meta = it.second;
        uint256 reducedHash;
        walletdb.ReadPubcoinHashes(meta.GetPubCoinValueHash(), reducedHash);
        if (reducedHash == hashPubcoin)
            return true;
    }

    return false;
}

/**
 * Does this mint serial hash map to a CMintMeta object in memory
 *
 * @param hashSerial mint serial hash
 * @return success
 */
bool CHDMintTracker::HasSerialHash(const uint256& hashSerial) const
{
    auto it = mapSerialHashes.find(hashSerial);
    return it != mapSerialHashes.end();
}

bool CHDMintTracker::HasLelantusSerialHash(const uint256& hashSerial) const
{
    auto it = mapLelantusSerialHashes.find(hashSerial);
    return it != mapLelantusSerialHashes.end();
}

/**
 * Update the tracker state
 *
 * From the CMintMeta object passed, update the state (both memory and database) accordingly.
 * If a CHDMint object does not exist for this mint, fail.
 *
 * @param meta the CMintMeta object used to update
 * @return success
 */
bool CHDMintTracker::UpdateState(const CMintMeta& meta)
{
    uint256 hashPubcoin = meta.GetPubCoinValueHash();
    CWalletDB walletdb(strWalletFile);

    if (meta.isDeterministic) {
        CHDMint dMint;
        if (!walletdb.ReadHDMint(hashPubcoin, false, dMint)) {
            // Check archive just in case
            if (!meta.isArchived)
                return error("%s: failed to read deterministic mint from database", __func__);

            // Unarchive this mint since it is being requested and updated
            if (!walletdb.UnarchiveHDMint(hashPubcoin, false, dMint))
                return error("%s: failed to unarchive deterministic mint from database", __func__);
        }

        // get coin id & height
        int height, id;
        if(meta.nHeight<0 || meta.nId <= 0){
            sigma::CoinDenomination denom;
            IntegerToDenomination(dMint.GetAmount(), denom);
            std::tie(height, id) = sigma::CSigmaState::GetState()->GetMintedCoinHeightAndId(sigma::PublicCoin(dMint.GetPubcoinValue(), denom));
        }
        else{
            height = meta.nHeight;
            id = meta.nId;
        }

        dMint.SetHeight(height);
        dMint.SetId(id);
        dMint.SetUsed(meta.isUsed);
        int64_t amount;
        DenominationToInteger(meta.denom, amount);
        dMint.SetAmount(amount);

        if (!walletdb.WriteHDMint(dMint.GetPubCoinHash(), dMint, false))
            return error("%s: failed to update deterministic mint when writing to db", __func__);

        pwalletMain->NotifyZerocoinChanged(
            pwalletMain,
            dMint.GetPubcoinValue().GetHex(),
            std::string("Update (") + std::to_string((double)dMint.GetAmount() / COIN) + "mint)",
            CT_UPDATED);
    } else {
        CSigmaEntry sigma;
        if (!walletdb.ReadSigmaEntry(meta.GetPubCoinValue(), sigma))
            return error("%s: failed to read mint from database", __func__);

        sigma.nHeight = meta.nHeight;
        sigma.id = meta.nId;
        sigma.IsUsed = meta.isUsed;
        sigma.set_denomination(meta.denom);

        if (!walletdb.WriteSigmaEntry(sigma))
            return error("%s: failed to write mint to database", __func__);

        pwalletMain->NotifyZerocoinChanged(
            pwalletMain,
            sigma.value.GetHex(),
            std::string("Update (") + std::to_string((double)sigma.get_denomination_value() / COIN) + "mint)",
            CT_UPDATED);
    }

    mapSerialHashes[meta.hashSerial] = meta;

    return true;
}

bool CHDMintTracker::UpdateState(const CLelantusMintMeta& meta)
{
    uint256 hashPubcoin = meta.GetPubCoinValueHash();
    CWalletDB walletdb(strWalletFile);

    CHDMint dMint;
    if (!walletdb.ReadHDMint(hashPubcoin, true, dMint)) {
        // Check archive just in case
        if (!meta.isArchived)
            return error("%s: failed to read Lelantus mint from database", __func__);

        // Unarchive this mint since it is being requested and updated
        if (!walletdb.UnarchiveHDMint(hashPubcoin, true, dMint))
            return error("%s: failed to unarchive Lelantus mint from database", __func__);
    }

    // get coin id & height
    int height, id;
    if(meta.nHeight<0 || meta.nId <= 0){
        std::tie(height, id) = lelantus::CLelantusState::GetState()->GetMintedCoinHeightAndId(lelantus::PublicCoin(dMint.GetPubcoinValue()));
    }
    else{
        height = meta.nHeight;
        id = meta.nId;
    }

    dMint.SetHeight(height);
    dMint.SetId(id);
    dMint.SetUsed(meta.isUsed);
    dMint.SetAmount(meta.amount);

    if (!walletdb.WriteHDMint(meta.GetPubCoinValueHash(), dMint, true))
        return error("%s: failed to update Lelantus mint when writing to db", __func__);

    auto pubcoin = dMint.GetPubcoinValue() + lelantus::Params::get_default()->get_h1() * Scalar(meta.amount).negate();
    walletdb.WritePubcoinHashes(hashPubcoin, primitives::GetPubCoinValueHash(pubcoin));


    pwalletMain->NotifyZerocoinChanged(
            pwalletMain,
            dMint.GetPubcoinValue().GetHex(),
            std::string("Update (") + std::to_string((double)dMint.GetAmount() / COIN) + "mint)",
            CT_UPDATED);

    mapLelantusSerialHashes[meta.hashSerial] = meta;

    return true;
}

/**
 * Add a mint object to memory.
 *
 * If this is a new mint, also write the CHDMint object to database.
 * Also notifies Qt that a Sigma mint has been added so as to update the balance display correctly.
 * This is used to populate memory on startup.
 *
 * @param dMint CHDMint object to add
 * @param isNew set to true if this mint has just been created, also adds mint to database
 * @param isArchived set to true if this mint is archived, used to set meta object correctly
 * @return success
 */
void CHDMintTracker::Add(CWalletDB& walletdb, const CHDMint& dMint, bool isNew, bool isArchived)
{
    CMintMeta meta;
    meta.SetPubCoinValue(dMint.GetPubcoinValue());
    meta.nHeight = dMint.GetHeight();
    meta.nId = dMint.GetId();
    meta.txid = dMint.GetTxHash();
    meta.isUsed = dMint.IsUsed();
    meta.hashSerial = dMint.GetSerialHash();
    sigma::CoinDenomination denom;
    IntegerToDenomination(dMint.GetAmount(), denom);
    meta.denom = denom;
    meta.isArchived = isArchived;
    meta.isDeterministic = true;
    meta.isSeedCorrect = true;
    mapSerialHashes[meta.hashSerial] = meta;

    pwalletMain->NotifyZerocoinChanged(
        pwalletMain,
        dMint.GetPubcoinValue().GetHex(),
        std::string("Update (") + std::to_string((double)dMint.GetAmount() / COIN) + "mint)",
        CT_UPDATED);

    if (isNew)
        walletdb.WriteHDMint(meta.GetPubCoinValueHash(), dMint, false);
}

void CHDMintTracker::AddLelantus(CWalletDB& walletdb, const CHDMint& dMint, bool isNew, bool isArchived)
{
    CLelantusMintMeta meta;
    meta.SetPubCoinValue(dMint.GetPubcoinValue());
    meta.nHeight = dMint.GetHeight();
    meta.nId = dMint.GetId();
    meta.txid = dMint.GetTxHash();
    meta.isUsed = dMint.IsUsed();
    meta.hashSerial = dMint.GetSerialHash();
    meta.amount = dMint.GetAmount();
    meta.isArchived = isArchived;
    meta.isSeedCorrect = true;
    mapLelantusSerialHashes[meta.hashSerial] = meta;

    pwalletMain->NotifyZerocoinChanged(
            pwalletMain,
            dMint.GetPubcoinValue().GetHex(),
            std::string("Update (") + std::to_string((double)dMint.GetAmount() / COIN) + "mint)",
            CT_UPDATED);

    if (isNew) {
        walletdb.WriteHDMint(meta.GetPubCoinValueHash(), dMint, true);
        auto pubcoin = dMint.GetPubcoinValue() + lelantus::Params::get_default()->get_h1() * Scalar(meta.amount).negate();
        walletdb.WritePubcoinHashes(meta.GetPubCoinValueHash(), primitives::GetPubCoinValueHash(pubcoin));
    }
}

void CHDMintTracker::Add(CWalletDB& walletdb, const CSigmaEntry& sigma, bool isNew, bool isArchived)
{
    CMintMeta meta;
    meta.SetPubCoinValue(sigma.value);
    meta.nHeight = sigma.nHeight;
    meta.nId = sigma.id;
    //meta.txid = sigma.GetTxHash();
    meta.isUsed = sigma.IsUsed;
    meta.hashSerial = primitives::GetSerialHash(sigma.serialNumber);
    meta.denom = sigma.get_denomination();
    meta.isArchived = isArchived;
    meta.isDeterministic = false;
    meta.isSeedCorrect = true;
    mapSerialHashes[meta.hashSerial] = meta;

    if (isNew)
        walletdb.WriteSigmaEntry(sigma);
}

/**
 * Sets a mint as used via it's pubcoin hash.
 *
 * @param hashPubcoin mint pubcoin hash. Used to retrieve meta object
 * @param txid transaction ID of mint
 * @return void
 */
void CHDMintTracker::SetPubcoinUsed(const uint256& hashPubcoin, const uint256& txid)
{
    CMintMeta meta;
    if(!GetMetaFromPubcoin(hashPubcoin, meta))
        return;
    meta.isUsed = true;
    mapPendingSpends.insert(std::make_pair(meta.hashSerial, txid));
    UpdateState(meta);
}

void CHDMintTracker::SetLelantusPubcoinUsed(const uint256& hashPubcoin, const uint256& txid)
{
    CLelantusMintMeta meta;
    if(!GetLelantusMetaFromPubcoin(hashPubcoin, meta))
        return;
    meta.isUsed = true;
    mapPendingSpends.insert(std::make_pair(meta.hashSerial, txid));
    UpdateState(meta);
}


/**
 * Sets a mint as not used via it's pubcoin hash.
 *
 * @param hashPubcoin mint pubcoin hash. Used to retrieve meta object
 * @return void
 */
void CHDMintTracker::SetPubcoinNotUsed(const uint256& hashPubcoin)
{
    CMintMeta meta;
    if(!GetMetaFromPubcoin(hashPubcoin, meta))
        return;
    meta.isUsed = false;

    if (mapPendingSpends.count(meta.hashSerial))
        mapPendingSpends.erase(meta.hashSerial);

    UpdateState(meta);
}

void CHDMintTracker::SetLelantusPubcoinNotUsed(const uint256& hashPubcoin)
{
    CLelantusMintMeta meta;
    if(!GetLelantusMetaFromPubcoin(hashPubcoin, meta))
        return;
    meta.isUsed = false;

    if (mapPendingSpends.count(meta.hashSerial))
        mapPendingSpends.erase(meta.hashSerial);

    UpdateState(meta);
}


/**
 * Check mempool for the spend associated with the mint serial hash passed
 *
 * @param setMempool the set of txid hashes in the mempool
 * @param hashSerial the mint serial hash to check for
 * @return success
 */
bool CHDMintTracker::IsMempoolSpendOurs(const std::set<uint256>& setMempool, const uint256& hashSerial){
    for(auto& mempoolTxid : setMempool){
        CTransactionRef ptx = txpools.get(mempoolTxid);
        if(!ptx) {
            continue;
        }

        const CTransaction &tx = *ptx;
        for (const CTxIn& txin : tx.vin) {
            if (txin.IsSigmaSpend()) {
                std::unique_ptr<sigma::CoinSpend> spend;
                uint32_t pubcoinId;
                try {
                    std::tie(spend, pubcoinId) = sigma::ParseSigmaSpend(txin);
                } catch (CBadTxIn &) {
                    return false;
                } catch (std::ios_base::failure &) {
                    return false;
                }

                uint256 mempoolHashSerial = primitives::GetSerialHash(spend->getCoinSerialNumber());
                if(mempoolHashSerial==hashSerial){
                    return true;
                }
            }

            if (txin.IsLelantusJoinSplit()) {
                std::unique_ptr<lelantus::JoinSplit> joinsplit;
                try {
                    joinsplit = lelantus::ParseLelantusJoinSplit(tx);
                } catch (CBadTxIn &) {
                    return false;
                } catch (std::ios_base::failure &) {
                    return false;
                }

                const std::vector<Scalar>& serials = joinsplit->getCoinSerialNumbers();
                for(const auto& serial: serials) {
                    uint256 mempoolHashSerial = primitives::GetSerialHash(serial);
                    if(mempoolHashSerial==hashSerial){
                        return true;
                    }
                }
            }
        }
    }

    return false;
}

/**
 * Update the in-memory CMintMeta object for the current mempool
 *
 * @param setMempool the set of txid hashes in the mempool
 * @param mint the CMintMeta object to check for
 * @param fSpend if this mint object is being updated as a result of a spend transaction
 * @return success
 */
bool CHDMintTracker::UpdateMetaStatus(const std::set<uint256>& setMempool, CMintMeta& mint, bool fSpend)
{
    uint256 hashPubcoin = mint.GetPubCoinValueHash();
    //! Check whether this mint has been spent and is considered 'pending' or 'confirmed'
    // If there is not a record of the block height, then look it up and assign it
    COutPoint outPoint;
    sigma::PublicCoin pubCoin(mint.GetPubCoinValue(), mint.denom);
    bool isMintInChain = GetOutPoint(outPoint, pubCoin);
    LogPrintf("UpdateMetaStatus : isMintInChain: %d\n", isMintInChain);
    const uint256& txidMint = outPoint.hash;

    //See if there is internal record of spending this mint (note this is memory only, would reset on restart - next function checks this)
    bool isPendingSpend = static_cast<bool>(mapPendingSpends.count(mint.hashSerial));

    // Mempool might hold pending spend
    if(!isPendingSpend && fSpend)
        isPendingSpend = IsMempoolSpendOurs(setMempool, mint.hashSerial);

    LogPrintf("UpdateMetaStatus : isPendingSpend: %d\n", isPendingSpend);

    // See if there is a blockchain record of spending this mint
    CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    Scalar bnSerial;
    bool isConfirmedSpend = sigmaState->IsUsedCoinSerialHash(bnSerial, mint.hashSerial);
    LogPrintf("UpdateMetaStatus : isConfirmedSpend: %d\n", isConfirmedSpend);

    bool isUsed = isPendingSpend || isConfirmedSpend;

    if ((mint.nHeight==-1) || (mint.nId==-1) || !isMintInChain || isUsed != mint.isUsed) {
        CTransactionRef tx;
        uint256 hashBlock;

        // Txid will be marked 0 if there is no knowledge of the final tx hash yet
        if (mint.txid.IsNull()) {
            if (!isMintInChain) {
                if(mint.nHeight>-1) mint.nHeight = -1;
                if(mint.nId>-1) mint.nId = -1;
                // still want to update this mint later if syncing. else ignore
                if(IsInitialBlockDownload()){
                    return true;
                }
                return false;
            }
            mint.txid = txidMint;
        }

        LogPrintf("UpdateMetaStatus : mint.txid = %d\n", mint.txid.GetHex());

        if (setMempool.count(mint.txid)) {
            if(mint.nHeight>-1) mint.nHeight = -1;
            if(mint.nId>-1) mint.nId = -1;
            return true;
        }

        // Check the transaction associated with this mint
        if (!GetTransaction(mint.txid, tx, ::Params().GetConsensus(), hashBlock, true)) {
            LogPrintf("%s : Failed to find tx for mint txid=%s\n", __func__, mint.txid.GetHex());
            mint.isArchived = true;
            Archive(mint);
            return true;
        }

        bool isUpdated = false;

        // An orphan tx if hashblock is in mapBlockIndex but not in chain active
        if (mapBlockIndex.count(hashBlock)){
            if(!chainActive.Contains(mapBlockIndex.at(hashBlock))) {
                LogPrintf("%s : Found orphaned mint txid=%s\n", __func__, mint.txid.GetHex());
                mint.isUsed = false;
                mint.nHeight = 0;

                return true;
            }else if((mint.nHeight==-1) || (mint.nId<=0)){ // assign nHeight if not present
                sigma::PublicCoin pubcoin(mint.GetPubCoinValue(), mint.denom);
                auto MintedCoinHeightAndId = sigmaState->GetMintedCoinHeightAndId(pubcoin);
                mint.nHeight = MintedCoinHeightAndId.first;
                mint.nId = MintedCoinHeightAndId.second;
                LogPrintf("%s : Set mint %s nHeight to %d\n", __func__, hashPubcoin.GetHex(), mint.nHeight);
                LogPrintf("%s : Set mint %s nId to %d\n", __func__, hashPubcoin.GetHex(), mint.nId);
                isUpdated = true;
            }
        }

        // Check that the mint has correct used status
        if (mint.isUsed != isUsed) {
            LogPrintf("%s : Set mint %s isUsed to %d\n", __func__, hashPubcoin.GetHex(), isUsed);
            mint.isUsed = isUsed;
            isUpdated = true;
        }

        if(isUpdated) return true;
    }

    return false;
}

bool CHDMintTracker::UpdateLelantusMetaStatus(const std::set<uint256>& setMempool, CLelantusMintMeta& mint, bool fSpend)
{
    uint256 hashPubcoin = mint.GetPubCoinValueHash();
    //! Check whether this mint has been spent and is considered 'pending' or 'confirmed'
    // If there is not a record of the block height, then look it up and assign it
    COutPoint outPoint;
    lelantus::PublicCoin pubCoin(mint.GetPubCoinValue());
    bool isMintInChain = GetOutPoint(outPoint, pubCoin);
    LogPrintf("UpdateLelantusMetaStatus : isMintInChain: %d\n", isMintInChain);
    const uint256& txidMint = outPoint.hash;

    //See if there is internal record of spending this mint (note this is memory only, would reset on restart - next function checks this)
    bool isPendingSpend = static_cast<bool>(mapPendingSpends.count(mint.hashSerial));

    // Mempool might hold pending spend
    if(!isPendingSpend && fSpend)
        isPendingSpend = IsMempoolSpendOurs(setMempool, mint.hashSerial);

    LogPrintf("UpdateLelantusMetaStatus : isPendingSpend: %d\n", isPendingSpend);

    // See if there is a blockchain record of spending this mint
    lelantus::CLelantusState *lelantusState = lelantus::CLelantusState::GetState();
    Scalar bnSerial;
    bool isConfirmedSpend = lelantusState->IsUsedCoinSerialHash(bnSerial, mint.hashSerial);
    LogPrintf("UpdateLelantusMetaStatus : isConfirmedSpend: %d\n", isConfirmedSpend);

    bool isUsed = isPendingSpend || isConfirmedSpend;

    if ((mint.nHeight==-1) || (mint.nId==-1) || !isMintInChain || isUsed != mint.isUsed) {
        CTransactionRef tx;
        uint256 hashBlock;

        // Txid will be marked 0 if there is no knowledge of the final tx hash yet
        if (mint.txid.IsNull()) {
            if (!isMintInChain) {
                if(mint.nHeight>-1) mint.nHeight = -1;
                if(mint.nId>-1) mint.nId = -1;
                // still want to update this mint later if syncing. else ignore
                if(IsInitialBlockDownload()){
                    return true;
                }
                return false;
            }
            mint.txid = txidMint;
        }

        LogPrintf("UpdateLelantusMetaStatus : mint.txid = %d\n", mint.txid.GetHex());

        if (setMempool.count(mint.txid)) {
            if(mint.nHeight>-1) mint.nHeight = -1;
            if(mint.nId>-1) mint.nId = -1;
            return true;
        }

        // Check the transaction associated with this mint
        if (!GetTransaction(mint.txid, tx, ::Params().GetConsensus(), hashBlock, true)) {
            LogPrintf("%s : Failed to find tx for mint txid=%s\n", __func__, mint.txid.GetHex());
            mint.isArchived = true;
            Archive(mint);
            return true;
        }

        bool isUpdated = false;

        // An orphan tx if hashblock is in mapBlockIndex but not in chain active
        if (mapBlockIndex.count(hashBlock)) {
            if(!chainActive.Contains(mapBlockIndex.at(hashBlock))) {
                LogPrintf("%s : Found orphaned mint txid=%s\n", __func__, mint.txid.GetHex());
                mint.isUsed = false;
                mint.nHeight = 0;

                return true;
            } else if((mint.nHeight==-1) || (mint.nId<=0)) { // assign nHeight if not present
                lelantus::PublicCoin pubcoin(mint.GetPubCoinValue());
                auto MintedCoinHeightAndId = lelantusState->GetMintedCoinHeightAndId(pubcoin);
                mint.nHeight = MintedCoinHeightAndId.first;
                mint.nId = MintedCoinHeightAndId.second;
                LogPrintf("%s : Set mint %s nHeight to %d\n", __func__, hashPubcoin.GetHex(), mint.nHeight);
                LogPrintf("%s : Set mint %s nId to %d\n", __func__, hashPubcoin.GetHex(), mint.nId);
                isUpdated = true;
            }
        }

        // Check that the mint has correct used status
        if (mint.isUsed != isUsed) {
            LogPrintf("%s : Set mint %s isUsed to %d\n", __func__, hashPubcoin.GetHex(), isUsed);
            mint.isUsed = isUsed;
            isUpdated = true;
        }

        if(isUpdated) return true;
    }

    return false;
}

/**
 * Update mints found on-chain.
 *
 * @param mintPoolEntries the set of mint pool entries to update
 * @param updatedMeta the CMintMeta objects to update
 * @return void
 */
void CHDMintTracker::UpdateFromBlock(const std::list<std::pair<uint256, MintPoolEntry>>& mintPoolEntries, const std::vector<CMintMeta>& updatedMeta){
    if (mintPoolEntries.size() > 0) {
        pwalletMain->zwallet->SyncWithChain(false, mintPoolEntries);
    }

    //overwrite any updates
    for (CMintMeta meta : updatedMeta)
        UpdateState(meta);
}

void CHDMintTracker::UpdateFromBlock(const std::list<std::pair<uint256, MintPoolEntry>>& mintPoolEntries, const std::vector<CLelantusMintMeta>& updatedMeta){
    if (mintPoolEntries.size() > 0) {
        pwalletMain->zwallet->SyncWithChain(false, mintPoolEntries);
    }

    //overwrite any updates
    for (CLelantusMintMeta meta : updatedMeta)
        UpdateState(meta);
}

/**
 * Update the state if mint transactions found on-chain exist in the wallet.
 *
 * We attempt to read a mintpool object from the on-chain data found. If so, update state.
 *
 * @param mints the set of public coin objects to check for.
 * @return void
 */
void CHDMintTracker::UpdateMintStateFromBlock(const std::vector<sigma::PublicCoin>& mints){
    CWalletDB walletdb(strWalletFile);
    std::vector<CMintMeta> updatedMeta;
    std::list<std::pair<uint256, MintPoolEntry>> mintPoolEntries;
    uint160 hashSeedMasterEntry;
    CKeyID seedId;
    int32_t nCount;
    std::set<uint256> setMempool = GetMempoolTxids();
    for (auto& mint : mints) {
        uint256 hashPubcoin = primitives::GetPubCoinValueHash(mint.getValue());
        CMintMeta meta;
        // Check hashPubcoin in db
        if(walletdb.ReadMintPoolPair(hashPubcoin, hashSeedMasterEntry, seedId, nCount)){
            // If found in db but not in memory - this is likely a resync
            if(!GetMetaFromPubcoin(hashPubcoin, meta)){
                MintPoolEntry mintPoolEntry(hashSeedMasterEntry, seedId, nCount);
                mintPoolEntries.push_back(std::make_pair(hashPubcoin, mintPoolEntry));
                continue;
            }
            if(UpdateMetaStatus(setMempool, meta)){
                updatedMeta.emplace_back(meta);
            }
        }
    }

    UpdateFromBlock(mintPoolEntries, updatedMeta);
}

void CHDMintTracker::UpdateMintStateFromBlock(const std::vector<std::pair<lelantus::PublicCoin, std::pair<uint64_t, uint256>>>& mints) {
    CWalletDB walletdb(strWalletFile);
    std::vector<CLelantusMintMeta> updatedMeta;
    std::list<std::pair<uint256, MintPoolEntry>> mintPoolEntries;
    uint160 hashSeedMasterEntry;
    CKeyID seedId;
    int32_t nCount;
    std::set<uint256> setMempool = GetMempoolTxids();
    for (auto& mint : mints) {
        uint256 reducedHash;
        if(!walletdb.ReadPubcoinHashes(primitives::GetPubCoinValueHash(mint.first.getValue()), reducedHash)) {
            uint64_t amount = mint.second.first;
            auto pubcoin = mint.first.getValue() + lelantus::Params::get_default()->get_h1() * Scalar(amount).negate();
            reducedHash = primitives::GetPubCoinValueHash(pubcoin);
        }
        CLelantusMintMeta meta;
        // Check reducedHash in db
        if(walletdb.ReadMintPoolPair(reducedHash, hashSeedMasterEntry, seedId, nCount)) {
            // If found in db but not in memory - this is likely a resync
            if(!GetLelantusMetaFromPubcoin(primitives::GetPubCoinValueHash(mint.first.getValue()), meta)){
                MintPoolEntry mintPoolEntry(hashSeedMasterEntry, seedId, nCount);
                mintPoolEntries.push_back(std::make_pair(reducedHash, mintPoolEntry));
                continue;
            }
            if(UpdateLelantusMetaStatus(setMempool, meta)){
                updatedMeta.emplace_back(meta);
            }
        }
    }

    UpdateFromBlock(mintPoolEntries, updatedMeta);
}

/**
 * Update the state if spend transactions found on-chain exist in the wallet.
 *
 * We attempt to read a mintpool object from the on-chain data found. If so, update state.
 *
 * @param spentSerials the set of spent serial objects to check for.
 * @return void
 */
void CHDMintTracker::UpdateSpendStateFromBlock(const sigma::spend_info_container& spentSerials){
    CWalletDB walletdb(strWalletFile);
    std::vector<CMintMeta> updatedMeta;
    std::list<std::pair<uint256, MintPoolEntry>> mintPoolEntries;
    uint160 hashSeedMasterEntry;
    CKeyID seedId;
    int32_t nCount;
    std::set<uint256> setMempool = GetMempoolTxids();
    for(auto& spentSerial : spentSerials){
        uint256 spentSerialHash = primitives::GetSerialHash(spentSerial.first);
        CMintMeta meta;
        GroupElement pubcoin;
        // Check serialHash in db
        if(walletdb.ReadPubcoin(spentSerialHash, pubcoin)){
            // If found in db but not in memory - this is likely a resync
            if(!GetMetaFromSerial(spentSerialHash, meta)){
                uint256 hashPubcoin = primitives::GetPubCoinValueHash(pubcoin);
                if(!walletdb.ReadMintPoolPair(hashPubcoin, hashSeedMasterEntry, seedId, nCount)){
                    continue;
                }
                MintPoolEntry mintPoolEntry(hashSeedMasterEntry, seedId, nCount);
                mintPoolEntries.push_back(std::make_pair(hashPubcoin, mintPoolEntry));
                continue;
            }
            if(UpdateMetaStatus(setMempool, meta, true)){
                updatedMeta.emplace_back(meta);
            }
        }
    }

    UpdateFromBlock(mintPoolEntries, updatedMeta);
}

void CHDMintTracker::UpdateSpendStateFromBlock(const std::unordered_map<Scalar, int>& spentSerials){
    CWalletDB walletdb(strWalletFile);
    std::vector<CLelantusMintMeta> updatedMeta;
    std::list<std::pair<uint256, MintPoolEntry>> mintPoolEntries;
    uint160 hashSeedMasterEntry;
    CKeyID seedId;
    int32_t nCount;
    std::set<uint256> setMempool = GetMempoolTxids();
    for(auto& spentSerial : spentSerials){
        uint256 spentSerialHash = primitives::GetSerialHash(spentSerial.first);
        CLelantusMintMeta meta;
        GroupElement pubcoin;
        // Check serialHash in db
        if(walletdb.ReadPubcoin(spentSerialHash, pubcoin)) {
            // If found in db but not in memory - this is likely a resync
            if(!GetMetaFromSerial(spentSerialHash, meta)){
                uint256 hashPubcoin = primitives::GetPubCoinValueHash(pubcoin);
                if(!walletdb.ReadMintPoolPair(hashPubcoin, hashSeedMasterEntry, seedId, nCount)) {
                    continue;
                }
                MintPoolEntry mintPoolEntry(hashSeedMasterEntry, seedId, nCount);
                mintPoolEntries.push_back(std::make_pair(hashPubcoin, mintPoolEntry));
                continue;
            }
            if(UpdateLelantusMetaStatus(setMempool, meta, true)){
                updatedMeta.emplace_back(meta);
            }
        }
    }

    UpdateFromBlock(mintPoolEntries, updatedMeta);
}

/**
 * Update the state if mint transactions found in the mempool exist in the wallet.
 *
 * We attempt to read a mintpool object from the mempool data found. If so, update state.
 *
 * @param pubCoins the set of public coin objects to check for.
 * @return void
 */
void CHDMintTracker::UpdateMintStateFromMempool(const std::vector<GroupElement>& pubCoins){
    CWalletDB walletdb(strWalletFile);
    std::vector<CMintMeta> updatedMeta;
    std::list<std::pair<uint256, MintPoolEntry>> mintPoolEntries;
    uint160 hashSeedMasterEntry;
    CKeyID seedId;
    int32_t nCount;
    std::set<uint256> setMempool = GetMempoolTxids();
    for (auto& pubcoin : pubCoins) {
        uint256 hashPubcoin = primitives::GetPubCoinValueHash(pubcoin);

        LogPrintf("UpdateMintStateFromMempool: hashPubcoin=%d\n", hashPubcoin.GetHex());
        // Check hashPubcoin in db
        if(walletdb.ReadMintPoolPair(hashPubcoin, hashSeedMasterEntry, seedId, nCount)){
            // If found in db but not in memory - this is likely a resync
            CMintMeta meta;
            CLelantusMintMeta metaLelantus;
            bool skip = !GetMetaFromPubcoin(hashPubcoin, meta);

            if(skip) {
                MintPoolEntry mintPoolEntry(hashSeedMasterEntry, seedId, nCount);
                mintPoolEntries.push_back(std::make_pair(hashPubcoin, mintPoolEntry));
                continue;
            }

            if(UpdateMetaStatus(setMempool, meta)){
                updatedMeta.emplace_back(meta);
            }
        }
    }

    UpdateFromBlock(mintPoolEntries, updatedMeta);
}

void CHDMintTracker::UpdateLelantusMintStateFromMempool(const std::vector<GroupElement>& pubCoins, const std::vector<uint64_t>& amounts) {
    CWalletDB walletdb(strWalletFile);
    std::vector<CLelantusMintMeta> updatedLelantusMeta;
    std::list<std::pair<uint256, MintPoolEntry>> mintPoolEntries;
    uint160 hashSeedMasterEntry;
    CKeyID seedId;
    int32_t nCount;
    std::set<uint256> setMempool = GetMempoolTxids();
    int i = 0;
    for (auto& pubcoin : pubCoins) {
        uint256 reducedHash;
        if(!walletdb.ReadPubcoinHashes(primitives::GetPubCoinValueHash(pubcoin), reducedHash)) {
            auto pub = pubcoin + lelantus::Params::get_default()->get_h1() * Scalar(amounts[i]).negate();
            reducedHash = primitives::GetPubCoinValueHash(pub);
        }


        LogPrintf("UpdateMintStateFromMempool: hashPubcoin=%d\n", reducedHash.GetHex());
        // Check reducedHash in db
        if(walletdb.ReadMintPoolPair(reducedHash, hashSeedMasterEntry, seedId, nCount)){
            // If found in db but not in memory - this is likely a resync
            CMintMeta meta;
            CLelantusMintMeta metaLelantus;
            bool skip = !GetLelantusMetaFromPubcoin(primitives::GetPubCoinValueHash(pubcoin), metaLelantus);

            if(skip) {
                MintPoolEntry mintPoolEntry(hashSeedMasterEntry, seedId, nCount);
                mintPoolEntries.push_back(std::make_pair(reducedHash, mintPoolEntry));
                i++;
                continue;
            }

            if(UpdateLelantusMetaStatus(setMempool, metaLelantus)){
                updatedLelantusMeta.emplace_back(metaLelantus);
            }

        }
        i++;
    }

    UpdateFromBlock(mintPoolEntries, updatedLelantusMeta);
}

/**
 * Update the state if spend transactions found in the mempool exist in the wallet.
 *
 * We attempt to read a mintpool object from the mempool data found. If so, update state.
 *
 * @param spentSerials the set of spent serial objects to check for.
 * @return void
 */
void CHDMintTracker::UpdateSpendStateFromMempool(const std::vector<Scalar>& spentSerials) {
    CWalletDB walletdb(strWalletFile);
    std::vector<CMintMeta> updatedMeta;
    std::list<std::pair<uint256, MintPoolEntry>> mintPoolEntries;
    uint160 hashSeedMasterEntry;
    CKeyID seedId;
    int32_t nCount;
    std::set<uint256> setMempool = GetMempoolTxids();
    for(auto& spentSerial : spentSerials){
        uint256 spentSerialHash = primitives::GetSerialHash(spentSerial);
        CMintMeta meta;
        GroupElement pubcoin;
        // Check serialHash in db
        if(walletdb.ReadPubcoin(spentSerialHash, pubcoin)){
            // If found in db but not in memory - this is likely a resync
            if(!GetMetaFromSerial(spentSerialHash, meta)){
                uint256 hashPubcoin = primitives::GetPubCoinValueHash(pubcoin);
                if(!walletdb.ReadMintPoolPair(hashPubcoin, hashSeedMasterEntry, seedId, nCount)){
                    continue;
                }
                MintPoolEntry mintPoolEntry(hashSeedMasterEntry, seedId, nCount);
                mintPoolEntries.push_back(std::make_pair(hashPubcoin, mintPoolEntry));
                continue;
            }
            if(UpdateMetaStatus(setMempool, meta, true)){
                updatedMeta.emplace_back(meta);
            }
        }
    }

    UpdateFromBlock(mintPoolEntries, updatedMeta);
}

void CHDMintTracker::UpdateJoinSplitStateFromMempool(const std::vector<Scalar>& spentSerials) {
    CWalletDB walletdb(strWalletFile);
    std::vector<CLelantusMintMeta> updatedMeta;
    std::list<std::pair<uint256, MintPoolEntry>> mintPoolEntries;
    uint160 hashSeedMasterEntry;
    CKeyID seedId;
    int32_t nCount;
    std::set<uint256> setMempool = GetMempoolTxids();
    for(auto& spentSerial : spentSerials){
        uint256 spentSerialHash = primitives::GetSerialHash(spentSerial);
        CLelantusMintMeta meta;
        GroupElement pubcoin;
        // Check serialHash in db
        if(walletdb.ReadPubcoin(spentSerialHash, pubcoin)) {
            // If found in db but not in memory - this is likely a resync
            if(!GetMetaFromSerial(spentSerialHash, meta)){
                uint256 hashPubcoin = primitives::GetPubCoinValueHash(pubcoin);
                if(!walletdb.ReadMintPoolPair(hashPubcoin, hashSeedMasterEntry, seedId, nCount)) {
                    continue;
                }
                MintPoolEntry mintPoolEntry(hashSeedMasterEntry, seedId, nCount);
                mintPoolEntries.push_back(std::make_pair(hashPubcoin, mintPoolEntry));
                continue;
            }
            if(UpdateLelantusMetaStatus(setMempool, meta, true)){
                updatedMeta.emplace_back(meta);
            }
        }
    }

    UpdateFromBlock(mintPoolEntries, updatedMeta);
}

/**
 * Returns the in memory mint objects as CSigmaEntry objects (ie. mints containing private data)
 *
 * @param fUnusedOnly convert unused mints only
 * @param fMatureOnly convert mature (ie. spendable due to sufficient confirmations) mints only
 * @return list of CSigmaEntry objects
 */
std::list<CSigmaEntry> CHDMintTracker::MintsAsSigmaEntries(bool fUnusedOnly, bool fMatureOnly){
    std::list <CSigmaEntry> listPubcoin;
    CWalletDB walletdb(strWalletFile);
    std::vector<CMintMeta> vecMists = ListMints(fUnusedOnly, fMatureOnly, false);
    std::list<CMintMeta> listMints(vecMists.begin(), vecMists.end());
    for (const CMintMeta& mint : listMints) {
        CSigmaEntry entry;
        pwalletMain->GetMint(mint.hashSerial, entry);
        listPubcoin.push_back(entry);
    }
    return listPubcoin;
}

std::list<CLelantusEntry> CHDMintTracker::MintsAsLelantusEntries(bool fUnusedOnly, bool fMatureOnly){
    std::list <CLelantusEntry> listCoin;
    CWalletDB walletdb(strWalletFile);
    std::vector<CLelantusMintMeta> vecMists = ListLelantusMints(fUnusedOnly, fMatureOnly, false);
    std::list<CLelantusMintMeta> listMints(vecMists.begin(), vecMists.end());
    for (const CLelantusMintMeta& mint : listMints) {
        CLelantusEntry entry;
        pwalletMain->GetMint(mint.hashSerial, entry);
        listCoin.push_back(entry);
    }
    return listCoin;
}

/**
 * Sets up the in memory mint objects.
 *
 * @param fUnusedOnly process unused mints only
 * @param fUnusedOnly process mature (ie. spendable due to sufficient confirmations) mints only
 * @param fUpdateStatus If the mints should be updated
 * @param fLoad If the mints should be loaded from database
 * @param fWrongSeed If mints without correct seed should be added
 * @return vector of CMintMeta objects
 */
std::vector<CMintMeta> CHDMintTracker::ListMints(bool fUnusedOnly, bool fMatureOnly, bool fUpdateStatus, bool fLoad, bool fWrongSeed)
{
    std::vector<CMintMeta> setMints;
    if (fLoad) {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        CWalletDB walletdb(strWalletFile);
        std::list<CSigmaEntry> listMintsDB;
        walletdb.ListSigmaPubCoin(listMintsDB);
        for (auto& mint : listMintsDB){
            Add(walletdb, mint);
        }
        LogPrint("zero", "%s: added %d sigmamints from DB\n", __func__, listMintsDB.size());

        std::list<CHDMint> listDeterministicDB = walletdb.ListHDMints(false);
        for (auto& dMint : listDeterministicDB) {
            Add(walletdb, dMint, false, false);
        }
        LogPrint("zero", "%s: added %d hdmint from DB\n", __func__, listDeterministicDB.size());
    }

    std::vector<CMintMeta> vOverWrite;
    std::set<uint256> setMempool = GetMempoolTxids();
    for (auto& it : mapSerialHashes) {
        CMintMeta mint = it.second;

        //This is only intended for unarchived coins
        if (mint.isArchived)
            continue;

        // Update the metadata of the mints if requested
        if (fUpdateStatus){
            if(UpdateMetaStatus(setMempool, mint)) {
                if (mint.isArchived)
                    continue;

                // Mint was updated, queue for overwrite
                vOverWrite.emplace_back(mint);
            }
        }

        if (fUnusedOnly && mint.isUsed)
            continue;

        if (fMatureOnly) {
            // Not confirmed
            if (!mint.nHeight || !(mint.nHeight + (ZC_MINT_CONFIRMATIONS-1) <= chainActive.Height()))
                continue;
        }

        if (!fWrongSeed && !mint.isSeedCorrect)
            continue;

        setMints.push_back(mint);
    }

    //overwrite any updates
    for (CMintMeta& meta : vOverWrite)
        UpdateState(meta);

    return setMints;
}

std::vector<CLelantusMintMeta> CHDMintTracker::ListLelantusMints(bool fUnusedOnly, bool fMatureOnly, bool fUpdateStatus, bool fLoad, bool fWrongSeed)
{
    std::vector<CLelantusMintMeta> setMints;
    if (fLoad) {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        CWalletDB walletdb(strWalletFile);

        std::list<CHDMint> listDeterministicDB = walletdb.ListHDMints(true);
        for (auto& dMint : listDeterministicDB) {
            AddLelantus(walletdb, dMint, false, false);
        }
        LogPrint("zero", "%s: added %d lelantus hdmint from DB\n", __func__, listDeterministicDB.size());
    }

    std::vector<CLelantusMintMeta> vOverWrite;
    std::set<uint256> setMempool = GetMempoolTxids();

    for (auto& it : mapLelantusSerialHashes) {
        CLelantusMintMeta mint = it.second;

        //This is only intended for unarchived coins
        if (mint.isArchived)
            continue;

        // Update the metadata of the mints if requested
        if (fUpdateStatus){
            if(UpdateLelantusMetaStatus(setMempool, mint)) {
                if (mint.isArchived)
                    continue;

                // Mint was updated, queue for overwrite
                vOverWrite.emplace_back(mint);
            }
        }

        if (fUnusedOnly && mint.isUsed)
            continue;

        if (fMatureOnly) {
            // Not confirmed
            if (!mint.nHeight || !(mint.nHeight + (ZC_MINT_CONFIRMATIONS-1) <= chainActive.Height()))
                continue;
        }

        if (!fWrongSeed && !mint.isSeedCorrect)
            continue;

        setMints.push_back(mint);
    }

    //overwrite any updates
    for (CLelantusMintMeta& meta : vOverWrite)
        UpdateState(meta);

    return setMints;
}

/**
 * Get txids of all mempool entries.
 *
 * @return set of mempool txids
 */
std::set<uint256> CHDMintTracker::GetMempoolTxids(){
    std::set<uint256> setMempool;
    setMempool.clear();
    {
        LOCK(mempool.cs);
        txpools.getTransactions(setMempool);
    }
    return setMempool;
}

/**
 * map of serial hashes -> CMintMeta objects
 *
 * @return void
 */
void CHDMintTracker::Clear()
{
    mapSerialHashes.clear();
}
