// Copyright (c) 2019 The Firo Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "hdmint/wallet.h"
#include "validation.h"
#include "txdb.h"
#include "init.h"
#include "hdmint/hdmint.h"
#include "sigma/openssl_context.h"
#include "wallet/walletdb.h"
#include "wallet/wallet.h"
#include "sigma.h"
#include "lelantus.h"
#include "crypto/hmac_sha256.h"
#include "crypto/hmac_sha512.h"
#include "keystore.h"
#include <boost/optional.hpp>
#include "masternode-sync.h"

/**
 * Constructor for CHDMintWallet object.
 *
 * Sets database values: the wallet file, mintpool, masterseed hash and count values.
 * Doesn't set encrypted values if the wallet is locked.
 *
 * @param strWalletFile wallet file string
 * @return CHDMintWallet object
 */
CHDMintWallet::CHDMintWallet(const std::string& strWalletFile, bool resetCount) : tracker(strWalletFile), strWalletFile(strWalletFile)
{
    this->mintPool = CMintPool();

    //Don't try to do anything else if the wallet is locked.
    if (pwalletMain->IsLocked()) {
        return;
    }

    // Use MasterKeyId from HDChain as index for mintpool
    uint160 hashSeedMaster = pwalletMain->GetHDChain().masterKeyID;

    if (!SetupWallet(hashSeedMaster, resetCount)) {
        LogPrintf("%s: failed to save deterministic seed\n", __func__);
        return;
    }
}

/**
 * Constructor helper function.
 *
 * @param hashSeedMaster hash master seed
 * @param fResetCount if true, set DB counts to 0.
 * @return bool
 */
bool CHDMintWallet::SetupWallet(const uint160& hashSeedMaster, bool fResetCount)
{
    CWalletDB walletdb(strWalletFile);
    if (pwalletMain->IsLocked())
        return false;

    if (hashSeedMaster.IsNull()) {
        return error("%s: failed to set master seed.", __func__);
    }

    this->hashSeedMaster = hashSeedMaster;

    nCountNextUse = COUNT_DEFAULT;
    nCountNextGenerate = COUNT_DEFAULT;

    if (fResetCount){
        walletdb.WriteMintCount(nCountNextUse);
        walletdb.WriteMintSeedCount(nCountNextGenerate);
    }else{
        if (!walletdb.ReadMintCount(nCountNextUse))
            nCountNextUse = COUNT_DEFAULT;
        if (!walletdb.ReadMintSeedCount(nCountNextGenerate))
            nCountNextGenerate = COUNT_DEFAULT;
    }

    return true;
}

/**
 * Regenerate a MintPoolEntry value from given values.
 *
 * Doesn't do anything if the wallet is encrypted+locked.
 * Attempts to recreate mint seed (512-bit value used for mint generate) from inputs.
 * Then recreates mint from the seed, and stores walletdb values appropriately.
 *
 * @param mintHashSeedMaster hash master seed for this mint
 * @param seedId seed ID for the key used to generate mint
 * @param nCount count for this mint in the HD chain
 * @RETURN pair of <hashPubcoin,hashSerial> for this mint
 */
std::pair<uint256,uint256> CHDMintWallet::RegenerateMintPoolEntry(CWalletDB& walletdb, const uint160& mintHashSeedMaster, CKeyID& seedId, const int32_t& nCount)
{
    // hashPubcoin, hashSerial
    std::pair<uint256,uint256> nIndexes;

    //Is locked
    if (pwalletMain->IsLocked())
        throw std::runtime_error("Error: Please enter the wallet passphrase with walletpassphrase first.");

    uint512 mintSeed;
    if(!CreateMintSeed(walletdb, mintSeed, nCount, seedId))
        throw std::runtime_error("Unable to create seed for mint regeneration.");

    GroupElement commitmentValue;
    sigma::PrivateCoin coin(sigma::Params::get_default(), sigma::CoinDenomination::SIGMA_DENOM_1);
    if(!SeedToMint(mintSeed, commitmentValue, coin)) //for lelantus put just part of commit, for checking we will need to reduce h1^v from lelantus mint
        throw std::runtime_error("Unable to create sigmamint from seed in mint regeneration.");

    uint256 hashPubcoin = primitives::GetPubCoinValueHash(commitmentValue);
    uint256 hashSerial = primitives::GetSerialHash(coin.getSerialNumber());

    MintPoolEntry mintPoolEntry(mintHashSeedMaster, seedId, nCount);
    mintPool.Add(std::make_pair(hashPubcoin, mintPoolEntry));
    walletdb.WritePubcoin(hashSerial, commitmentValue);
    walletdb.WriteMintPoolPair(hashPubcoin, mintPoolEntry);

    nIndexes.first = hashPubcoin;
    nIndexes.second = hashSerial;

    return nIndexes;

}

/**
 * Generate the mintpool for the current master seed.
 *
 * only runs if the current mintpool is exhausted and we need new mints (ie. the next mint to
 * generate is the same as the one last used)
 * Generates 20 mints at a time.
 * Makes the appropriate database entries.
 *
 * @param nIndex The number of mints to generate. Defaults to 20 if no param passed.
 */
void CHDMintWallet::GenerateMintPool(CWalletDB& walletdb, int32_t nIndex)
{
    //Is locked
    if (pwalletMain->IsLocked())
        return;

    // Only generate new values (ie. if last generated less than or the same, proceed)
    if(nCountNextGenerate > nCountNextUse){
        return;
    }

    LOCK(pwalletMain->cs_wallet);

    int32_t nLastCount = nCountNextGenerate;
    int32_t nStop = nLastCount + 20;
    if(nIndex > 0 && nIndex >= nLastCount)
        nStop = nIndex + 20;
    LogPrintf("%s : nLastCount=%d nStop=%d\n", __func__, nLastCount, nStop - 1);
    for (; nLastCount <= nStop; ++nLastCount) {
        if (ShutdownRequested())
            return;

        CKeyID seedId;
        uint512 mintSeed;
        if(!CreateMintSeed(walletdb, mintSeed, nLastCount, seedId, false))
            continue;

        GroupElement commitmentValue;
        sigma::PrivateCoin coin(sigma::Params::get_default(), sigma::CoinDenomination::SIGMA_DENOM_1);
        if(!SeedToMint(mintSeed, commitmentValue, coin)) //for lelantus put just part of commit, for checking we will need to reduce h1^v from lelantus mint
            continue;

        uint256 hashPubcoin = primitives::GetPubCoinValueHash(commitmentValue);

        MintPoolEntry mintPoolEntry(hashSeedMaster, seedId, nLastCount);
        mintPool.Add(std::make_pair(hashPubcoin, mintPoolEntry));
        walletdb.WritePubcoin(primitives::GetSerialHash(coin.getSerialNumber()), commitmentValue);
        walletdb.WriteMintPoolPair(hashPubcoin, mintPoolEntry);
    }

    // write hdchain back to database
    if (!walletdb.WriteHDChain(pwalletMain->GetHDChain()))
        throw std::runtime_error(std::string(__func__) + ": Writing HD chain model failed");

    // Update local + DB entries for count last generated
    nCountNextGenerate = nLastCount;
    walletdb.WriteMintSeedCount(nCountNextGenerate);

}

/**
 * Load mintpool values from the database into memory.
 *
 */
bool CHDMintWallet::LoadMintPoolFromDB()
{
    CWalletDB walletdb(strWalletFile);
    std::vector<std::pair<uint256, MintPoolEntry>> listMintPool = walletdb.ListMintPool();

    for (auto& mintPoolPair : listMintPool){
        mintPool.Add(mintPoolPair);
    }

    return true;
}

/**
 * Get the mint serial hash for the mint pubcoin hash given.
 *
 * We only have a map of serial hashes to pubcoins (from db), so need to traverse the other way in a loop.
 *
 * @param serialPubcoinPairs a vector of mint hash serials to pubcoin objects.
 * @param hashPubcoin mint pubcoin hash
 * @param hashSerial reference to a mint serial hash. Is set if found
 * @return success
 */
bool CHDMintWallet::GetSerialForPubcoin(const std::vector<std::pair<uint256, GroupElement>>& serialPubcoinPairs, const uint256& hashPubcoin, uint256& hashSerial)
{
    bool fFound = false;
    for(const auto& serialPubcoinPair : serialPubcoinPairs){
        if(hashPubcoin == primitives::GetPubCoinValueHash(serialPubcoinPair.second)){
            hashSerial = serialPubcoinPair.first;
            fFound = true;
            break;
        }
    }

    return fFound;
}

void CHDMintWallet::SetWalletTransactionBlock(CWalletTx &wtx, const CBlockIndex *blockIndex, const CBlock &block) {
    size_t posInBlock = INT_MAX;
    uint256 txHash = wtx.tx->GetHash();
    for (size_t i=0; i<block.vtx.size(); i++)
        if (block.vtx[i]->GetHash() == txHash)
            posInBlock = i;
    assert(posInBlock < INT_MAX);
    wtx.SetMerkleBranch(blockIndex, (int)posInBlock);
}

/**
 * Catch the mint counter up with the chain.
 *
 * Mints are created deterministically so we can completely regenerate all mints and transaction data for them from chain data.
 * Rather than a single pass of listMints, we wrap each pass in an outer while loop, that continues until no updates are found.
 * The reason for this is to allow the mint counter in the wallet to update and regenerate more of the mint pool should it need to.
 *
 * @param fGenerateMintPool whether or not to call GenerateMintPool. defaults to true
 * @param listMints An optional value. If passed, only sync the mints in this list. Else get all mints in the mintpool
 */
void CHDMintWallet::SyncWithChain(bool fGenerateMintPool, boost::optional<std::list<std::pair<uint256, MintPoolEntry>>> listMints)
{
    CWalletDB walletdb(strWalletFile);
    bool foundSigma = true;
    bool foundLela = true;


    std::set<uint256> setAddedTx;
    std::set<uint256> setChecked;
    while (foundSigma || foundLela) {
        foundSigma = false;
        foundLela = false;
        if (fGenerateMintPool)
            GenerateMintPool(walletdb);
        LogPrintf("%s: Mintpool size=%d\n", __func__, mintPool.size());

        if(listMints==boost::none){
            listMints = std::list<std::pair<uint256, MintPoolEntry>>();
            mintPool.List(listMints.get());
        }
        for (std::pair<uint256, MintPoolEntry>& pMint : listMints.get()) {
            if (setChecked.count(pMint.first))
                continue;
            setChecked.insert(pMint.first);

            if (ShutdownRequested())
                return;

            uint160& mintHashSeedMaster = std::get<0>(pMint.second);
            int32_t& mintCount = std::get<2>(pMint.second);

            // halt processing if mint already in tracker
            COutPoint outPoint;
            if (!tracker.HasSigmaPubcoinHash(pMint.first, walletdb) && sigma::GetOutPoint(outPoint, pMint.first)) {
                const uint256& txHash = outPoint.hash;
                //this mint has already occurred on the chain, increment counter's state to reflect this
                LogPrintf("%s : Found wallet coin mint=%s count=%d tx=%s\n", __func__, pMint.first.GetHex(), mintCount, txHash.GetHex());
                foundSigma = true;

                uint256 hashBlock;
                CTransactionRef tx;
                if (!GetTransaction(txHash, tx, Params().GetConsensus(), hashBlock, true)) {
                    LogPrintf("%s : failed to get transaction for mint %s!\n", __func__, pMint.first.GetHex());
                    foundSigma = false;
                    continue;
                }

                //Find the denomination
                boost::optional<sigma::CoinDenomination> denomination = boost::none;
                bool fFoundMint = false;
                GroupElement bnValue;
                for (const CTxOut& out : tx->vout) {
                    if (!out.scriptPubKey.IsSigmaMint())
                        continue;

                    sigma::PublicCoin pubcoin;
                    CValidationState state;
                    if (!TxOutToPublicCoin(out, pubcoin, state)) {
                        LogPrintf("%s : failed to get mint from txout for %s!\n", __func__, pMint.first.GetHex());
                        continue;
                    }

                    // See if this is the mint that we are looking for
                    uint256 hashPubcoin = primitives::GetPubCoinValueHash(pubcoin.getValue());
                    if (pMint.first == hashPubcoin) {
                        denomination = pubcoin.getDenomination();
                        bnValue = pubcoin.getValue();
                        fFoundMint = true;
                        break;
                    }
                }

                if (!fFoundMint || denomination == boost::none) {
                    LogPrintf("%s : failed to get mint %s from tx %s!\n", __func__, pMint.first.GetHex(), tx->GetHash().GetHex());
                    foundSigma = false;
                    break;
                }

                CBlockIndex* pindex = nullptr;
                if (mapBlockIndex.count(hashBlock))
                    pindex = mapBlockIndex.at(hashBlock);

                if (!setAddedTx.count(txHash)) {
                    CBlock block;
                    CWalletTx wtx(pwalletMain, tx);
                    if (pindex && ReadBlockFromDisk(block, pindex, Params().GetConsensus()))
                        SetWalletTransactionBlock(wtx, pindex, block);

                    //Fill out wtx so that a transaction record can be created
                    wtx.nTimeReceived = pindex->GetBlockTime();
                    pwalletMain->AddToWallet(wtx, false);
                    setAddedTx.insert(txHash);
                }

                if(!SetMintSeedSeen(walletdb, pMint, pindex->nHeight, txHash, denomination.get()))
                    continue;

                // Only update if the current hashSeedMaster matches the mints'
                if(hashSeedMaster == mintHashSeedMaster && mintCount >= GetCount()){
                    SetCount(++mintCount);
                    UpdateCountDB(walletdb);
                    LogPrint("zero", "%s: updated count to %d\n", __func__, nCountNextUse);
                }
            }

            if (tracker.HasLelantusPubcoinHash(pMint.first, walletdb))
                continue;

            uint160 seedId = std::get<1>(pMint.second);
            CDataStream ss(SER_GETHASH, 0);
            ss << pMint.first;
            ss << seedId;
            uint256 mintTag = Hash(ss.begin(), ss.end());

            if (!pwalletMain->IsLocked() && lelantus::GetOutPointFromMintTag(outPoint, mintTag)) {
                const uint256& txHash = outPoint.hash;
                //this mint has already occurred on the chain, increment counter's state to reflect this
                LogPrintf("%s : Found wallet coin mint=%s count=%d tx=%s\n", __func__, pMint.first.GetHex(), mintCount, txHash.GetHex());
                foundLela = true;

                uint256 hashBlock;
                CTransactionRef tx;
                if (!GetTransaction(txHash, tx, Params().GetConsensus(), hashBlock, true)) {
                    LogPrintf("%s : failed to get transaction for mint %s!\n", __func__, pMint.first.GetHex());
                    foundLela = false;
                    continue;
                }

                uint64_t amount  = 0;
                bool fFoundMint = false;
                for (const CTxOut& out : tx->vout) {
                    if (!out.scriptPubKey.IsLelantusMint() && !out.scriptPubKey.IsLelantusJMint())
                        continue;
                    secp_primitives::GroupElement pubcoin;
                    try {
                        if (out.scriptPubKey.IsLelantusMint()) {
                            amount = out.nValue;
                            lelantus::ParseLelantusMintScript(out.scriptPubKey, pubcoin);
                        }  else {
                            std::vector<unsigned char> encryptedValue;
                            lelantus::ParseLelantusJMintScript(out.scriptPubKey, pubcoin, encryptedValue);
                            if(!pwalletMain->DecryptMintAmount(encryptedValue, pubcoin, amount))
                                continue;
                        }
                    } catch (std::invalid_argument&) {
                        continue;
                    }
                    if(amount != 0)
                        pubcoin += lelantus::Params::get_default()->get_h1() * Scalar(amount).negate();
                    // See if this is the mint that we are looking for
                    uint256 hashPubcoin = primitives::GetPubCoinValueHash(pubcoin);
                    if (pMint.first == hashPubcoin) {
                        fFoundMint = true;
                        break;
                    }
                }

                if (!fFoundMint) {
                    LogPrintf("%s : failed to get mint %s from tx %s!\n", __func__, pMint.first.GetHex(), tx->GetHash().GetHex());
                    foundLela = false;
                    break;
                }

                CBlockIndex* pindex = nullptr;
                if (mapBlockIndex.count(hashBlock))
                    pindex = mapBlockIndex.at(hashBlock);

                if (!setAddedTx.count(txHash)) {
                    CBlock block;
                    CWalletTx wtx(pwalletMain, tx);
                    if (pindex && ReadBlockFromDisk(block, pindex, Params().GetConsensus()))
                        SetWalletTransactionBlock(wtx, pindex, block);

                    //Fill out wtx so that a transaction record can be created
                    wtx.nTimeReceived = pindex->GetBlockTime();
                    pwalletMain->AddToWallet(wtx, false);
                    setAddedTx.insert(txHash);
                }

                if(!SetLelantusMintSeedSeen(walletdb, pMint, pindex->nHeight, txHash, amount))
                    continue;

                // Only update if the current hashSeedMaster matches the mints'
                if(hashSeedMaster == mintHashSeedMaster && mintCount >= GetCount()){
                    SetCount(++mintCount);
                    UpdateCountDB(walletdb);
                    LogPrint("zero", "%s: updated count to %d\n", __func__, nCountNextUse);
                }
            }
        }
        // Clear listMints to allow it to be repopulated by the mintPool on the next iteration
        if(foundSigma || foundLela)
            listMints = boost::none;
    }
}

/**
 * Add the mint from the chain to the mint tracker.
 *
 * Gets the mint from known values and creates a CHDMint object. Stores it in the tracker.
 * If the wallet is not locked, the mint is regenerated from the known values. If regeneration fails, return false.
 * If the wallet is locked, we use unencrypted db values to regenerate the object.
 *
 * @param mintPoolEntryPair pair of pubcoin hash to MintPoolEntry object
 * @param nHeight mint txid height
 * @param txid mint txid height
 * @param denom mint denomination
 */
bool CHDMintWallet::SetMintSeedSeen(CWalletDB& walletdb, std::pair<uint256,MintPoolEntry> mintPoolEntryPair, int nHeight, const uint256& txid, const sigma::CoinDenomination& denom)
{
    // Regenerate the mint
    uint256 hashPubcoin = mintPoolEntryPair.first;
    CKeyID seedId = std::get<1>(mintPoolEntryPair.second);
    int32_t mintCount = std::get<2>(mintPoolEntryPair.second);

    GroupElement bnValue;
    uint256 hashSerial;
    // Can regenerate if unlocked (cheaper)
    if(!pwalletMain->IsLocked()){
        LogPrintf("%s: Wallet not locked, creating mind seed..\n", __func__);
        uint512 mintSeed;
        CreateMintSeed(walletdb, mintSeed, mintCount, seedId);
        sigma::PrivateCoin coin(sigma::Params::get_default(), denom, false);
        if(!SeedToMint(mintSeed, bnValue, coin))
            return false;
        hashSerial = primitives::GetSerialHash(coin.getSerialNumber());
    }else{
        LogPrintf("%s: Wallet locked, retrieving mind seed..\n", __func__);
        // Get serial and pubcoin data from the db
        std::vector<std::pair<uint256, GroupElement>> serialPubcoinPairs = walletdb.ListSerialPubcoinPairs();
        bool fFound = false;
        for(auto serialPubcoinPair : serialPubcoinPairs){
            GroupElement pubcoin = serialPubcoinPair.second;
            if(hashPubcoin == primitives::GetPubCoinValueHash(pubcoin)){
                LogPrintf("%s: Found pubcoin and serial hash\n", __func__);
                bnValue = pubcoin;
                hashSerial = serialPubcoinPair.first;
                fFound = true;
                break;
            }
        }
        // Not found in DB
        if(!fFound){
            LogPrintf("%s: Pubcoin not found in DB. \n", __func__);
            return false;
        }
    }

    LogPrintf("%s: Creating mint object.. \n", __func__);

    int id;
    std::tie(std::ignore, id) = sigma::CSigmaState::GetState()->GetMintedCoinHeightAndId(sigma::PublicCoin(bnValue, denom));

    // Create mint object
    CHDMint dMint(mintCount, seedId, hashSerial, bnValue);
    int64_t amount;
    DenominationToInteger(denom, amount);
    dMint.SetAmount(amount);
    dMint.SetHeight(nHeight);
    dMint.SetId(id);

    // Check if this is also already spent
    int nHeightTx;
    uint256 txidSpend;
    CTransactionRef txSpend;
    if (IsSerialInBlockchain(hashSerial, nHeightTx, txidSpend, txSpend)) {
        //Find transaction details and make a wallettx and add to wallet
        LogPrintf("%s: Mint object is spent. Setting used..\n", __func__);
        dMint.SetUsed(true);
        CWalletTx wtx(pwalletMain, txSpend);
        CBlockIndex* pindex = chainActive[nHeightTx];
        CBlock block;
        if (ReadBlockFromDisk(block, pindex, Params().GetConsensus()))
            SetWalletTransactionBlock(wtx, pindex, block);

        wtx.nTimeReceived = pindex->nTime;
        pwalletMain->AddToWallet(wtx, false);
    }

    LogPrintf("%s: Adding mint to tracker.. \n", __func__);
    // Add to tracker which also adds to database
    tracker.Add(walletdb, dMint, true);

    return true;
}

bool CHDMintWallet::SetLelantusMintSeedSeen(CWalletDB& walletdb, std::pair<uint256,MintPoolEntry> mintPoolEntryPair, int nHeight, const uint256& txid, uint64_t amount)
{
    // Regenerate the mint
    uint256 hashPubcoin = mintPoolEntryPair.first;
    CKeyID seedId = std::get<1>(mintPoolEntryPair.second);
    int32_t mintCount = std::get<2>(mintPoolEntryPair.second);

    auto params = lelantus::Params::get_default();

    GroupElement bnValue;
    uint256 hashSerial;
    // Can regenerate if unlocked (cheaper)
    Scalar serial;
    if(!pwalletMain->IsLocked()) {
        LogPrintf("%s: Wallet not locked, creating mind seed..\n", __func__);
        uint512 mintSeed;
        CreateMintSeed(walletdb, mintSeed, mintCount, seedId);
        lelantus::PrivateCoin coin(params, amount);
        if(!SeedToLelantusMint(mintSeed, coin))
            return false;
        hashSerial = primitives::GetSerialHash(coin.getSerialNumber());
        bnValue = coin.getPublicCoin().getValue();
        serial = coin.getSerialNumber();
    } else {
        LogPrintf("%s: Wallet locked, retrieving mind seed..\n", __func__);
        // Get serial and pubcoin data from the db
        std::vector<std::pair<uint256, GroupElement>> serialPubcoinPairs = walletdb.ListSerialPubcoinPairs();
        bool fFound = false;
        for(auto serialPubcoinPair : serialPubcoinPairs){
            GroupElement pubcoin = serialPubcoinPair.second;
            uint256 reducedHash;
            walletdb.ReadPubcoinHashes(primitives::GetPubCoinValueHash(pubcoin), reducedHash);
            if(hashPubcoin == reducedHash){
                LogPrintf("%s: Found pubcoin and serial hash\n", __func__);
                bnValue = pubcoin;
                hashSerial = serialPubcoinPair.first;
                fFound = true;
                break;
            }
        }
        // Not found in DB
        if(!fFound){
            LogPrintf("%s: Pubcoin not found in DB. \n", __func__);
            return false;
        }
    }

    LogPrintf("%s: Creating mint object.. \n", __func__);
    int height, id;
    std::tie(height, id) = lelantus::CLelantusState::GetState()->GetMintedCoinHeightAndId(bnValue);

    // Create mint object
    CHDMint dMint(mintCount, seedId, hashSerial, bnValue);
    dMint.SetAmount(amount);
    dMint.SetHeight(nHeight);
    dMint.SetId(id);

    // Check if this is also already spent
    int nHeightTx;
    uint256 txidSpend;
    CTransactionRef txSpend;
    bool used = false;
    if (IsLelantusSerialInBlockchain(hashSerial, nHeightTx, txidSpend, txSpend)) {
        //Find transaction details and make a wallettx and add to wallet
        LogPrintf("%s: Mint object is spent. Setting used..\n", __func__);
        dMint.SetUsed(true);
        CWalletTx wtx(pwalletMain, txSpend);
        CBlockIndex* pindex = chainActive[nHeightTx];
        CBlock block;
        if (ReadBlockFromDisk(block, pindex, Params().GetConsensus()))
            SetWalletTransactionBlock(wtx, pindex, block);

        wtx.nTimeReceived = pindex->nTime;
        pwalletMain->AddToWallet(wtx, false);
        used = true;
    } else {
        lelantus::CLelantusState *lelantusState = lelantus::CLelantusState::GetState();
        // this is for some edge cases, when mint is used but the serial is not at map
        Scalar s;
        if (lelantusState->IsUsedCoinSerialHash(s, hashSerial)) {
            dMint.SetUsed(true);
            serial = s;
            used = true;
        }
    }

    // Adding spend entry into db,
    if(used && (serial != uint64_t(0))) {
        CLelantusSpendEntry spend;
        spend.coinSerial = serial;
        spend.pubCoin = bnValue;
        spend.id = id;
        spend.amount = amount;

        if (!walletdb.WriteLelantusSpendSerialEntry(spend)) {
            throw std::runtime_error(_("Failed to write coin serial number into wallet"));
        }
    }

    LogPrintf("%s: Adding mint to tracker.. \n", __func__);
    // Add to tracker which also adds to database
    tracker.AddLelantus(walletdb, dMint, true);

    return true;
}

/**
 * Convert a 512-bit mint seed into a mint.
 *
 * See https://github.com/firoorg/firo/pull/392 for specification on mint generation.
 *
 * @param mintSeed uint512 object of seed for mint
 * @param commit reference to public coin. Is set in this function
 * @param coin reference to private coin. Is set in this function
 * @return success
 */
bool CHDMintWallet::SeedToMint(const uint512& mintSeed, GroupElement& commit, sigma::PrivateCoin& coin)
{
    //convert state seed into a seed for the private key
    uint256 nSeedPrivKey = mintSeed.trim256();
    nSeedPrivKey = Hash(nSeedPrivKey.begin(), nSeedPrivKey.end());
    coin.setEcdsaSeckey(nSeedPrivKey);

    // Create a key pair
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(OpenSSLContext::get_context(), &pubkey, coin.getEcdsaSeckey())){
        return false;
    }
    // Hash the public key in the group to obtain a serial number
    Scalar serialNumber = coin.serialNumberFromSerializedPublicKey(OpenSSLContext::get_context(), &pubkey);
    coin.setSerialNumber(serialNumber);

    //hash randomness seed with Bottom 256 bits of mintSeed
    Scalar randomness;
    uint256 nSeedRandomness = ArithToUint512(UintToArith512(mintSeed) >> 256).trim256();
    randomness.memberFromSeed(nSeedRandomness.begin());
    coin.setRandomness(randomness);

    // Generate a Pedersen commitment to the serial number
    commit = sigma::SigmaPrimitives<Scalar, GroupElement>::commit(
             coin.getParams()->get_g(), coin.getSerialNumber(), coin.getParams()->get_h0(), coin.getRandomness());

    return true;
}

/**
 * Convert a 512-bit mint seed into a mint.
 *
 * See https://github.com/firoorg/firo/pull/392 for specification on mint generation.
 *
 * @param mintSeed uint512 object of seed for mint
 * @param coin reference to private coin. Is set in this function
 * @return success
 */
bool CHDMintWallet::SeedToLelantusMint(const uint512& mintSeed, lelantus::PrivateCoin& coin)
{
    //convert state seed into a seed for the private key
    uint256 nSeedPrivKey = mintSeed.trim256();
    nSeedPrivKey = Hash(nSeedPrivKey.begin(), nSeedPrivKey.end());

    // Create a key pair
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(OpenSSLContext::get_context(), &pubkey, nSeedPrivKey.begin())) {
        return false;
    }

    // Hash the public key in the group to obtain a serial number
    Scalar serialNumber = coin.serialNumberFromSerializedPublicKey(OpenSSLContext::get_context(), &pubkey);

    // hash randomness seed with Bottom 256 bits of mintSeed
    Scalar randomness;
    uint256 nSeedRandomness = ArithToUint512(UintToArith512(mintSeed) >> 256).trim256();
    randomness.memberFromSeed(nSeedRandomness.begin());

    std::vector<unsigned char> seckey(nSeedPrivKey.begin(), nSeedPrivKey.end());
    //generating coin
    coin = lelantus::PrivateCoin(
        coin.getParams(),
        serialNumber,
        coin.getV(),
        randomness,
        seckey,
        LELANTUS_TX_VERSION_4);

    return true;
}

/**
 * Get seed ID for the key used in mint generation.
 *
 * See https://github.com/firoorg/firo/pull/392 for specification on mint generation.
 * Looks to the mintpool first - if mint doesn't exist, generates new mints in the mintpool.
 *
 * @param nCount count in the HD Chain of the mint to use.
 * @return the seed ID
 */
CKeyID CHDMintWallet::GetMintSeedID(CWalletDB& walletdb, int32_t nCount){
    // Get CKeyID for n from mintpool
    uint256 hashPubcoin;
    std::pair<uint256,MintPoolEntry> mintPoolEntryPair;

    if(!mintPool.Get(nCount, hashSeedMaster, mintPoolEntryPair)){
        // Add up to mintPool index + 20
        GenerateMintPool(walletdb, nCount);
        if(!mintPool.Get(nCount, hashSeedMaster, mintPoolEntryPair)){
            ResetCount(walletdb);
            throw std::runtime_error("Unable to retrieve mint seed ID");
        }
    }

    return std::get<1>(mintPoolEntryPair.second);
}

/**
 * Create the mint seed for the count passed.
 *
 * See https://github.com/firoorg/firo/pull/392 for specification on mint generation.
 * We check if the key for the count passed exists. if so retrieve it's seed ID. if not, generate a new key.
 * If seedId is passed, use that seedId and ignore key generation section.
 * Following that, get the key, and use it to generate the mint seed according to the specification.
 *
 * @param mintSeed
 * @param nCount (optional) count in the HD Chain of the key to use for mint generation.
 * @param seedId (optional) seedId of the key to use for mint generation.
 * @return sucess
 */
bool CHDMintWallet::CreateMintSeed(CWalletDB& walletdb, uint512& mintSeed, const int32_t& nCount, CKeyID& seedId, bool fWriteChain)
{
    LOCK(pwalletMain->cs_wallet);
    CKey key;

    if(seedId.IsNull()){
        CPubKey pubKey;
        int32_t chainIndex = pwalletMain->GetHDChain().nExternalChainCounters[BIP44_MINT_INDEX];
        if(nCount==chainIndex){
            // If chainIndex is the same as n (ie. we are generating next available key), generate a new key.
            pubKey = pwalletMain->GenerateNewKey(BIP44_MINT_INDEX, fWriteChain);
        }
        else if(nCount<chainIndex){
            // if it's less than the current chain index, we are regenerating the mintpool. get the key at n
            CKey secret;
            pubKey = pwalletMain->GetKeyFromKeypath(BIP44_MINT_INDEX, nCount, secret);
        }
        else{
            throw std::runtime_error("Unable to retrieve mint seed ID (internal index greater than HDChain index). \n"
                                    "We recommend restarting with -zapwalletmints.");
        }
        seedId = pubKey.GetID();
    }

    if (!pwalletMain->CCryptoKeyStore::GetKey(seedId, key)){
        ResetCount(walletdb);
        throw std::runtime_error("Unable to retrieve generated key for mint seed. Is the wallet locked?");
    }

    // HMAC-SHA512(SHA256(count),key)
    unsigned char countHash[CSHA256().OUTPUT_SIZE];
    std::vector<unsigned char> result(CSHA512().OUTPUT_SIZE);

    std::string nCountStr = std::to_string(nCount);
    CSHA256().Write(reinterpret_cast<const unsigned char*>(nCountStr.c_str()), nCountStr.size()).Finalize(countHash);

    CHMAC_SHA512(countHash, CSHA256().OUTPUT_SIZE).Write(key.begin(), key.size()).Finalize(&result[0]);

    mintSeed = uint512(result);

    return true;
}

/**
 * Get in-memory count of the next mint to use.
 *
 * @return the count
 */
int32_t CHDMintWallet::GetCount()
{
    return nCountNextUse;
}

/**
 * Reset in-memory count to that of the database value.
 * Necessary during transaction creation when fee calcuation causes the creation to reset.
 *
 * @return void
 */
void CHDMintWallet::ResetCount(CWalletDB& walletdb)
{
    walletdb.ReadMintCount(nCountNextUse);
}

/**
 * Set in-memory count to parameter passed
 *
 * @param nCount count to be set
 * @return void
 */
void CHDMintWallet::SetCount(int32_t nCount)
{
    nCountNextUse = nCount;
}

/**
 * Increment in-memory count of the next mint to use.
 *
 * @return void
 */
void CHDMintWallet::UpdateCountLocal()
{
    nCountNextUse++;
    LogPrintf("CHDMintWallet : Updating count local to %s\n",nCountNextUse);
}

/**
 * Increment database count of the next mint to use.
 * calls GenerateMintPool, which will run if we have exhausted the mintpool.
 *
 * @return void
 */
void CHDMintWallet::UpdateCountDB(CWalletDB& walletdb)
{
    LogPrintf("CHDMintWallet : Updating count in DB to %s\n",nCountNextUse);
    walletdb.WriteMintCount(nCountNextUse);
    GenerateMintPool(walletdb);
}

/**
 * Gets a CHDMint object from a mintpool entry.
 *
 * @param denom denomination of mint
 * @param coin reference to private coin object
 * @param dMint reference to CHDMint object
 * @param mintPoolEntry mintpool data
 * @return success
 */
bool CHDMintWallet::GetHDMintFromMintPoolEntry(CWalletDB& walletdb, const sigma::CoinDenomination denom, sigma::PrivateCoin& coin, CHDMint& dMint, MintPoolEntry& mintPoolEntry){
    uint512 mintSeed;
    CreateMintSeed(walletdb, mintSeed, std::get<2>(mintPoolEntry), std::get<1>(mintPoolEntry));

    GroupElement commitmentValue;
    if(!SeedToMint(mintSeed, commitmentValue, coin)){
        return false;
    }

    coin.setPublicCoin(sigma::PublicCoin(commitmentValue, denom));

    uint256 hashSerial = primitives::GetSerialHash(coin.getSerialNumber());
    dMint = CHDMint(std::get<2>(mintPoolEntry), std::get<1>(mintPoolEntry), hashSerial, coin.getPublicCoin().getValue());
    return true;
}

/**
 * Gets a CHDMint object from a mintpool entry.
 *
 * @param coin reference to private coin object,should keep the value of coin
 * @param dMint reference to CHDMint object
 * @param mintPoolEntry mintpool data
 * @return success
 */
bool CHDMintWallet::GetLelantusHDMintFromMintPoolEntry(CWalletDB& walletdb, lelantus::PrivateCoin& coin, CHDMint& dMint, MintPoolEntry& mintPoolEntry){
    uint512 mintSeed;
    CreateMintSeed(walletdb, mintSeed, std::get<2>(mintPoolEntry), std::get<1>(mintPoolEntry));

    if(!SeedToLelantusMint(mintSeed, coin)){
        return false;
    }

    uint256 hashSerial = primitives::GetSerialHash(coin.getSerialNumber());
    dMint = CHDMint(std::get<2>(mintPoolEntry), std::get<1>(mintPoolEntry), hashSerial, coin.getPublicCoin().getValue());
    return true;
}

/**
 * Generate a CHDMint object, taking care of surrounding conditions.
 *
 * If the chain is not synced, do not proceed, unless fAllowUnsynced is set.
 * If passed the mintpool entry, we directly call GetHDMintFromMintPoolEntry and return.
 * If not, we assume that this is a new mint being created.
 * Following creation, verify the mint does not already exist, in-memory or on-chain. This is to prevent sync issues with the
 * mint counter between copies of the same wallet. If it does, increment the count and repeat creation. Continue until an available
 * mint is found.
 *
 * @param denom denomination of mint
 * @param coin reference to private coin object
 * @param dMint reference to CHDMint object
 * @param mintPoolEntry mintpool data
 * @param fAllowUnsynced allow mint creation if chain is not synced (for tests)
 * @return success
 */
bool CHDMintWallet::GenerateMint(CWalletDB& walletdb, const sigma::CoinDenomination denom, sigma::PrivateCoin& coin, CHDMint& dMint, boost::optional<MintPoolEntry> mintPoolEntry, bool fAllowUnsynced)
{
    if (!masternodeSync.IsBlockchainSynced() && !fAllowUnsynced && !(Params().NetworkIDString() == CBaseChainParams::REGTEST))
        throw std::runtime_error("Unable to generate mint: Blockchain not yet synced.");

    if(mintPoolEntry!=boost::none)
        return GetHDMintFromMintPoolEntry(walletdb, denom, coin, dMint, mintPoolEntry.get());

    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    while(true){
        if(hashSeedMaster.IsNull())
            throw std::runtime_error("Unable to generate mint: HashSeedMaster not set");
        CKeyID seedId = GetMintSeedID(walletdb, nCountNextUse);
        mintPoolEntry = MintPoolEntry(hashSeedMaster, seedId, nCountNextUse);
        // Empty mintPoolEntry implies this is a new mint being created, so update nCountNextUse
        UpdateCountLocal();

        if(!GetHDMintFromMintPoolEntry(walletdb, denom, coin, dMint, mintPoolEntry.get()))
            return false;

        // New HDMint exists, try new count
        if(walletdb.HasHDMint(dMint.GetPubcoinValue()) ||
           sigmaState->HasCoin(coin.getPublicCoin())) {
            LogPrintf("%s: Coin detected used, trying next. count: %d\n", __func__, std::get<2>(mintPoolEntry.get()));
        }else{
            LogPrintf("%s: Found unused coin, count: %d\n", __func__, std::get<2>(mintPoolEntry.get()));
            break;
        }
    }

    int64_t amount;
    DenominationToInteger(denom, amount);
    dMint.SetAmount(amount);

    return true;
}

/**
 * Generate a CHDMint object, taking care of surrounding conditions.
 *
 * If the chain is not synced, do not proceed, unless fAllowUnsynced is set.
 * If passed the mintpool entry, we directly call GetHDMintFromMintPoolEntry and return.
 * If not, we assume that this is a new mint being created.
 * Following creation, verify the mint does not already exist, in-memory or on-chain. This is to prevent sync issues with the
 * mint counter between copies of the same wallet. If it does, increment the count and repeat creation. Continue until an available
 * mint is found.
 *
 * @param coin reference to private coin object, should keep the value of coin
 * @param dMint reference to CHDMint object
 * @param mintPoolEntry mintpool data
 * @param fAllowUnsynced allow mint creation if chain is not synced (for tests)
 * @return success
 */
bool CHDMintWallet::GenerateLelantusMint(CWalletDB& walletdb, lelantus::PrivateCoin& coin, CHDMint& dMint, uint160& seedIdOut, boost::optional<MintPoolEntry> mintPoolEntry, bool fAllowUnsynced)
{
    if(!masternodeSync.IsBlockchainSynced() && !fAllowUnsynced && !(Params().NetworkIDString() == CBaseChainParams::REGTEST))
        throw std::runtime_error("Unable to generate mint: Blockchain not yet synced.");

    if(mintPoolEntry!=boost::none)
        return GetLelantusHDMintFromMintPoolEntry(walletdb, coin, dMint, mintPoolEntry.get());

    lelantus::CLelantusState *lelantusState = lelantus::CLelantusState::GetState();
    while(true) {
        if(hashSeedMaster.IsNull())
            throw std::runtime_error("Unable to generate mint: HashSeedMaster not set");
        CKeyID seedId = GetMintSeedID(walletdb, nCountNextUse);
        seedIdOut = seedId;
        mintPoolEntry = MintPoolEntry(hashSeedMaster, seedId, nCountNextUse);
        // Empty mintPoolEntry implies this is a new mint being created, so update nCountNextUse
        UpdateCountLocal();

        if(!GetLelantusHDMintFromMintPoolEntry(walletdb, coin, dMint, mintPoolEntry.get()))
            return false;

        // New HDMint exists, try new count
        if(walletdb.HasHDMint(dMint.GetPubcoinValue())
        || lelantusState->HasCoin(coin.getPublicCoin())) {
            LogPrintf("%s: Coin detected used, trying next. count: %d\n", __func__, std::get<2>(mintPoolEntry.get()));
        }else{
            LogPrintf("%s: Found unused coin, count: %d\n", __func__, std::get<2>(mintPoolEntry.get()));
            break;
        }
    }

    dMint.SetAmount(coin.getV());
    return true;
}


/**
 * Regenerate a CSigmaEntry (ie. mint object with private data)
 *
 * Internally calls GenerateMint with known MintPoolEntry and constructs the CSigmaEntry
 *
 * @param dMint HDMint object
 * @param sigma reference to full mint object
 * @return success
 */
bool CHDMintWallet::RegenerateMint(CWalletDB& walletdb, const CHDMint& dMint, CSigmaEntry& sigma, bool forEstimation)
{
    sigma::CoinDenomination denom;
    IntegerToDenomination(dMint.GetAmount(), denom);

    //Generate the coin
    sigma::PrivateCoin coin(sigma::Params::get_default(), denom, false);
    CHDMint dMintDummy;
    CKeyID seedId = dMint.GetSeedId();
    int32_t nCount = dMint.GetCount();
    MintPoolEntry mintPoolEntry(hashSeedMaster, seedId, nCount);
    if(!forEstimation)
        GenerateMint(walletdb, denom, coin, dMintDummy, mintPoolEntry, true);

    //Fill in the sigmamint object's details
    GroupElement bnValue = coin.getPublicCoin().getValue();
    if (primitives::GetPubCoinValueHash(bnValue) != dMint.GetPubCoinHash() && !forEstimation)
        return error("%s: failed to correctly generate mint, pubcoin hash mismatch", __func__);
    if(forEstimation)
        sigma.value = dMint.GetPubcoinValue();
    else
        sigma.value = bnValue;

    Scalar bnSerial = coin.getSerialNumber();
    if (primitives::GetSerialHash(bnSerial) != dMint.GetSerialHash() && !forEstimation)
        return error("%s: failed to correctly generate mint, serial hash mismatch", __func__);

    sigma.set_denomination(denom);
    sigma.randomness = coin.getRandomness();
    sigma.serialNumber = bnSerial;
    sigma.IsUsed = dMint.IsUsed();
    sigma.nHeight = dMint.GetHeight();
    sigma.id = dMint.GetId();
    sigma.ecdsaSecretKey = std::vector<unsigned char>(&coin.getEcdsaSeckey()[0],&coin.getEcdsaSeckey()[32]);

    return true;
}

bool CHDMintWallet::RegenerateMint(CWalletDB& walletdb, const CHDMint& dMint, CLelantusEntry& lelantusEntry, bool forEstimation)
{
    //Generate the coin
    lelantus::PrivateCoin coin(lelantus::Params::get_default(), dMint.GetAmount());
    CHDMint dMintDummy;
    CKeyID seedId = dMint.GetSeedId();
    int32_t nCount = dMint.GetCount();
    MintPoolEntry mintPoolEntry(hashSeedMaster, seedId, nCount);
    uint160 dummySeedId;
    if(!forEstimation)
        GenerateLelantusMint(walletdb, coin, dMintDummy, dummySeedId, mintPoolEntry, true);

    //Fill in the lelantus object's details
    GroupElement bnValue = coin.getPublicCoin().getValue();
    if (primitives::GetPubCoinValueHash(bnValue) != dMint.GetPubCoinHash() && !forEstimation)
        return error("%s: failed to correctly generate lelantus mint, pubcoin hash mismatch", __func__);
    if(forEstimation)
        lelantusEntry.value = dMint.GetPubcoinValue();
    else
        lelantusEntry.value = bnValue;

    Scalar bnSerial = coin.getSerialNumber();
    if (primitives::GetSerialHash(bnSerial) != dMint.GetSerialHash() && !forEstimation)
        return error("%s: failed to correctly generate lelantus mint, serial hash mismatch", __func__);

    lelantusEntry.amount = dMint.GetAmount();
    lelantusEntry.randomness = coin.getRandomness();
    lelantusEntry.serialNumber = bnSerial;
    lelantusEntry.IsUsed = dMint.IsUsed();
    lelantusEntry.nHeight = dMint.GetHeight();
    lelantusEntry.id = dMint.GetId();
    lelantusEntry.ecdsaSecretKey = std::vector<unsigned char>(&coin.getEcdsaSeckey()[0],&coin.getEcdsaSeckey()[32]);

    return true;
}

/**
 * Checks to see if serial passed is on-chain (ie. a check on whether the mint for the serial is spent)
 *
 * @param hashSerial mint serial hash
 * @param nHeightTx transaction height on-chain
 * @param txidSpend transaction hash
 * @param tx full transaction object
 * @return success
 */
bool CHDMintWallet::IsSerialInBlockchain(const uint256& hashSerial, int& nHeightTx, uint256& txidSpend, CTransactionRef & tx)
{
    txidSpend.SetNull();
    CMintMeta mMeta;
    Scalar bnSerial;
    if (!sigma::CSigmaState::GetState()->IsUsedCoinSerialHash(bnSerial, hashSerial))
        return false;

    if(!tracker.GetMetaFromSerial(hashSerial, mMeta))
        return false;

    txidSpend = mMeta.txid;

    return IsTransactionInChain(txidSpend, nHeightTx, tx);
}

bool CHDMintWallet::IsLelantusSerialInBlockchain(const uint256& hashSerial, int& nHeightTx, uint256& txidSpend, CTransactionRef & tx)
{
    txidSpend.SetNull();
    CLelantusMintMeta mMeta;
    Scalar bnSerial;

    if (!lelantus::CLelantusState::GetState()->IsUsedCoinSerialHash(bnSerial, hashSerial))
        return false;

    if(!tracker.GetMetaFromSerial(hashSerial, mMeta))
        return false;

    txidSpend = mMeta.txid;

    return IsTransactionInChain(txidSpend, nHeightTx, tx);
}

/**
 * Constructs a PublicCoin object from a mint-containing transaction output
 *
 * @param txout mint-containing transaction output
 * @param pubCoin mint public coin
 * @param state validation state object
 * @return success
 */
bool CHDMintWallet::TxOutToPublicCoin(const CTxOut& txout, sigma::PublicCoin& pubCoin, CValidationState& state)
{
    // If you wonder why +1, go to file wallet.cpp and read the comments in function
    // CWallet::CreateSigmaMintModel around "scriptSerializedCoin << OP_SIGMAMINT";
    std::vector<unsigned char> coin_serialised(txout.scriptPubKey.begin() + 1,
                                          txout.scriptPubKey.end());
    secp_primitives::GroupElement publicSigma;
    publicSigma.deserialize(&coin_serialised[0]);

    sigma::CoinDenomination denomination;
    if(!IntegerToDenomination(txout.nValue, denomination))
        return state.DoS(100, error("TxOutToPublicCoin : txout.nValue is not correct"));

    LogPrint("zero", "%s ZCPRINT denomination %d pubcoin %s\n", __func__, denomination, publicSigma.GetHex());

    sigma::PublicCoin checkPubCoin(publicSigma, denomination);
    pubCoin = checkPubCoin;

    return true;
}
