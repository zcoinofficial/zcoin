// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet.h"
#include "walletexcept.h"
#include "sigmaspendbuilder.h"
#include "lelantusjoinsplitbuilder.h"
#include "amount.h"
#include "base58.h"
#include "checkpoints.h"
#include "chain.h"
#include "wallet/coincontrol.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "key.h"
#include "keystore.h"
#include "validation.h"
#include "sigma.h"
#include "../sigma/coinspend.h"
#include "../sigma/spend_metadata.h"
#include "../sigma/coin.h"
#include "lelantus.h"
#include "net.h"
#include "policy/policy.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/sign.h"
#include "timedata.h"
#include "txmempool.h"
#include "util.h"
#include "ui_interface.h"
#include "utilmoneystr.h"
#include "validation.h"
#include "masternode-sync.h"
#include "random.h"
#include "init.h"
#include "hdmint/wallet.h"
#include "rpc/protocol.h"

#include "crypto/hmac_sha512.h"
#include "crypto/aes.h"

#include "hdmint/tracker.h"

#include "evo/deterministicmns.h"

#include <assert.h>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem.hpp>
#include <boost/thread.hpp>
#include <vector>

#include "bip47/account.h"
#include "bip47/paymentcode.h"
#include "bip47/bip47utils.h"

CWallet* pwalletMain = NULL;

/** Transaction fee set by the user */
CFeeRate payTxFee(DEFAULT_TRANSACTION_FEE);
unsigned int nTxConfirmTarget = DEFAULT_TX_CONFIRM_TARGET;
bool bSpendZeroConfChange = DEFAULT_SPEND_ZEROCONF_CHANGE;
bool fSendFreeTransactions = DEFAULT_SEND_FREE_TRANSACTIONS;
bool fWalletRbf = DEFAULT_WALLET_RBF;

const char * DEFAULT_WALLET_DAT = "wallet.dat";

/**
 * Fees smaller than this (in satoshi) are considered zero fee (for transaction creation)
 * Override with -mintxfee
 */
CFeeRate CWallet::minTxFee = CFeeRate(DEFAULT_TRANSACTION_MINFEE);
/**
 * If fee estimation does not have enough data to provide estimates, use this fee instead.
 * Has no effect if not using fee estimation
 * Override with -fallbackfee
 */
CFeeRate CWallet::fallbackFee = CFeeRate(DEFAULT_FALLBACK_FEE);

const uint256 CMerkleTx::ABANDON_HASH(uint256S("0000000000000000000000000000000000000000000000000000000000000001"));

/** @defgroup mapWallet
 *
 * @{
 */

struct CompareValueOnly
{
    bool operator()(const std::pair<CAmount, std::pair<const CWalletTx*, unsigned int> >& t1,
                    const std::pair<CAmount, std::pair<const CWalletTx*, unsigned int> >& t2) const
    {
        return t1.first < t2.first;
    }
};

struct CompareByAmount
{
    bool operator()(const CompactTallyItem& t1, const CompactTallyItem& t2) const
    {
        return t1.nAmount > t2.nAmount;
    }
};

static void EnsureMintWalletAvailable()
{
    if (!pwalletMain || !pwalletMain->zwallet) {
        throw std::logic_error("Sigma feature requires HD wallet");
    }
}

std::string COutput::ToString() const {
    return strprintf("COutput(%s, %d, %d) [%s]", tx->GetHash().ToString(), i, nDepth, FormatMoney(tx->tx->vout[i].nValue));
}

const CWalletTx *CWallet::GetWalletTx(const uint256 &hash) const {
    LOCK(cs_wallet);
    std::map<uint256, CWalletTx>::const_iterator it = mapWallet.find(hash);
    if (it == mapWallet.end())
        return NULL;
    return &(it->second);
}

CPubKey CWallet::GetKeyFromKeypath(uint32_t nChange, uint32_t nChild, CKey& secret) {
    AssertLockHeld(cs_wallet); // mapKeyMetadata

    boost::optional<bool> regTest = GetOptBoolArg("-regtest")
    , testNet = GetOptBoolArg("-testnet");
    uint32_t nIndex = (regTest || testNet) ? BIP44_TEST_INDEX : BIP44_FIRO_INDEX;

    // Fail if not using HD wallet (no keypaths)
    if (hdChain.masterKeyID.IsNull())
        throw std::runtime_error(std::string(__func__) + ": Non-HD wallet detected");

    // use BIP44 keypath: m / purpose' / coin_type' / account' / change / address_index
    CKey key;                      //master key seed (256bit)
    CExtKey masterKey;             //hd master key
    CExtKey purposeKey;            //key at m/44'
    CExtKey coinTypeKey;           //key at m/44'/<1/136>' (Testnet or Firo Coin Type respectively, according to SLIP-0044)
    CExtKey accountKey;            //key at m/44'/<1/136>'/0'
    CExtKey externalChainChildKey; //key at m/44'/<1/136>'/0'/<c> (Standard: 0/1, Mints: 2)
    CExtKey childKey;              //key at m/44'/<1/136>'/0'/<c>/<n>

    if(hdChain.nVersion >= CHDChain::VERSION_WITH_BIP39){
        MnemonicContainer mContainer = mnemonicContainer;
        DecryptMnemonicContainer(mContainer);
        SecureVector seed = mContainer.GetSeed();
        masterKey.SetMaster(&seed[0], seed.size());
    } else {
        // try to get the master key
        if (!GetKey(hdChain.masterKeyID, key))
            throw std::runtime_error(std::string(__func__) + ": Master key not found");
        masterKey.SetMaster(key.begin(), key.size());
    }

    // derive m/44'
    // use hardened derivation (child keys >= 0x80000000 are hardened after bip32)
    masterKey.Derive(purposeKey, BIP44_INDEX | BIP32_HARDENED_KEY_LIMIT);

    // derive m/44'/136'
    purposeKey.Derive(coinTypeKey, nIndex | BIP32_HARDENED_KEY_LIMIT);

    // derive m/44'/136'/0'
    coinTypeKey.Derive(accountKey, BIP32_HARDENED_KEY_LIMIT);

    // derive m/44'/136'/0'/<c>
    accountKey.Derive(externalChainChildKey, nChange);

    // derive m/44'/136'/0'/<c>/<n>
    externalChainChildKey.Derive(childKey, nChild);

    secret = childKey.key;

    CPubKey pubkey = secret.GetPubKey();
    assert(secret.VerifyPubKey(pubkey));

    return pubkey;
}

CPubKey CWallet::GenerateNewKey(uint32_t nChange, bool fWriteChain)
{
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    bool fCompressed = CanSupportFeature(FEATURE_COMPRPUBKEY); // default to compressed public keys if we want 0.6.0 wallets

    CKey secret;

    // Create new metadata
    int64_t nCreationTime = GetTime();
    CKeyMetadata metadata(nCreationTime);
    metadata.nChange = Component(nChange, false);

    boost::optional<bool> regTest = GetOptBoolArg("-regtest")
    , testNet = GetOptBoolArg("-testnet");

    uint32_t nIndex = (regTest || testNet) ? BIP44_TEST_INDEX : BIP44_FIRO_INDEX;

    // use HD key derivation if HD was enabled during wallet creation
    // TODO: change code to foloow bitcoin structure more closely
    if (IsHDEnabled()) {
        // use BIP44 keypath: m / purpose' / coin_type' / account' / change / address_index
        CKey key;                      //master key seed (256bit)
        CExtKey masterKey;             //hd master key
        CExtKey purposeKey;            //key at m/44'
        CExtKey coinTypeKey;           //key at m/44'/<1/136>' (Testnet or Firo Coin Type respectively, according to SLIP-0044)
        CExtKey accountKey;            //key at m/44'/<1/136>'/0'
        CExtKey externalChainChildKey; //key at m/44'/<1/136>'/0'/<c> (Standard: 0/1, Mints: 2)
        CExtKey childKey;              //key at m/44'/<1/136>'/0'/<c>/<n>
        //For bip39 we use it's original way for generating keys to make it compatible with hardware and software wallets
        if(hdChain.nVersion >= CHDChain::VERSION_WITH_BIP39){
            MnemonicContainer mContainer = mnemonicContainer;
            DecryptMnemonicContainer(mContainer);
            SecureVector seed = mContainer.GetSeed();
            masterKey.SetMaster(seed.empty() ? nullptr: &seed[0], seed.size());
        } else {
            // try to get the master key
            if (!GetKey(hdChain.masterKeyID, key) || !key.size())
                throw std::runtime_error(std::string(__func__) + ": Master key not found");
            masterKey.SetMaster(key.begin(), key.size());
        }

        // derive m/44'
        // use hardened derivation (child keys >= 0x80000000 are hardened after bip32)
        masterKey.Derive(purposeKey, BIP44_INDEX | BIP32_HARDENED_KEY_LIMIT);

        // derive m/44'/136'
        purposeKey.Derive(coinTypeKey, nIndex | BIP32_HARDENED_KEY_LIMIT);

        // derive m/44'/136'/0'
        coinTypeKey.Derive(accountKey, BIP32_HARDENED_KEY_LIMIT);

        // derive m/44'/136'/0'/<c>
        accountKey.Derive(externalChainChildKey, nChange);

        // derive child key at next index, skip keys already known to the wallet
        do
        {
            if (hdChain.nExternalChainCounters.size() <= nChange) {
                hdChain.nExternalChainCounters.resize(nChange+1, 0);
            }
            externalChainChildKey.Derive(childKey, hdChain.nExternalChainCounters[nChange]);
            metadata.hdKeypath = "m/44'/" + std::to_string(nIndex) + "'/0'/" + std::to_string(nChange) + "/" + std::to_string(hdChain.nExternalChainCounters[nChange]);
            metadata.hdMasterKeyID = hdChain.masterKeyID;
            metadata.nChild = Component(hdChain.nExternalChainCounters[nChange], false);
            // increment childkey index
            hdChain.nExternalChainCounters[nChange]++;
        } while (HaveKey(childKey.key.GetPubKey().GetID()));
        secret = childKey.key;

        // update the chain model in the database
        if(fWriteChain){
            if (!CWalletDB(strWalletFile).WriteHDChain(hdChain))
                throw std::runtime_error(std::string(__func__) + ": Writing HD chain model failed");
        }
    /* bitcoin 0.14:
    if (IsHDEnabled()) {
        DeriveNewChildKey(metadata, secret);
    */
    } else {
        secret.MakeNewKey(fCompressed);
    }

    // Compressed public keys were introduced in version 0.6.0
    if (fCompressed)
        SetMinVersion(FEATURE_COMPRPUBKEY);

    CPubKey pubkey = secret.GetPubKey();
    assert(secret.VerifyPubKey(pubkey));

    mapKeyMetadata[pubkey.GetID()] = metadata;
    UpdateTimeFirstKey(nCreationTime);

    if (!AddKeyPubKey(secret, pubkey))
        throw std::runtime_error(std::string(__func__) + ": AddKey failed");
    return pubkey;
}

void CWallet::DeriveNewChildKey(CKeyMetadata& metadata, CKey& secret)
{
    // for now we use a fixed keypath scheme of m/0'/0'/k
    CKey key;                      //master key seed (256bit)
    CExtKey masterKey;             //hd master key
    CExtKey accountKey;            //key at m/0'
    CExtKey externalChainChildKey; //key at m/0'/0'
    CExtKey childKey;              //key at m/0'/0'/<n>'

    // try to get the master key
    if (!GetKey(hdChain.masterKeyID, key))
        throw std::runtime_error(std::string(__func__) + ": Master key not found");

    masterKey.SetMaster(key.begin(), key.size());

    // derive m/0'
    // use hardened derivation (child keys >= 0x80000000 are hardened after bip32)
    masterKey.Derive(accountKey, BIP32_HARDENED_KEY_LIMIT);

    // derive m/0'/0'
    accountKey.Derive(externalChainChildKey, BIP32_HARDENED_KEY_LIMIT);

    // derive child key at next index, skip keys already known to the wallet
    do {
        // always derive hardened keys
        // childIndex | BIP32_HARDENED_KEY_LIMIT = derive childIndex in hardened child-index-range
        // example: 1 | BIP32_HARDENED_KEY_LIMIT == 0x80000001 == 2147483649
        externalChainChildKey.Derive(childKey, hdChain.nExternalChainCounter | BIP32_HARDENED_KEY_LIMIT);
        metadata.hdKeypath = "m/0'/0'/" + std::to_string(hdChain.nExternalChainCounter) + "'";
        metadata.hdMasterKeyID = hdChain.masterKeyID;
        // increment childkey index
        hdChain.nExternalChainCounter++;
    } while (HaveKey(childKey.key.GetPubKey().GetID()));
    secret = childKey.key;

    // update the chain model in the database
    if (!CWalletDB(strWalletFile).WriteHDChain(hdChain))
        throw std::runtime_error(std::string(__func__) + ": Writing HD chain model failed");
}

bool CWallet::AddKeyPubKey(const CKey& secret, const CPubKey &pubkey)
{
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    if (!CCryptoKeyStore::AddKeyPubKey(secret, pubkey))
        return false;

    // check if we need to remove from watch-only
    CScript script;
    script = GetScriptForDestination(pubkey.GetID());
    if (HaveWatchOnly(script))
        RemoveWatchOnly(script);
    script = GetScriptForRawPubKey(pubkey);
    if (HaveWatchOnly(script))
        RemoveWatchOnly(script);

    if (!fFileBacked)
        return true;
    if (!IsCrypted()) {
        return CWalletDB(strWalletFile).WriteKey(pubkey,
                                                 secret.GetPrivKey(),
                                                 mapKeyMetadata[pubkey.GetID()]);
    }
    return true;
}

bool CWallet::AddCryptedKey(const CPubKey &vchPubKey,
                            const std::vector<unsigned char> &vchCryptedSecret)
{
    if (!CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret))
        return false;
    if (!fFileBacked)
        return true;
    {
        LOCK(cs_wallet);
        if (pwalletdbEncryption)
            return pwalletdbEncryption->WriteCryptedKey(vchPubKey,
                                                        vchCryptedSecret,
                                                        mapKeyMetadata[vchPubKey.GetID()]);
        else
            return CWalletDB(strWalletFile).WriteCryptedKey(vchPubKey,
                                                            vchCryptedSecret,
                                                            mapKeyMetadata[vchPubKey.GetID()]);
    }
    return false;
}

bool CWallet::LoadKeyMetadata(const CTxDestination& keyID, const CKeyMetadata &meta)
{
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    UpdateTimeFirstKey(meta.nCreateTime);
    mapKeyMetadata[keyID] = meta;
    return true;
}

bool CWallet::LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret)
{
    return CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret);
}

void CWallet::UpdateTimeFirstKey(int64_t nCreateTime)
{
    AssertLockHeld(cs_wallet);
    if (nCreateTime <= 1) {
        // Cannot determine birthday information, so set the wallet birthday to
        // the beginning of time.
        nTimeFirstKey = 1;
    } else if (!nTimeFirstKey || nCreateTime < nTimeFirstKey) {
        nTimeFirstKey = nCreateTime;
    }
}

bool CWallet::AddCScript(const CScript& redeemScript)
{
    if (!CCryptoKeyStore::AddCScript(redeemScript))
        return false;
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).WriteCScript(Hash160(redeemScript), redeemScript);
}

bool CWallet::LoadCScript(const CScript& redeemScript)
{
    /* A sanity check was added in pull #3843 to avoid adding redeemScripts
     * that never can be redeemed. However, old wallets may still contain
     * these. Do not add them to the wallet and warn. */
    if (redeemScript.size() > MAX_SCRIPT_ELEMENT_SIZE)
    {
        std::string strAddr = CBitcoinAddress(CScriptID(redeemScript)).ToString();
        LogPrintf("%s: Warning: This wallet contains a redeemScript of size %i which exceeds maximum size %i thus can never be redeemed. Do not use address %s.\n",
            __func__, redeemScript.size(), MAX_SCRIPT_ELEMENT_SIZE, strAddr);
        return true;
    }

    return CCryptoKeyStore::AddCScript(redeemScript);
}

bool CWallet::AddWatchOnly(const CScript& dest)
{
    if (!CCryptoKeyStore::AddWatchOnly(dest))
        return false;
    const CKeyMetadata& meta = mapKeyMetadata[CScriptID(dest)];
    UpdateTimeFirstKey(meta.nCreateTime);
    NotifyWatchonlyChanged(true);
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).WriteWatchOnly(dest, meta);
}

bool CWallet::AddWatchOnly(const CScript& dest, int64_t nCreateTime)
{
    mapKeyMetadata[CScriptID(dest)].nCreateTime = nCreateTime;
    return AddWatchOnly(dest);
}

bool CWallet::RemoveWatchOnly(const CScript &dest)
{
    AssertLockHeld(cs_wallet);
    if (!CCryptoKeyStore::RemoveWatchOnly(dest))
        return false;
    if (!HaveWatchOnly())
        NotifyWatchonlyChanged(false);
    if (fFileBacked)
        if (!CWalletDB(strWalletFile).EraseWatchOnly(dest))
            return false;

    return true;
}

bool CWallet::LoadWatchOnly(const CScript &dest)
{
    return CCryptoKeyStore::AddWatchOnly(dest);
}

bool CWallet::Unlock(const SecureString &strWalletPassphrase, const bool& fFirstUnlock)
{
    CCrypter crypter;
    CKeyingMaterial vMasterKey;

    {
        LOCK(cs_wallet);
        BOOST_FOREACH(const MasterKeyMap::value_type& pMasterKey, mapMasterKeys)
        {
            if(!crypter.SetKeyFromPassphrase(strWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, vMasterKey))
                continue; // try another master key
            if (CCryptoKeyStore::Unlock(vMasterKey, fFirstUnlock))
                return true;
        }
    }
    return false;
}

bool CWallet::ChangeWalletPassphrase(const SecureString& strOldWalletPassphrase, const SecureString& strNewWalletPassphrase)
{
    bool fWasLocked = IsLocked();

    {
        LOCK(cs_wallet);
        Lock();

        CCrypter crypter;
        CKeyingMaterial vMasterKey;
        BOOST_FOREACH(MasterKeyMap::value_type& pMasterKey, mapMasterKeys)
        {
            if(!crypter.SetKeyFromPassphrase(strOldWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, vMasterKey))
                return false;
            if (CCryptoKeyStore::Unlock(vMasterKey))
            {
                int64_t nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = pMasterKey.second.nDeriveIterations * (100 / ((double)(GetTimeMillis() - nStartTime)));

                nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = (pMasterKey.second.nDeriveIterations + pMasterKey.second.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) / 2;

                if (pMasterKey.second.nDeriveIterations < 25000)
                    pMasterKey.second.nDeriveIterations = 25000;

                LogPrintf("Wallet passphrase changed to an nDeriveIterations of %i\n", pMasterKey.second.nDeriveIterations);

                if (!crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                    return false;
                if (!crypter.Encrypt(vMasterKey, pMasterKey.second.vchCryptedKey))
                    return false;
                CWalletDB(strWalletFile).WriteMasterKey(pMasterKey.first, pMasterKey.second);
                if (fWasLocked)
                    Lock();
                return true;
            }
        }
    }

    return false;
}

void CWallet::SetBestChain(const CBlockLocator& loc)
{
    CWalletDB walletdb(strWalletFile);
    walletdb.WriteBestBlock(loc);
}

bool CWallet::SetMinVersion(enum WalletFeature nVersion, CWalletDB* pwalletdbIn, bool fExplicit)
{
    LOCK(cs_wallet); // nWalletVersion
    if (nWalletVersion >= nVersion)
        return true;

    // when doing an explicit upgrade, if we pass the max version permitted, upgrade all the way
    if (fExplicit && nVersion > nWalletMaxVersion)
            nVersion = FEATURE_LATEST;

    nWalletVersion = nVersion;

    if (nVersion > nWalletMaxVersion)
        nWalletMaxVersion = nVersion;

    if (fFileBacked)
    {
        CWalletDB* pwalletdb = pwalletdbIn ? pwalletdbIn : new CWalletDB(strWalletFile);
        if (nWalletVersion > 40000)
            pwalletdb->WriteMinVersion(nWalletVersion);
        if (!pwalletdbIn)
            delete pwalletdb;
    }

    return true;
}

bool CWallet::SetMaxVersion(int nVersion)
{
    LOCK(cs_wallet); // nWalletVersion, nWalletMaxVersion
    // cannot downgrade below current version
    if (nWalletVersion > nVersion)
        return false;

    nWalletMaxVersion = nVersion;

    return true;
}

std::set<uint256> CWallet::GetConflicts(const uint256& txid) const
{
    std::set<uint256> result;
    AssertLockHeld(cs_wallet);

    std::map<uint256, CWalletTx>::const_iterator it = mapWallet.find(txid);
    if (it == mapWallet.end())
        return result;
    const CWalletTx& wtx = it->second;

    std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range;

    BOOST_FOREACH(const CTxIn& txin, wtx.tx->vin)
    {
        if (mapTxSpends.count(txin.prevout) <= 1)
            continue;  // No conflict if zero or one spends
        range = mapTxSpends.equal_range(txin.prevout);
        for (TxSpends::const_iterator _it = range.first; _it != range.second; ++_it)
            result.insert(_it->second);
    }
    return result;
}

bool CWallet::HasWalletSpend(const uint256& txid) const
{
    AssertLockHeld(cs_wallet);
    auto iter = mapTxSpends.lower_bound(COutPoint(txid, 0));
    return (iter != mapTxSpends.end() && iter->first.hash == txid);
}

void CWallet::Flush(bool shutdown)
{
    bitdb.Flush(shutdown);
}

bool CWallet::Verify()
{
    if (GetBoolArg("-disablewallet", DEFAULT_DISABLE_WALLET))
        return true;

    LogPrintf("Using BerkeleyDB version %s\n", DbEnv::version(0, 0, 0));
    std::string walletFile = GetArg("-wallet", DEFAULT_WALLET_DAT);

    LogPrintf("Using wallet %s\n", walletFile);
    uiInterface.InitMessage(_("Verifying wallet..."));

    // Wallet file must be a plain filename without a directory
    if (walletFile != boost::filesystem::basename(walletFile) + boost::filesystem::extension(walletFile))
        return InitError(strprintf(_("Wallet %s resides outside data directory %s"), walletFile, GetDataDir().string()));

    if (!bitdb.Open(GetDataDir()))
    {
        // try moving the database env out of the way
        boost::filesystem::path pathDatabase = GetDataDir() / "database";
        boost::filesystem::path pathDatabaseBak = GetDataDir() / strprintf("database.%d.bak", GetTime());
        try {
            boost::filesystem::rename(pathDatabase, pathDatabaseBak);
            LogPrintf("Moved old %s to %s. Retrying.\n", pathDatabase.string(), pathDatabaseBak.string());
        } catch (const boost::filesystem::filesystem_error&) {
            // failure is ok (well, not really, but it's not worse than what we started with)
        }

        // try again
        if (!bitdb.Open(GetDataDir())) {
            // if it still fails, it probably means we can't even create the database env
            return InitError(strprintf(_("Error initializing wallet database environment %s!"), GetDataDir()));
        }
    }

    if (GetBoolArg("-salvagewallet", false))
    {
        // Recover readable keypairs:
        if (!CWalletDB::Recover(bitdb, walletFile, true))
            return false;
    }

    if (boost::filesystem::exists(GetDataDir() / walletFile))
    {
        CDBEnv::VerifyResult r = bitdb.Verify(walletFile, CWalletDB::Recover);
        if (r == CDBEnv::RECOVER_OK)
        {
            InitWarning(strprintf(_("Warning: Wallet file corrupt, data salvaged!"
                                         " Original %s saved as %s in %s; if"
                                         " your balance or transactions are incorrect you should"
                                         " restore from a backup."),
                walletFile, "wallet.{timestamp}.bak", GetDataDir()));
        }
        if (r == CDBEnv::RECOVER_FAIL)
            return InitError(strprintf(_("%s corrupt, salvage failed"), walletFile));
    }

    return true;
}

void CWallet::SyncMetaData(std::pair<TxSpends::iterator, TxSpends::iterator> range)
{
    // We want all the wallet transactions in range to have the same metadata as
    // the oldest (smallest nOrderPos).
    // So: find smallest nOrderPos:

    int nMinOrderPos = std::numeric_limits<int>::max();
    const CWalletTx* copyFrom = NULL;
    for (TxSpends::iterator it = range.first; it != range.second; ++it)
    {
        const uint256& hash = it->second;
        int n = mapWallet[hash].nOrderPos;
        if (n < nMinOrderPos)
        {
            nMinOrderPos = n;
            copyFrom = &mapWallet[hash];
        }
    }
    // Now copy data from copyFrom to rest:
    for (TxSpends::iterator it = range.first; it != range.second; ++it)
    {
        const uint256& hash = it->second;
        CWalletTx* copyTo = &mapWallet[hash];
        if (copyFrom == copyTo) continue;
        if (!copyFrom->IsEquivalentTo(*copyTo)) continue;
        copyTo->mapValue = copyFrom->mapValue;
        copyTo->vOrderForm = copyFrom->vOrderForm;
        // fTimeReceivedIsTxTime not copied on purpose
        // nTimeReceived not copied on purpose
        copyTo->nTimeSmart = copyFrom->nTimeSmart;
        copyTo->fFromMe = copyFrom->fFromMe;
        copyTo->strFromAccount = copyFrom->strFromAccount;
        // nOrderPos not copied on purpose
        // cached members not copied on purpose
    }
}

/**
 * Outpoint is spent if any non-conflicted transaction
 * spends it:
 */
bool CWallet::IsSpent(const uint256 &hash, unsigned int n) const
{
    auto tx = GetWalletTx(hash);

    // Try to handle mint output first.
    if (tx && tx->tx->vout.size() > n) {
        LOCK(cs_wallet);

        auto& script = tx->tx->vout[n].scriptPubKey;
        CWalletDB db(strWalletFile);

        if (script.IsZerocoinMint()) {
            return true;
        } else if (zwallet && script.IsSigmaMint()) {
            auto pub = sigma::ParseSigmaMintScript(script);
            uint256 hashPubcoin = primitives::GetPubCoinValueHash(pub);
            CMintMeta meta;
            if(!zwallet->GetTracker().GetMetaFromPubcoin(hashPubcoin, meta)){
                return false;
            }
            return meta.isUsed;
        } else if (zwallet && (script.IsLelantusMint() || script.IsLelantusJMint())) {
            secp_primitives::GroupElement pubcoin;
            lelantus::ParseLelantusMintScript(script, pubcoin);
            uint256 hashPubcoin = primitives::GetPubCoinValueHash(pubcoin);
            CLelantusMintMeta meta;
            if(!zwallet->GetTracker().GetLelantusMetaFromPubcoin(hashPubcoin, meta)){
                return false;
            }
            return meta.isUsed;
        }
    }

    // Normal output.
    const COutPoint outpoint(hash, n);
    std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range;
    range = mapTxSpends.equal_range(outpoint);

    for (TxSpends::const_iterator it = range.first; it != range.second; ++it)
    {
        const uint256& wtxid = it->second;
        std::map<uint256, CWalletTx>::const_iterator mit = mapWallet.find(wtxid);
        if (mit != mapWallet.end()) {
            int depth = mit->second.GetDepthInMainChain();
            if (depth > 0  || (depth == 0 && !mit->second.isAbandoned()))
                return true; // Spent
        }
    }
    return false;
}

void CWallet::AddToSpends(const COutPoint& outpoint, const uint256& wtxid)
{
    mapTxSpends.insert(std::make_pair(outpoint, wtxid));
    setWalletUTXO.erase(outpoint);

    std::pair<TxSpends::iterator, TxSpends::iterator> range;
    range = mapTxSpends.equal_range(outpoint);
    SyncMetaData(range);
}


void CWallet::AddToSpends(const uint256& wtxid)
{
    assert(mapWallet.count(wtxid));
    CWalletTx& thisTx = mapWallet[wtxid];
    if (thisTx.IsCoinBase()) // Coinbases don't spend anything!
        return;

    BOOST_FOREACH(const CTxIn& txin, thisTx.tx->vin) {
        if (!txin.IsZerocoinSpend() && !txin.IsSigmaSpend() && !txin.IsLelantusJoinSplit()) {
            AddToSpends(txin.prevout, wtxid);
        }
    }
}

bool CWallet::EncryptWallet(const SecureString& strWalletPassphrase)
{
    if (IsCrypted())
        return false;

    CKeyingMaterial vMasterKey;

    vMasterKey.resize(WALLET_CRYPTO_KEY_SIZE);
    GetStrongRandBytes(&vMasterKey[0], WALLET_CRYPTO_KEY_SIZE);

    CMasterKey kMasterKey;

    kMasterKey.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE);
    GetStrongRandBytes(&kMasterKey.vchSalt[0], WALLET_CRYPTO_SALT_SIZE);

    CCrypter crypter;
    int64_t nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, 25000, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = 2500000 / ((double)(GetTimeMillis() - nStartTime));

    nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = (kMasterKey.nDeriveIterations + kMasterKey.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) / 2;

    if (kMasterKey.nDeriveIterations < 25000)
        kMasterKey.nDeriveIterations = 25000;

    LogPrintf("Encrypting Wallet with an nDeriveIterations of %i\n", kMasterKey.nDeriveIterations);

    if (!crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod))
        return false;
    if (!crypter.Encrypt(vMasterKey, kMasterKey.vchCryptedKey))
        return false;

    {
        LOCK(cs_wallet);
        mapMasterKeys[++nMasterKeyMaxID] = kMasterKey;
        if (fFileBacked)
        {
            assert(!pwalletdbEncryption);
            pwalletdbEncryption = new CWalletDB(strWalletFile);
            if (!pwalletdbEncryption->TxnBegin()) {
                delete pwalletdbEncryption;
                pwalletdbEncryption = NULL;
                return false;
            }
            pwalletdbEncryption->WriteMasterKey(nMasterKeyMaxID, kMasterKey);
        }

        if (!EncryptKeys(vMasterKey))
        {
            if (fFileBacked) {
                pwalletdbEncryption->TxnAbort();
                delete pwalletdbEncryption;
            }
            // We now probably have half of our keys encrypted in memory, and half not...
            // die and let the user reload the unencrypted wallet.
            assert(false);
        }

        // Encryption was introduced in version 0.4.0
        SetMinVersion(FEATURE_WALLETCRYPT, pwalletdbEncryption, true);

        if (fFileBacked)
        {
            if (!pwalletdbEncryption->TxnCommit()) {
                delete pwalletdbEncryption;
                // We now have keys encrypted in memory, but not on disk...
                // die to avoid confusion and let the user reload the unencrypted wallet.
                assert(false);
            }

            delete pwalletdbEncryption;
            pwalletdbEncryption = NULL;
        }

        Lock();
        Unlock(strWalletPassphrase, true);

        if(!mnemonicContainer.IsNull() && hdChain.nVersion >= CHDChain::VERSION_WITH_BIP39) {
            assert(EncryptMnemonicContainer(vMasterKey));
            SetMinVersion(FEATURE_HD);
            assert(SetMnemonicContainer(mnemonicContainer, false));
            TopUpKeyPool();
        }

        Lock();

        // Need to completely rewrite the wallet file; if we don't, bdb might keep
        // bits of the unencrypted private key in slack space in the database file.
        CDB::Rewrite(strWalletFile);

    }
    NotifyStatusChanged(this);

    return true;
}

DBErrors CWallet::ReorderTransactions()
{
    LOCK(cs_wallet);
    CWalletDB walletdb(strWalletFile);

    // Old wallets didn't have any defined order for transactions
    // Probably a bad idea to change the output of this

    // First: get all CWalletTx and CAccountingEntry into a sorted-by-time multimap.
    typedef std::pair<CWalletTx*, CAccountingEntry*> TxPair;
    typedef std::multimap<int64_t, TxPair > TxItems;
    TxItems txByTime;

    for (std::map<uint256, CWalletTx>::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
    {
        CWalletTx* wtx = &((*it).second);
        txByTime.insert(make_pair(wtx->nTimeReceived, TxPair(wtx, (CAccountingEntry*)0)));
    }
    std::list<CAccountingEntry> acentries;
    walletdb.ListAccountCreditDebit("", acentries);
    BOOST_FOREACH(CAccountingEntry& entry, acentries)
    {
        txByTime.insert(make_pair(entry.nTime, TxPair((CWalletTx*)0, &entry)));
    }

    nOrderPosNext = 0;
    std::vector<int64_t> nOrderPosOffsets;
    for (TxItems::iterator it = txByTime.begin(); it != txByTime.end(); ++it)
    {
        CWalletTx *const pwtx = (*it).second.first;
        CAccountingEntry *const pacentry = (*it).second.second;
        int64_t& nOrderPos = (pwtx != 0) ? pwtx->nOrderPos : pacentry->nOrderPos;

        if (nOrderPos == -1)
        {
            nOrderPos = nOrderPosNext++;
            nOrderPosOffsets.push_back(nOrderPos);

            if (pwtx)
            {
                if (!walletdb.WriteTx(*pwtx))
                    return DB_LOAD_FAIL;
            }
            else
                if (!walletdb.WriteAccountingEntry(pacentry->nEntryNo, *pacentry))
                    return DB_LOAD_FAIL;
        }
        else
        {
            int64_t nOrderPosOff = 0;
            BOOST_FOREACH(const int64_t& nOffsetStart, nOrderPosOffsets)
            {
                if (nOrderPos >= nOffsetStart)
                    ++nOrderPosOff;
            }
            nOrderPos += nOrderPosOff;
            nOrderPosNext = std::max(nOrderPosNext, nOrderPos + 1);

            if (!nOrderPosOff)
                continue;

            // Since we're changing the order, write it back
            if (pwtx)
            {
                if (!walletdb.WriteTx(*pwtx))
                    return DB_LOAD_FAIL;
            }
            else
                if (!walletdb.WriteAccountingEntry(pacentry->nEntryNo, *pacentry))
                    return DB_LOAD_FAIL;
        }
    }
    walletdb.WriteOrderPosNext(nOrderPosNext);

    return DB_LOAD_OK;
}

int64_t CWallet::IncOrderPosNext(CWalletDB *pwalletdb)
{
    AssertLockHeld(cs_wallet); // nOrderPosNext
    int64_t nRet = nOrderPosNext++;
    if (pwalletdb) {
        pwalletdb->WriteOrderPosNext(nOrderPosNext);
    } else {
        CWalletDB(strWalletFile).WriteOrderPosNext(nOrderPosNext);
    }
    return nRet;
}

bool CWallet::AccountMove(std::string strFrom, std::string strTo, CAmount nAmount, std::string strComment)
{
    CWalletDB walletdb(strWalletFile);
    if (!walletdb.TxnBegin())
        return false;

    int64_t nNow = GetAdjustedTime();

    // Debit
    CAccountingEntry debit;
    debit.nOrderPos = IncOrderPosNext(&walletdb);
    debit.strAccount = strFrom;
    debit.nCreditDebit = -nAmount;
    debit.nTime = nNow;
    debit.strOtherAccount = strTo;
    debit.strComment = strComment;
    AddAccountingEntry(debit, &walletdb);

    // Credit
    CAccountingEntry credit;
    credit.nOrderPos = IncOrderPosNext(&walletdb);
    credit.strAccount = strTo;
    credit.nCreditDebit = nAmount;
    credit.nTime = nNow;
    credit.strOtherAccount = strFrom;
    credit.strComment = strComment;
    AddAccountingEntry(credit, &walletdb);

    if (!walletdb.TxnCommit())
        return false;

    return true;
}

bool CWallet::GetAccountPubkey(CPubKey &pubKey, std::string strAccount, bool bForceNew)
{
    CWalletDB walletdb(strWalletFile);

    CAccount account;
    walletdb.ReadAccount(strAccount, account);

    if (!bForceNew) {
        if (!account.vchPubKey.IsValid())
            bForceNew = true;
        else {
            // Check if the current key has been used
            CScript scriptPubKey = GetScriptForDestination(account.vchPubKey.GetID());
            for (std::map<uint256, CWalletTx>::iterator it = mapWallet.begin();
                 it != mapWallet.end() && account.vchPubKey.IsValid();
                 ++it)
                BOOST_FOREACH(const CTxOut& txout, (*it).second.tx->vout)
                    if (txout.scriptPubKey == scriptPubKey) {
                        bForceNew = true;
                        break;
                    }
        }
    }

    // Generate a new key
    if (bForceNew) {
        if (!GetKeyFromPool(account.vchPubKey))
            return false;

        SetAddressBook(account.vchPubKey.GetID(), strAccount, "receive");
        walletdb.WriteAccount(strAccount, account);
    }

    pubKey = account.vchPubKey;

    return true;
}

void CWallet::MarkDirty()
{
    {
        LOCK(cs_wallet);
        BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
            item.second.MarkDirty();
    }
}

namespace {
void HandleSecretAddresses(CWallet & wallet, bip47::CAccountReceiver const & receiver)
{
    if (wallet.IsLocked()) {
        wallet.NotifyBip47KeysChanged(receiver.getAccountNum(), chainActive.Tip());
        return;
    }

    bip47::utils::AddReceiverSecretAddresses(receiver, wallet);
}
}

bool CWallet::MarkReplaced(const uint256& originalHash, const uint256& newHash)
{
    LOCK(cs_wallet);

    auto mi = mapWallet.find(originalHash);

    // There is a bug if MarkReplaced is not called on an existing wallet transaction.
    assert(mi != mapWallet.end());

    CWalletTx& wtx = (*mi).second;

    // Ensure for now that we're not overwriting data
    assert(wtx.mapValue.count("replaced_by_txid") == 0);

    wtx.mapValue["replaced_by_txid"] = newHash.ToString();

    CWalletDB walletdb(strWalletFile, "r+");

    bool success = true;
    if (!walletdb.WriteTx(wtx)) {
        LogPrintf("%s: Updating walletdb tx %s failed", __func__, wtx.GetHash().ToString());
        success = false;
    }

    NotifyTransactionChanged(this, originalHash, CT_UPDATED);

    return success;
}

bool CWallet::AddToWallet(const CWalletTx& wtxIn, bool fFlushOnClose)
{
    LOCK(cs_wallet);

    CWalletDB walletdb(strWalletFile, "r+", fFlushOnClose);

    uint256 hash = wtxIn.GetHash();

    // Inserts only if not already there, returns tx inserted or tx found
    std::pair<std::map<uint256, CWalletTx>::iterator, bool> ret = mapWallet.insert(std::make_pair(hash, wtxIn));
    CWalletTx& wtx = (*ret.first).second;
    wtx.BindWallet(this);
    bool fInsertedNew = ret.second;
    if (fInsertedNew)
    {
        wtx.nTimeReceived = GetAdjustedTime();
        wtx.nOrderPos = IncOrderPosNext(&walletdb);
        wtxOrdered.insert(make_pair(wtx.nOrderPos, TxPair(&wtx, (CAccountingEntry*)0)));

        auto mnList = deterministicMNManager->GetListAtChainTip();
        for(unsigned int i = 0; i < wtx.tx->vout.size(); ++i) {
            if (IsMine(wtx.tx->vout[i]) && !IsSpent(hash, i)) {
                setWalletUTXO.insert(COutPoint(hash, i));
                if (deterministicMNManager->IsProTxWithCollateral(wtx.tx, i) || mnList.HasMNByCollateral(COutPoint(hash, i))) {
                    LockCoin(COutPoint(hash, i));
                }
            }
        }

        wtx.nTimeSmart = wtx.nTimeReceived;
        if (!wtxIn.hashUnset())
        {
            if (mapBlockIndex.count(wtxIn.hashBlock))
            {
                int64_t latestNow = wtx.nTimeReceived;
                int64_t latestEntry = 0;
                {
                    // Tolerate times up to the last timestamp in the wallet not more than 5 minutes into the future
                    int64_t latestTolerated = latestNow + 300;
                    const TxItems & txOrdered = wtxOrdered;
                    for (TxItems::const_reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it)
                    {
                        CWalletTx *const pwtx = (*it).second.first;
                        if (pwtx == &wtx)
                            continue;
                        CAccountingEntry *const pacentry = (*it).second.second;
                        int64_t nSmartTime;
                        if (pwtx)
                        {
                            nSmartTime = pwtx->nTimeSmart;
                            if (!nSmartTime)
                                nSmartTime = pwtx->nTimeReceived;
                        }
                        else
                            nSmartTime = pacentry->nTime;
                        if (nSmartTime <= latestTolerated)
                        {
                            latestEntry = nSmartTime;
                            if (nSmartTime > latestNow)
                                latestNow = nSmartTime;
                            break;
                        }
                    }
                }

                int64_t blocktime = mapBlockIndex[wtxIn.hashBlock]->GetBlockTime();
                wtx.nTimeSmart = std::max(latestEntry, std::min(blocktime, latestNow));
            }
            else
                LogPrintf("AddToWallet(): found %s in block %s not in index\n",
                         wtxIn.GetHash().ToString(),
                         wtxIn.hashBlock.ToString());
        }
        AddToSpends(hash);
    }

    bool fUpdated = false;
    if (!fInsertedNew)
    {
        // Merge
        if (!wtxIn.hashUnset() && wtxIn.hashBlock != wtx.hashBlock)
        {
            wtx.hashBlock = wtxIn.hashBlock;
            fUpdated = true;
        }
        // If no longer abandoned, update
        if (wtxIn.hashBlock.IsNull() && wtx.isAbandoned())
        {
            wtx.hashBlock = wtxIn.hashBlock;
            fUpdated = true;
        }
        if (wtxIn.nIndex != -1 && (wtxIn.nIndex != wtx.nIndex))
        {
            wtx.nIndex = wtxIn.nIndex;
            fUpdated = true;
        }
        if (wtxIn.fFromMe && wtxIn.fFromMe != wtx.fFromMe)
        {
            wtx.fFromMe = wtxIn.fFromMe;
            fUpdated = true;
        }
    }

    //// debug print
    LogPrintf("AddToWallet %s  %s%s\n", wtxIn.GetHash().ToString(), (fInsertedNew ? "new" : ""), (fUpdated ? "update" : ""));

    // Write to disk
    if (fInsertedNew || fUpdated)
        if (!walletdb.WriteTx(wtx))
            return false;

    // Handle bip47 notification tx
    if (fInsertedNew)
    {
        HandleBip47Transaction(wtx);
    }

    // Break debit/credit balance caches:
    wtx.MarkDirty();

    // Notify UI of new or updated transaction
    NotifyTransactionChanged(this, hash, fInsertedNew ? CT_NEW : CT_UPDATED);

    // notify an external script when a wallet transaction comes in or is updated
    std::string strCmd = GetArg("-walletnotify", "");

    if ( !strCmd.empty())
    {
        boost::replace_all(strCmd, "%s", wtxIn.GetHash().GetHex());
        boost::thread t(runCommand, strCmd); // thread runs free
    }

    return true;
}

bool CWallet::LoadToWallet(const CWalletTx& wtxIn)
{
    uint256 hash = wtxIn.GetHash();

    mapWallet[hash] = wtxIn;
    CWalletTx& wtx = mapWallet[hash];
    wtx.BindWallet(this);
    wtxOrdered.insert(make_pair(wtx.nOrderPos, TxPair(&wtx, (CAccountingEntry*)0)));
    AddToSpends(hash);
    BOOST_FOREACH(const CTxIn& txin, wtx.tx->vin) {
        if (mapWallet.count(txin.prevout.hash)) {
            CWalletTx& prevtx = mapWallet[txin.prevout.hash];
            if (prevtx.nIndex == -1 && !prevtx.hashUnset()) {
                MarkConflicted(prevtx.hashBlock, wtx.GetHash());
            }
        }
    }

    return true;
}

/**
 * Add a transaction to the wallet, or update it.  pIndex and posInBlock should
 * be set when the transaction was known to be included in a block.  When
 * posInBlock = SYNC_TRANSACTION_NOT_IN_BLOCK (-1) , then wallet state is not
 * updated in AddToWallet, but notifications happen and cached balances are
 * marked dirty.
 * If fUpdate is true, existing transactions will be updated.
 * TODO: One exception to this is that the abandoned state is cleared under the
 * assumption that any further notification of a transaction that was considered
 * abandoned is an indication that it is not safe to be considered abandoned.
 * Abandoned state should probably be more carefuly tracked via different
 * posInBlock signals or by checking mempool presence when necessary.
 */
bool CWallet::AddToWalletIfInvolvingMe(const CTransaction& tx, const CBlockIndex* pIndex, int posInBlock, bool fUpdate)
{
    {
        AssertLockHeld(cs_wallet);

        if (posInBlock != -1) {
            if(!(tx.IsCoinBase() || tx.IsSigmaSpend() || tx.IsZerocoinRemint() || tx.IsZerocoinSpend()) || tx.IsLelantusJoinSplit()) {
                BOOST_FOREACH(const CTxIn& txin, tx.vin) {
                    std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range = mapTxSpends.equal_range(txin.prevout);
                    while (range.first != range.second) {
                        if (range.first->second != tx.GetHash()) {
                            LogPrintf("Transaction %s (in block %s) conflicts with wallet transaction %s (both spend %s:%i)\n", tx.GetHash().ToString(), pIndex->GetBlockHash().ToString(), range.first->second.ToString(), range.first->first.hash.ToString(), range.first->first.n);
                            MarkConflicted(pIndex->GetBlockHash(), range.first->second);
                        }
                        range.first++;
                    }
                }
            }
        }

        bool fExisted = mapWallet.count(tx.GetHash()) != 0;
        if (fExisted && !fUpdate) return false;
        if (fExisted || IsMine(tx) || IsFromMe(tx))
        {
            CWalletTx wtx(this, MakeTransactionRef(tx));

            // Get merkle branch if transaction was found in a block
            if (posInBlock != -1)
                wtx.SetMerkleBranch(pIndex, posInBlock);

            return AddToWallet(wtx, false);
        }
    }
    return false;
}

bool CWallet::AbandonTransaction(const uint256& hashTx)
{
    LOCK2(cs_main, cs_wallet);

    CWalletDB walletdb(strWalletFile, "r+");

    std::set<uint256> todo;
    std::set<uint256> done;

    // Can't mark abandoned if confirmed or in mempool
    assert(mapWallet.count(hashTx));
    CWalletTx& origtx = mapWallet[hashTx];
    if (origtx.GetDepthInMainChain() > 0 || origtx.InMempool() || origtx.InStempool()) {
        return false;
    }

    todo.insert(hashTx);

    while (!todo.empty()) {
        uint256 now = *todo.begin();
        todo.erase(now);
        done.insert(now);
        assert(mapWallet.count(now));
        CWalletTx& wtx = mapWallet[now];
        int currentconfirm = wtx.GetDepthInMainChain();
        // If the orig tx was not in block, none of its spends can be
        assert(currentconfirm <= 0);
        // if (currentconfirm < 0) {Tx and spends are already conflicted, no need to abandon}
        if (currentconfirm == 0 && !wtx.isAbandoned()) {
            // If the orig tx was not in block/mempool, none of its spends can be in mempool
            assert(!wtx.InMempool());
            assert(!wtx.InStempool());
            wtx.nIndex = -1;
            wtx.setAbandoned();
            wtx.MarkDirty();
            walletdb.WriteTx(wtx);
            NotifyTransactionChanged(this, wtx.GetHash(), CT_UPDATED);
            // Iterate over all its outputs, and mark transactions in the wallet that spend them abandoned too
            TxSpends::const_iterator iter = mapTxSpends.lower_bound(COutPoint(hashTx, 0));
            while (iter != mapTxSpends.end() && iter->first.hash == now) {
                if (!done.count(iter->second)) {
                    todo.insert(iter->second);
                }
                iter++;
            }
            // If a transaction changes 'conflicted' state, that changes the balance
            // available of the outputs it spends. So force those to be recomputed
            BOOST_FOREACH(const CTxIn& txin, wtx.tx->vin)
            {
                if (mapWallet.count(txin.prevout.hash))
                    mapWallet[txin.prevout.hash].MarkDirty();
            }
        }

        if (wtx.tx->IsSigmaSpend()) {
            // find out coin serial number
            assert(wtx.tx->vin.size() == 1);

            const CTxIn &txin = wtx.tx->vin[0];
            // NOTE(martun): +1 on the next line stands for 1 byte in which the opcode of
            // OP_SIGMASPEND is written.
            // because the size of serialized spend is also written, probably in 3 bytes.
            CDataStream serializedCoinSpend((const char *)&*(txin.scriptSig.begin() + 1),
                                            (const char *)&*txin.scriptSig.end(),
                                            SER_NETWORK, PROTOCOL_VERSION);
            sigma::CoinSpend spend(sigma::Params::get_default(),
                                         serializedCoinSpend);

            Scalar serial = spend.getCoinSerialNumber();

            // mark corresponding mint as unspent
            uint256 hashSerial = primitives::GetSerialHash(serial);
            CMintMeta meta;
            if(zwallet->GetTracker().GetMetaFromSerial(hashSerial, meta)){
                meta.isUsed = false;
                zwallet->GetTracker().UpdateState(meta);

                // erase sigma spend entry
                CSigmaSpendEntry spendEntry;
                spendEntry.coinSerial = serial;
                walletdb.EraseCoinSpendSerialEntry(spendEntry);
            }
        } else if (wtx.tx->IsLelantusJoinSplit()) {
            // find out coin serial number
            assert(wtx.tx->vin.size() == 1);

            const CTxIn &txin = wtx.tx->vin[0];
            std::unique_ptr<lelantus::JoinSplit> joinsplit;
            try {
                joinsplit = lelantus::ParseLelantusJoinSplit(txin);
            }
            catch (CBadTxIn&) {
                continue;
            }

            const std::vector<Scalar>& serials = joinsplit->getCoinSerialNumbers();

            for (const auto& serial : serials) {
                // mark corresponding mint as unspent
                uint256 hashSerial = primitives::GetSerialHash(serial);
                CLelantusMintMeta meta;
                if(zwallet->GetTracker().GetMetaFromSerial(hashSerial, meta)){
                    meta.isUsed = false;
                    zwallet->GetTracker().UpdateState(meta);

                    // erase lelantus spend entry
                    CLelantusSpendEntry spendEntry;
                    spendEntry.coinSerial = serial;
                    walletdb.EraseLelantusSpendSerialEntry(spendEntry);
                }
            }
        }

        if (wtx.tx->IsSigmaMint()) {
            for (const CTxOut &txout: wtx.tx->vout) {
                if (!txout.scriptPubKey.IsSigmaMint())
                    continue;

                try {
                    auto groupElement = sigma::ParseSigmaMintScript(txout.scriptPubKey);
                    uint256 hashPubcoin = primitives::GetPubCoinValueHash(groupElement);
                    CMintMeta meta;
                    if (zwallet->GetTracker().GetMetaFromPubcoin(hashPubcoin, meta))
                        zwallet->GetTracker().Archive(meta);
                }
                catch (std::invalid_argument &) {
                    continue;
                }
            }
        }

        if (wtx.tx->IsLelantusMint()) {
            for (const CTxOut &txout: wtx.tx->vout) {
                if (!txout.scriptPubKey.IsLelantusMint() && !txout.scriptPubKey.IsLelantusJMint())
                    continue;

                try {
                    secp_primitives::GroupElement groupElement;
                    lelantus::ParseLelantusMintScript(txout.scriptPubKey, groupElement);
                    uint256 hashPubcoin = primitives::GetPubCoinValueHash(groupElement);
                    CLelantusMintMeta meta;
                    if (zwallet->GetTracker().GetLelantusMetaFromPubcoin(hashPubcoin, meta))
                        zwallet->GetTracker().Archive(meta);
                }
                catch (std::invalid_argument &) {
                    continue;
                }
            }
        }
    }

    return true;
}

void CWallet::MarkConflicted(const uint256& hashBlock, const uint256& hashTx)
{
    LOCK2(cs_main, cs_wallet);

    int conflictconfirms = 0;
    if (mapBlockIndex.count(hashBlock)) {
        CBlockIndex* pindex = mapBlockIndex[hashBlock];
        if (chainActive.Contains(pindex)) {
            conflictconfirms = -(chainActive.Height() - pindex->nHeight + 1);
        }
    }
    // If number of conflict confirms cannot be determined, this means
    // that the block is still unknown or not yet part of the main chain,
    // for example when loading the wallet during a reindex. Do nothing in that
    // case.
    if (conflictconfirms >= 0)
        return;

    // Do not flush the wallet here for performance reasons
    CWalletDB walletdb(strWalletFile, "r+", false);

    std::set<uint256> todo;
    std::set<uint256> done;

    todo.insert(hashTx);

    while (!todo.empty()) {
        uint256 now = *todo.begin();
        todo.erase(now);
        done.insert(now);
        assert(mapWallet.count(now));
        CWalletTx& wtx = mapWallet[now];
        int currentconfirm = wtx.GetDepthInMainChain();
        if (conflictconfirms < currentconfirm) {
            // Block is 'more conflicted' than current confirm; update.
            // Mark transaction as conflicted with this block.
            wtx.nIndex = -1;
            wtx.hashBlock = hashBlock;
            wtx.MarkDirty();
            walletdb.WriteTx(wtx);
            // Iterate over all its outputs, and mark transactions in the wallet that spend them conflicted too
            TxSpends::const_iterator iter = mapTxSpends.lower_bound(COutPoint(now, 0));
            while (iter != mapTxSpends.end() && iter->first.hash == now) {
                 if (!done.count(iter->second)) {
                     todo.insert(iter->second);
                 }
                 iter++;
            }
            // If a transaction changes 'conflicted' state, that changes the balance
            // available of the outputs it spends. So force those to be recomputed
            BOOST_FOREACH(const CTxIn& txin, wtx.tx->vin)
            {
                if (mapWallet.count(txin.prevout.hash))
                    mapWallet[txin.prevout.hash].MarkDirty();
            }
        }
    }
}

void CWallet::SyncTransaction(const CTransaction& tx, const CBlockIndex *pindex, int posInBlock)
{
    LOCK2(cs_main, cs_wallet);

    if (!AddToWalletIfInvolvingMe(tx, pindex, posInBlock, true))
        return; // Not one of ours

    // If a transaction changes 'conflicted' state, that changes the balance
    // available of the outputs it spends. So force those to be
    // recomputed, also:
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        if (mapWallet.count(txin.prevout.hash))
            mapWallet[txin.prevout.hash].MarkDirty();
    }
}


isminetype CWallet::IsMine(const CTxIn &txin) const
{
    LOCK(cs_wallet);

    if (txin.IsZerocoinSpend()) {
        return ISMINE_NO;
    } else if (txin.IsSigmaSpend()) {
        CWalletDB db(strWalletFile);

        CDataStream serializedCoinSpend(
            std::vector<char>(txin.scriptSig.begin() + 1, txin.scriptSig.end()),
            SER_NETWORK, PROTOCOL_VERSION);

        sigma::Params* sigmaParams = sigma::Params::get_default();
        sigma::CoinSpend spend(sigmaParams, serializedCoinSpend);

        if (db.HasCoinSpendSerialEntry(spend.getCoinSerialNumber())) {
            return ISMINE_SPENDABLE;
        }
    } else if (txin.IsLelantusJoinSplit()) {
        CWalletDB db(strWalletFile);
        std::unique_ptr<lelantus::JoinSplit> joinsplit;
        try {
            joinsplit = lelantus::ParseLelantusJoinSplit(txin);
        }
        catch (CBadTxIn&) {
            return ISMINE_NO;
        }

        if (db.HasLelantusSpendSerialEntry(joinsplit->getCoinSerialNumbers()[0]) || db.HasCoinSpendSerialEntry(joinsplit->getCoinSerialNumbers()[0])) {
            return ISMINE_SPENDABLE;
        }
    } else if (txin.IsZerocoinRemint()) {
        return ISMINE_NO;
    }
    else {
        std::map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.tx->vout.size())
                return IsMine(prev.tx->vout[txin.prevout.n]);
        }
    }

    return ISMINE_NO;
}

// Note that this function doesn't distinguish between a 0-valued input,
// and a not-"is mine" (according to the filter) input.
CAmount CWallet::GetDebit(const CTxIn &txin, const isminefilter& filter) const
{
    LOCK(cs_wallet);

    if (txin.IsZerocoinSpend()) {
        // Reverting it to its pre-Sigma state.
        goto end;
    } else if (txin.IsSigmaSpend()) {
        if (!(filter & ISMINE_SPENDABLE)) {
            goto end;
        }

        CWalletDB db(strWalletFile);
        std::unique_ptr<sigma::CoinSpend> spend;

        try {
            std::tie(spend, std::ignore) = sigma::ParseSigmaSpend(txin);
        } catch (CBadTxIn&) {
            goto end;
        }

        if (db.HasCoinSpendSerialEntry(spend->getCoinSerialNumber())) {
            return spend->getIntDenomination();
        }
    } else if (txin.IsZerocoinRemint()) {
        return 0;
    } else if (txin.IsLelantusJoinSplit()) {
        if (!(filter & ISMINE_SPENDABLE)) {
            goto end;
        }

        CWalletDB db(strWalletFile);
        std::unique_ptr<lelantus::JoinSplit> joinsplit;
        try {
            joinsplit = lelantus::ParseLelantusJoinSplit(txin);
        }
        catch (CBadTxIn&) {
            goto end;
        }

        CAmount amount = 0;

        const std::vector<Scalar>& serials = joinsplit->getCoinSerialNumbers();
        for (const auto& serial : serials) {
            CLelantusSpendEntry lelantusSpend;
            if(db.ReadLelantusSpendSerialEntry(serial, lelantusSpend))
                amount += lelantusSpend.amount;
        }
        return amount;
    } else {
        std::map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.tx->vout.size())
                if (IsMine(prev.tx->vout[txin.prevout.n]) & filter)
                    return prev.tx->vout[txin.prevout.n].nValue;
        }
    }

end:
    return 0;
}

isminetype CWallet::IsMine(const CTxOut &txout) const
{
    LOCK(cs_wallet);

    if (txout.scriptPubKey.IsSigmaMint() || txout.scriptPubKey.IsLelantusMint() || txout.scriptPubKey.IsLelantusJMint()) {
        CWalletDB db(strWalletFile);
        secp_primitives::GroupElement pub;

            if (txout.scriptPubKey.IsSigmaMint()) {
                try {
                    pub = sigma::ParseSigmaMintScript(txout.scriptPubKey);
                } catch (std::invalid_argument &) {
                    return ISMINE_NO;
                }

            }
            else {
                try {
                    lelantus::ParseLelantusMintScript(txout.scriptPubKey, pub);
                } catch (std::invalid_argument &) {
                    return ISMINE_NO;
                }
            }
        return db.HasHDMint(pub) ? ISMINE_SPENDABLE : ISMINE_NO;
    } else {
        return ::IsMine(*this, txout.scriptPubKey);
    }
}

CAmount CWallet::GetCredit(const CTxOut& txout, const isminefilter& filter) const
{
    if (!MoneyRange(txout.nValue))
        throw std::runtime_error(std::string(__func__) + ": value out of range");
    if (txout.scriptPubKey.IsLelantusJMint()) {
        CWalletDB db(strWalletFile);
        secp_primitives::GroupElement pub;
        try {
            std::vector<unsigned char> encryptedValue;
            lelantus::ParseLelantusJMintScript(txout.scriptPubKey, pub, encryptedValue);
        } catch (std::invalid_argument&) {
            return ISMINE_NO;
        }
        uint256 hashPubcoin = primitives::GetPubCoinValueHash(pub);
        CHDMint dMint;
        if (db.ReadHDMint(hashPubcoin, true, dMint)) {
            return dMint.GetAmount();
        }
        return 0;
    }
    return ((IsMine(txout) & filter) ? txout.nValue : 0);
}

bool CWallet::IsChange(const uint256& tx, const CTxOut &txout) const
{
    auto wtx = GetWalletTx(tx);
    if (!wtx) {
        throw std::invalid_argument("The specified transaction hash is not belong to the wallet");
    }

    return wtx->IsChange(txout);
}

CAmount CWallet::GetChange(const uint256& tx, const CTxOut &txout) const
{
    if (!MoneyRange(txout.nValue))
        throw std::runtime_error(std::string(__func__) + ": value out of range");
    return (IsChange(tx, txout) ? txout.nValue : 0);
}

bool CWallet::IsMine(const CTransaction& tx) const
{
    BOOST_FOREACH(const CTxOut& txout, tx.vout)
        if (IsMine(txout))
            return true;
    return false;
}

bool CWallet::IsFromMe(const CTransaction& tx) const
{
    return (GetDebit(tx, ISMINE_ALL) > 0);
}

CAmount CWallet::GetDebit(const CTransaction& tx, const isminefilter& filter) const
{
    CAmount nDebit = 0;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        nDebit += GetDebit(txin, filter);
        if (!MoneyRange(nDebit))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return nDebit;
}

bool CWallet::IsAllFromMe(const CTransaction& tx, const isminefilter& filter) const
{
    LOCK(cs_wallet);

    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        auto mi = mapWallet.find(txin.prevout.hash);
        if (mi == mapWallet.end())
            return false; // any unknown inputs can't be from us

        const CWalletTx& prev = (*mi).second;

        if (txin.prevout.n >= prev.tx->vout.size())
            return false; // invalid input!

        if (!(IsMine(prev.tx->vout[txin.prevout.n]) & filter))
            return false;
    }
    return true;
}

CAmount CWallet::GetCredit(const CTransaction& tx, const isminefilter& filter) const
{
    CAmount nCredit = 0;
    BOOST_FOREACH(const CTxOut& txout, tx.vout)
    {
        nCredit += GetCredit(txout, filter);
        if (!MoneyRange(nCredit))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return nCredit;
}

CAmount CWallet::GetChange(const CTransaction& tx) const
{
    CAmount nChange = 0;
    BOOST_FOREACH(const CTxOut& txout, tx.vout)
    {
        nChange += GetChange(tx.GetHash(), txout);
        if (!MoneyRange(nChange))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return nChange;
}

CPubKey CWallet::GenerateNewHDMasterKey()
{
    CKey key;
    key.MakeNewKey(true);

    int64_t nCreationTime = GetTime();
    CKeyMetadata metadata(nCreationTime);

    // calculate the pubkey
    CPubKey pubkey = key.GetPubKey();
    assert(key.VerifyPubKey(pubkey));

    // set the hd keypath to "m" -> Master, refers the masterkeyid to itself
    metadata.hdKeypath     = "m";
    metadata.hdMasterKeyID = pubkey.GetID();

    {
        LOCK(cs_wallet);

        // mem store the metadata
        mapKeyMetadata[pubkey.GetID()] = metadata;

        // write the key&metadata to the database
        if (!AddKeyPubKey(key, pubkey))
            throw std::runtime_error(std::string(__func__) + ": AddKeyPubKey failed");
    }

    return pubkey;
}

void CWallet::GenerateNewMnemonic()
{
    CHDChain newHdChain;
    MnemonicContainer mnContainer;

    std::string strSeed = GetArg("-hdseed", "not hex");

    bool isHDSeedSet = strSeed != "not hex";

    if(isHDSeedSet && IsHex(strSeed)) {
        std::vector<unsigned char> seed = ParseHex(strSeed);
        if (!mnContainer.SetSeed(SecureVector(seed.begin(), seed.end())))
            throw std::runtime_error(std::string(__func__) + ": SetSeed failed");
        newHdChain.masterKeyID = CKeyID(Hash160(seed.begin(), seed.end()));
    }
    else {
        LogPrintf("CWallet::GenerateNewMnemonic -- Generating new MnemonicContainer\n");

        std::string mnemonic = GetArg("-mnemonic", "");
        std::string mnemonicPassphrase = GetArg("-mnemonicpassphrase", "");
        //remove trailing string identifiers
        boost::algorithm::trim_if(mnemonic, [](char c){return c=='\"' || c=='\'';});
        boost::algorithm::trim_if(mnemonicPassphrase, [](char c){return c=='\"' || c=='\'';});
        //Use 24 words by default;
        bool use12Words = GetBoolArg("-use12", false);
        mnContainer.Set12Words(use12Words);

        SecureString secureMnemonic(mnemonic.begin(), mnemonic.end());
        SecureString securePassphrase(mnemonicPassphrase.begin(), mnemonicPassphrase.end());

        if (!mnContainer.SetMnemonic(secureMnemonic, securePassphrase))
            throw std::runtime_error(std::string(__func__) + ": SetMnemonic failed");
        newHdChain.masterKeyID = CKeyID(Hash160(mnContainer.seed.begin(), mnContainer.seed.end()));
    }

    if (!SetHDChain(newHdChain, false))
        throw std::runtime_error(std::string(__func__) + ": SetHDChain failed");

    if (!SetMnemonicContainer(mnContainer, false))
        throw std::runtime_error(std::string(__func__) + ": SetMnemonicContainer failed");
}

bool CWallet::SetHDMasterKey(const CPubKey &pubkey, const int cHDChainVersion) {
    LOCK(cs_wallet);

    // ensure this wallet.dat can only be opened by clients supporting HD
    SetMinVersion(FEATURE_HD);

    // store the keyid (hash160) together with
    // the child index counter in the database
    // as a hdchain object
    CHDChain newHdChain;
    newHdChain.nVersion = cHDChainVersion;
    newHdChain.masterKeyID = pubkey.GetID();
    SetHDChain(newHdChain, false);

    return true;
}

bool CWallet::SetHDChain(const CHDChain &chain, bool memonly, bool& upgradeChain, bool genNewKeyPool)
{
    LOCK(cs_wallet);
    upgradeChain = (chain.nVersion==CHDChain::VERSION_BASIC);
    if (upgradeChain && !IsLocked()) { // Upgrade HDChain to latest version
        CHDChain newChain;
        newChain.masterKeyID = chain.masterKeyID;
        newChain.nVersion = CHDChain::VERSION_WITH_BIP44; // old versions cannot use mnemonic
        // whether to generate the keypool now (conditional as leads to DB deadlock if loading DB simultaneously)
        if (genNewKeyPool)
            NewKeyPool();
        if (!memonly && !CWalletDB(strWalletFile).WriteHDChain(newChain))
            throw std::runtime_error(std::string(__func__) + ": writing chain failed");
        hdChain = newChain;
    }
    else {
        if (!memonly && !CWalletDB(strWalletFile).WriteHDChain(chain))
            throw std::runtime_error(std::string(__func__) + ": writing chain failed");
        hdChain = chain;
    }

    return true;
}

bool CWallet::IsHDEnabled()
{
    return !hdChain.masterKeyID.IsNull();
}

bool CWallet::SetMnemonicContainer(const MnemonicContainer& mnContainer, bool memonly) {
    if (!memonly && !CWalletDB(strWalletFile).WriteMnemonic(mnContainer))
        throw std::runtime_error(std::string(__func__) + ": writing chain failed");
    mnemonicContainer = mnContainer;
    return true;
}

bool CWallet::EncryptMnemonicContainer(const CKeyingMaterial& vMasterKeyIn)
{
    if (!IsCrypted())
        return false;

    if (mnemonicContainer.IsCrypted())
        return true;

    uint256 id = uint256S(hdChain.masterKeyID.GetHex());

    std::vector<unsigned char> cryptedSeed;
    if (!EncryptMnemonicSecret(vMasterKeyIn, mnemonicContainer.GetSeed(), id, cryptedSeed))
        return false;
    SecureVector secureCryptedSeed(cryptedSeed.begin(), cryptedSeed.end());
    if (!mnemonicContainer.SetSeed(secureCryptedSeed))
        return false;

    SecureString mnemonic;
    if (mnemonicContainer.GetMnemonic(mnemonic)) {
        std::vector<unsigned char> cryptedMnemonic;
        SecureVector vectorMnemonic(mnemonic.begin(), mnemonic.end());

        if ((!mnemonic.empty() && !EncryptMnemonicSecret(vMasterKeyIn, vectorMnemonic, id, cryptedMnemonic)))
            return false;

        SecureVector secureCryptedMnemonic(cryptedMnemonic.begin(), cryptedMnemonic.end());
        if (!mnemonicContainer.SetMnemonic(secureCryptedMnemonic))
            return false;
    }

    mnemonicContainer.SetCrypted(true);

    return true;
}

bool CWallet::DecryptMnemonicContainer(MnemonicContainer& mnContainer)
{
    if (!IsCrypted())
        return true;

    if (!mnemonicContainer.IsCrypted())
        return false;

    uint256 id = uint256S(hdChain.masterKeyID.GetHex());

    SecureVector seed;
    SecureVector cryptedSeed = mnemonicContainer.GetSeed();
    std::vector<unsigned char> vCryptedSeed(cryptedSeed.begin(), cryptedSeed.end());
    if (!DecryptMnemonicSecret(vCryptedSeed, id, seed))
        return false;

    mnContainer = mnemonicContainer;
    if (!mnContainer.SetSeed(seed))
        return false;

    SecureString cryptedMnemonic;

    if (mnemonicContainer.GetMnemonic(cryptedMnemonic)) {
        SecureVector vectorMnemonic;

        std::vector<unsigned char> CryptedMnemonic(cryptedMnemonic.begin(), cryptedMnemonic.end());
        if (!CryptedMnemonic.empty() && !DecryptMnemonicSecret(CryptedMnemonic, id, vectorMnemonic))
            return false;

        if (!mnContainer.SetMnemonic(vectorMnemonic))
            return false;
    }

    mnContainer.SetCrypted(false);

    return true;
}

int64_t CWalletTx::GetTxTime() const {
    int64_t n = nTimeSmart;
    return n ? n : nTimeReceived;
}

int CWalletTx::GetRequestCount() const
{
    // Returns -1 if it wasn't being tracked
    int nRequests = -1;
    {
        LOCK(pwallet->cs_wallet);
        if (IsCoinBase())
        {
            // Generated block
            if (!hashUnset())
            {
                std::map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(hashBlock);
                if (mi != pwallet->mapRequestCount.end())
                    nRequests = (*mi).second;
            }
        }
        else
        {
            // Did anyone request this transaction?
            std::map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(GetHash());
            if (mi != pwallet->mapRequestCount.end())
            {
                nRequests = (*mi).second;

                // How about the block it's in?
                if (nRequests == 0 && !hashUnset())
                {
                    std::map<uint256, int>::const_iterator _mi = pwallet->mapRequestCount.find(hashBlock);
                    if (_mi != pwallet->mapRequestCount.end())
                        nRequests = (*_mi).second;
                    else
                        nRequests = 1; // If it's in someone else's block it must have got out
                }
            }
        }
    }
    return nRequests;
}

void CWalletTx::GetAmounts(std::list<COutputEntry>& listReceived,
                           std::list<COutputEntry>& listSent, CAmount& nFee, std::string& strSentAccount, const isminefilter& filter) const
{
    nFee = 0;
    listReceived.clear();
    listSent.clear();
    strSentAccount = strFromAccount;

    // Compute fee:
    CAmount nDebit = GetDebit(filter);
    if (nDebit > 0) // debit>0 means we signed/sent this transaction
    {
        if (!tx->IsLelantusJoinSplit()) {
            CAmount nValueOut = tx->GetValueOut();
            nFee = nDebit - nValueOut;
        }
        else
            nFee = lelantus::ParseLelantusJoinSplit(tx->vin[0])->getFee();
    }

    // Sent/received.
    for (unsigned int i = 0; i < tx->vout.size(); ++i)
    {
        const CTxOut& txout = tx->vout[i];
        isminetype fIsMine = pwallet->IsMine(txout);
        // Only need to handle txouts if AT LEAST one of these is true:
        //   1) they debit from us (sent)
        //   2) the output is to us (received)
        if (nDebit > 0)
        {
            // Don't report 'change' txouts
            if (IsChange(static_cast<uint32_t>(i)))
                continue;
        }
        else if (!(fIsMine & filter))
            continue;

        // In either case, we need to get the destination address
        CTxDestination address;

        if (txout.scriptPubKey.IsZerocoinMint() || txout.scriptPubKey.IsSigmaMint() || txout.scriptPubKey.IsLelantusMint() || txout.scriptPubKey.IsLelantusJMint())
        {
            address = CNoDestination();
        }
        else if (!ExtractDestination(txout.scriptPubKey, address) && !txout.scriptPubKey.IsUnspendable())
        {
            LogPrintf("CWalletTx::GetAmounts: Unknown transaction type found, txid %s\n",
                     this->GetHash().ToString());
            address = CNoDestination();
        }

        CAmount nValue;
        if(txout.scriptPubKey.IsLelantusJMint()) {
            LOCK(pwalletMain->cs_wallet);
            nValue = pwallet->GetCredit(txout, ISMINE_SPENDABLE);
        } else {
            nValue = txout.nValue;
        }

        COutputEntry output = {address, nValue, (int)i};

        // If we are debited by the transaction, add the output as a "sent" entry
        if (nDebit > 0)
            listSent.push_back(output);

        // If we are receiving the output, add it as a "received" entry
        if (fIsMine & filter)
            listReceived.push_back(output);
    }

}

/**
 * Scan the block chain (starting in pindexStart) for transactions
 * from or to us. If fUpdate is true, found transactions that already
 * exist in the wallet will be updated.
 *
 * Returns pointer to the first block in the last contiguous range that was
 * successfully scanned.
 *
 */
CBlockIndex* CWallet::ScanForWalletTransactions(CBlockIndex *pindexStart, bool fUpdate, bool fRecoverMnemonic)
{
    CBlockIndex* ret = nullptr;
    int64_t nNow = GetTime();
    const CChainParams& chainParams = Params();

    CBlockIndex* pindex = pindexStart;
    {
        LOCK2(cs_main, cs_wallet);

        // no need to read and scan block, if block was created before
        // our wallet birthday (as adjusted for block time variability)
        // if you are recovering wallet with mnemonics start rescan from block when mnemonics implemented in Firo
        if (fRecoverMnemonic) {
            pindex = chainActive[chainParams.GetConsensus().nMnemonicBlock];
            if (pindex == NULL)
                pindex = chainActive.Tip();
        } else
            while (pindex && nTimeFirstKey && (pindex->GetBlockTime() < (nTimeFirstKey - 7200)))
                pindex = chainActive.Next(pindex);

        ShowProgress(_("Rescanning..."), 0); // show rescan progress in GUI as dialog or on splashscreen, if -rescan on startup
        double dProgressStart = GuessVerificationProgress(chainParams.TxData(), pindex);
        double dProgressTip = GuessVerificationProgress(chainParams.TxData(), chainActive.Tip());
        while (pindex)
        {
            // A temporary fix for inability to Ctrl-C rescan when restoring a wallet (will be fixed in 0.15.)
            if (ShutdownRequested())
                return nullptr;
            if (pindex->nHeight % 100 == 0 && dProgressTip - dProgressStart > 0.0)
                ShowProgress(_("Rescanning..."), std::max(1, std::min(99, (int)((GuessVerificationProgress(chainParams.TxData(), pindex) - dProgressStart) / (dProgressTip - dProgressStart) * 100))));
            if (GetTime() >= nNow + 60) {
                nNow = GetTime();
                LogPrintf("Still rescanning. At block %d. Progress=%f\n", pindex->nHeight, GuessVerificationProgress(chainParams.TxData(), pindex));
            }

            CBlock block;
            if (ReadBlockFromDisk(block, pindex, Params().GetConsensus())) {
                for (size_t posInBlock = 0; posInBlock < block.vtx.size(); ++posInBlock) {
                    AddToWalletIfInvolvingMe(*block.vtx[posInBlock], pindex, posInBlock, fUpdate);
                }
                if (!ret) {
                    ret = pindex;
                }
            } else {
                ret = nullptr;
            }
            pindex = chainActive.Next(pindex);
        }
        ShowProgress(_("Rescanning..."), 100); // hide progress dialog in GUI
    }
    return ret;
}

void CWallet::ReacceptWalletTransactions()
{
    // If transactions aren't being broadcasted, don't let them into local mempool either
    if (!fBroadcastTransactions)
        return;
    LOCK2(cs_main, cs_wallet);
    std::map<int64_t, CWalletTx*> mapSorted;

    // Sort pending wallet transactions based on their initial wallet insertion order
    BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
    {
        const uint256& wtxid = item.first;
        CWalletTx& wtx = item.second;
        assert(wtx.GetHash() == wtxid);

        int nDepth = wtx.GetDepthInMainChain();

        if (!wtx.IsCoinBase() && (nDepth == 0 && !wtx.isAbandoned())) {
            mapSorted.insert(std::make_pair(wtx.nOrderPos, &wtx));
        }
    }

    // Try to add wallet transactions to memory pool
    BOOST_FOREACH(PAIRTYPE(const int64_t, CWalletTx*)& item, mapSorted)
    {
        CWalletTx& wtx = *(item.second);
        CValidationState state;
        // the app was closed and re-opened, do NOT check their
        // serial numbers, and DO NOT try to mark their serial numbers
        // a second time. We assume those operations were already done.
        wtx.AcceptToMemoryPool(maxTxFee, state);
        // If Dandelion enabled, relay transaction once again.
        if (GetBoolArg("-dandelion", true)) {
            wtx.RelayWalletTransaction(g_connman.get());
        }
    }
}

bool CWalletTx::RelayWalletTransaction(CConnman* connman)
{
    assert(pwallet->GetBroadcastTransactions());
    if (!IsCoinBase() && !isAbandoned() && GetDepthInMainChain() == 0)
    {
        CValidationState state;
        /* GetDepthInMainChain already catches known conflicts. */
        if (InMempool() || InStempool() || AcceptToMemoryPool(maxTxFee, state))
        {
            // If Dandelion enabled, push inventory item to just one destination.
            if (GetBoolArg("-dandelion", true)) {
                int64_t nCurrTime = GetTimeMicros();
                int64_t nEmbargo = 1000000 * DANDELION_EMBARGO_MINIMUM
                        + PoissonNextSend(nCurrTime, DANDELION_EMBARGO_AVG_ADD);
                CNode::insertDandelionEmbargo(GetHash(), nEmbargo);
                CInv inv(MSG_DANDELION_TX, GetHash());
                return CNode::localDandelionDestinationPushInventory(inv);
            }
            else {
                // LogPrintf("Relaying wtx %s\n", GetHash().ToString());
                if (connman) {
                    connman->RelayTransaction(*this);
                    return true;
                }
            }
        }
    }
    LogPrintf("CWalletTx::RelayWalletTransaction() --> invalid condition\n");
    return false;
}

std::set<uint256> CWalletTx::GetConflicts() const
{
    std::set<uint256> result;
    if (pwallet != NULL)
    {
        uint256 myHash = GetHash();
        result = pwallet->GetConflicts(myHash);
        result.erase(myHash);
    }
    return result;
}

CAmount CWalletTx::GetDebit(const isminefilter& filter) const
{
    if (tx->vin.empty())
        return 0;

    CAmount debit = 0;
    if(filter & ISMINE_SPENDABLE)
    {
        if (fDebitCached)
            debit += nDebitCached;
        else
        {
            nDebitCached = pwallet->GetDebit(*this, ISMINE_SPENDABLE);
            fDebitCached = true;
            debit += nDebitCached;
        }
    }
    if(filter & ISMINE_WATCH_ONLY)
    {
        if(fWatchDebitCached)
            debit += nWatchDebitCached;
        else
        {
            nWatchDebitCached = pwallet->GetDebit(*this, ISMINE_WATCH_ONLY);
            fWatchDebitCached = true;
            debit += nWatchDebitCached;
        }
    }
    return debit;
}

CAmount CWalletTx::GetCredit(const isminefilter& filter) const
{
    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (IsCoinBase() && GetBlocksToMaturity() > 0)
        return 0;

    CAmount credit = 0;
    if (filter & ISMINE_SPENDABLE)
    {
        // GetBalance can assume transactions in mapWallet won't change
        if (fCreditCached)
            credit += nCreditCached;
        else
        {
            nCreditCached = pwallet->GetCredit(*this, ISMINE_SPENDABLE);
            fCreditCached = true;
            credit += nCreditCached;
        }
    }
    if (filter & ISMINE_WATCH_ONLY)
    {
        if (fWatchCreditCached)
            credit += nWatchCreditCached;
        else
        {
            nWatchCreditCached = pwallet->GetCredit(*this, ISMINE_WATCH_ONLY);
            fWatchCreditCached = true;
            credit += nWatchCreditCached;
        }
    }
    return credit;
}

CAmount CWalletTx::GetImmatureCredit(bool fUseCache) const
{
    if (IsCoinBase() && GetBlocksToMaturity() > 0 && IsInMainChain())
    {
        if (fUseCache && fImmatureCreditCached)
            return nImmatureCreditCached;
        nImmatureCreditCached = pwallet->GetCredit(*this, ISMINE_SPENDABLE);
        fImmatureCreditCached = true;
        return nImmatureCreditCached;
    }

    return 0;
}

CAmount CWalletTx::GetAvailableCredit(bool fUseCache, bool fExcludeLocked) const {
    if (pwallet == 0)
        return 0;

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (IsCoinBase() && GetBlocksToMaturity() > 0)
        return 0;

    // We cannot use cache if vout contains mints due to it will not update when it spend
    if (fUseCache && fAvailableCreditCached && !tx->IsZerocoinMint() && !tx->IsSigmaMint() && !tx->IsLelantusMint() && !fExcludeLocked)
        return nAvailableCreditCached;

    CAmount nCredit = 0;
    uint256 hashTx = GetHash();
    for (unsigned int i = 0; i < tx->vout.size(); i++)
    {
        if (!pwallet->IsSpent(hashTx, i))
        {
            const CTxOut &txout = tx->vout[i];
            bool isPrivate = txout.scriptPubKey.IsZerocoinMint() || txout.scriptPubKey.IsSigmaMint() || txout.scriptPubKey.IsLelantusMint() || txout.scriptPubKey.IsLelantusJMint();
            bool condition = isPrivate;
            if (fExcludeLocked)
                condition = (isPrivate || pwallet->IsLockedCoin(hashTx, i));
            nCredit += condition ? 0 : pwallet->GetCredit(txout, ISMINE_SPENDABLE);
            if (!MoneyRange(nCredit))
                throw std::runtime_error("CWalletTx::GetAvailableCredit() : value out of range");
        }
    }

    nAvailableCreditCached = nCredit;
    fAvailableCreditCached = true;

    if (fExcludeLocked)
        fAvailableCreditCached = false;

    return nCredit;
}

CAmount CWalletTx::GetImmatureWatchOnlyCredit(const bool& fUseCache) const
{
    if (IsCoinBase() && GetBlocksToMaturity() > 0 && IsInMainChain())
    {
        if (fUseCache && fImmatureWatchCreditCached)
            return nImmatureWatchCreditCached;
        nImmatureWatchCreditCached = pwallet->GetCredit(*this, ISMINE_WATCH_ONLY);
        fImmatureWatchCreditCached = true;
        return nImmatureWatchCreditCached;
    }

    return 0;
}

CAmount CWalletTx::GetAvailableWatchOnlyCredit(const bool& fUseCache) const
{
    if (pwallet == 0)
        return 0;

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (IsCoinBase() && GetBlocksToMaturity() > 0)
        return 0;

    if (fUseCache && fAvailableWatchCreditCached)
        return nAvailableWatchCreditCached;

    CAmount nCredit = 0;
    for (unsigned int i = 0; i < tx->vout.size(); i++)
    {
        if (!pwallet->IsSpent(GetHash(), i))
        {
            const CTxOut &txout = tx->vout[i];
            nCredit += pwallet->GetCredit(txout, ISMINE_WATCH_ONLY);
            if (!MoneyRange(nCredit))
                throw std::runtime_error("CWalletTx::GetAvailableCredit() : value out of range");
        }
    }

    nAvailableWatchCreditCached = nCredit;
    fAvailableWatchCreditCached = true;
    return nCredit;
}

CAmount CWalletTx::GetChange() const
{
    if (fChangeCached)
        return nChangeCached;
    nChangeCached = pwallet->GetChange(*this);
    fChangeCached = true;
    return nChangeCached;
}

bool CWalletTx::InMempool() const
{
    LOCK(mempool.cs);
    if (mempool.exists(GetHash())) {
        return true;
    }
    return false;
}

bool CWalletTx::InStempool() const
{
    if (txpools.getStemTxPool().exists(GetHash())) {
        return true;
    }
    return false;
}

bool CWalletTx::IsTrusted() const
{
    // Quick answer in most cases.
    // Zerocoin spend is always false due to it use nSequence incorrectly.
    if (!tx->IsZerocoinSpend() && !CheckFinalTx(*this))
        return false;
    int nDepth = GetDepthInMainChain();
    if (nDepth >= 1)
        return true;
    if (nDepth < 0)
        return false;
    if (!bSpendZeroConfChange || !IsFromMe(ISMINE_ALL)) // using wtx's cached debit
        return false;

    // Don't trust unconfirmed transactions from us unless they are in the mempool.
    if (!InMempool() && !InStempool())
        return false;

    // Trusted if all inputs are from us and are in the mempool:
    BOOST_FOREACH(const CTxIn& txin, tx->vin)
    {
        if (txin.IsZerocoinSpend() || txin.IsSigmaSpend() || txin.IsZerocoinRemint() || txin.IsLelantusJoinSplit()) {
            if (!(pwallet->IsMine(txin) & ISMINE_SPENDABLE)) {
                return false;
            }
        } else {
            // Transactions not sent by us: not trusted
            const CWalletTx *parent = pwallet->GetWalletTx(txin.prevout.hash);
            if (parent == NULL)
                return false;
            const CTxOut &parentOut = parent->tx->vout[txin.prevout.n];
            if (pwallet->IsMine(parentOut) != ISMINE_SPENDABLE)
                return false;
        }
    }

    return true;
}

bool CWalletTx::IsChange(uint32_t out) const {
    if (out >= tx->vout.size()) {
        throw std::invalid_argument("The specified output index is not valid");
    }

    if (changes.count(out)) {
        return true;
    }

    // Legacy transaction handling.
    // Zerocoin spend have one special output mode to spend to yourself with change address,
    // we don't want to identify that output as change.
    if (!tx->IsZerocoinSpend() && ::IsMine(*pwallet, tx->vout[out].scriptPubKey)) {
        CTxDestination address;
        if (!ExtractDestination(tx->vout[out].scriptPubKey, address)) {
            return true;
        }

        LOCK(pwallet->cs_wallet);
        if (!pwallet->mapAddressBook.count(address)) {
            return true;
        }
    }

    return false;
}

bool CWalletTx::IsChange(const CTxOut& out) const {
    auto it = std::find(tx->vout.begin(), tx->vout.end(), out);
    if (it == tx->vout.end()) {
        throw std::invalid_argument("The specified output does not belong to the transaction");
    }

    return IsChange(it - tx->vout.begin());
}

bool CWalletTx::IsEquivalentTo(const CWalletTx& _tx) const
{
        CMutableTransaction tx1 = *this->tx;
        CMutableTransaction tx2 = *_tx.tx;
        for (unsigned int i = 0; i < tx1.vin.size(); i++) tx1.vin[i].scriptSig = CScript();
        for (unsigned int i = 0; i < tx2.vin.size(); i++) tx2.vin[i].scriptSig = CScript();
        return CTransaction(tx1) == CTransaction(tx2);
}

std::vector<uint256> CWallet::ResendWalletTransactionsBefore(int64_t nTime, CConnman* connman)
{
    std::vector<uint256> result;

    LOCK(cs_wallet);
    // Sort them in chronological order
    std::multimap<unsigned int, CWalletTx*> mapSorted;
    BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
    {
        CWalletTx& wtx = item.second;
        // Don't rebroadcast if newer than nTime:
        if (wtx.nTimeReceived > nTime)
            continue;
        mapSorted.insert(std::make_pair(wtx.nTimeReceived, &wtx));
    }
    BOOST_FOREACH(PAIRTYPE(const unsigned int, CWalletTx*)& item, mapSorted)
    {
        CWalletTx& wtx = *item.second;
        if (wtx.RelayWalletTransaction(connman))
            result.push_back(wtx.GetHash());
    }
    return result;
}

void CWallet::ResendWalletTransactions(int64_t nBestBlockTime, CConnman* connman)
{
    // Do this infrequently and randomly to avoid giving away
    // that these are our transactions.
    if (GetTime() < nNextResend || !fBroadcastTransactions)
        return;
    bool fFirst = (nNextResend == 0);
    nNextResend = GetTime() + GetRand(30 * 60);
    if (fFirst)
        return;

    // Only do it if there's been a new block since last time
    if (nBestBlockTime < nLastResend)
        return;
    nLastResend = GetTime();

    // Rebroadcast unconfirmed txes older than 5 minutes before the last
    // block was found:
    std::vector<uint256> relayed = ResendWalletTransactionsBefore(nBestBlockTime-5*60, connman);
    if (!relayed.empty())
        LogPrintf("%s: rebroadcast %u unconfirmed transactions\n", __func__, relayed.size());
}

/** @} */ // end of mapWallet




/** @defgroup Actions
 *
 * @{
 */


CAmount CWallet::GetBalance(bool fExcludeLocked) const
{
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (std::map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if (pcoin->IsTrusted())
                nTotal += pcoin->GetAvailableCredit(true, fExcludeLocked);
        }
    }

    return nTotal;
}

std::pair<CAmount, CAmount> CWallet::GetPrivateBalance() const
{
    size_t confirmed, unconfirmed;
    return GetPrivateBalance(confirmed, unconfirmed);
}

std::pair<CAmount, CAmount> CWallet::GetPrivateBalance(size_t &confirmed, size_t &unconfirmed) const
{
    std::pair<CAmount, CAmount> balance = {0, 0};

    confirmed = 0;
    unconfirmed = 0;

    auto zwallet = pwalletMain->zwallet.get();

    if(!zwallet)
        return balance;

    auto lelantusCoins = zwallet->GetTracker().ListLelantusMints(true, false, false);
    for (auto const &c : lelantusCoins) {

        if (c.isUsed || c.isArchived || !c.isSeedCorrect) {
            continue;
        }

        auto conf = c.nHeight > 0
            ? chainActive.Height() - c.nHeight + 1 : 0;

        if (conf >= ZC_MINT_CONFIRMATIONS) {
            confirmed++;
            balance.first += c.amount;
        } else {
            unconfirmed++;
            balance.second += c.amount;
        }
    }

    auto sigmaCoins = zwallet->GetTracker().ListMints(true, false, false);
    for (auto const &c : sigmaCoins) {

        if (c.isUsed || c.isArchived || !c.isSeedCorrect) {
            continue;
        }

        CAmount amount;
        if (!sigma::DenominationToInteger(c.denom, amount)) {
            throw std::runtime_error("Fail to get denomination value");
        }

        auto conf = c.nHeight > 0
            ? chainActive.Height() - c.nHeight + 1 : 0;

        if (conf >= ZC_MINT_CONFIRMATIONS) {
            confirmed++;
            balance.first += amount;
        } else {
            unconfirmed++;
            balance.second += amount;
        }
    }

    return balance;
}

std::vector<CRecipient> CWallet::CreateSigmaMintRecipients(
    std::vector<sigma::PrivateCoin>& coins,
    std::vector<CHDMint>& vDMints)
{
    EnsureMintWalletAvailable();

    std::vector<CRecipient> vecSend;
    CWalletDB walletdb(pwalletMain->strWalletFile);

    std::transform(coins.begin(), coins.end(), std::back_inserter(vecSend),
        [&vDMints, &walletdb](sigma::PrivateCoin& coin) -> CRecipient {

            // Generate and store secrets deterministically in the following function.
            CHDMint dMint;
            pwalletMain->zwallet->GenerateMint(walletdb, coin.getPublicCoin().getDenomination(), coin, dMint);


            // Get a copy of the 'public' portion of the coin. You should
            // embed this into a Signa 'MINT' transaction along with a series
            // of currency inputs totaling the assigned value of one sigma.
            auto& pubCoin = coin.getPublicCoin();

            if (!pubCoin.validate()) {
                throw std::runtime_error("Unable to mint a sigma coin.");
            }

            // Create script for coin
            CScript scriptSerializedCoin;
            // opcode is inserted as 1 byte according to file script/script.h
            scriptSerializedCoin << OP_SIGMAMINT;

            // and this one will write the size in different byte lengths depending on the length of vector. If vector size is <0.4c, which is 76, will write the size of vector in just 1 byte. In our case the size is always 34, so must write that 34 in 1 byte.
            std::vector<unsigned char> vch = pubCoin.getValue().getvch();
            scriptSerializedCoin.insert(scriptSerializedCoin.end(), vch.begin(), vch.end());

            CAmount v;
            DenominationToInteger(pubCoin.getDenomination(), v);

            vDMints.push_back(dMint);

            return {scriptSerializedCoin, v, false};
        }
    );

    return vecSend;
}

CRecipient CWallet::CreateLelantusMintRecipient(
        lelantus::PrivateCoin& coin,
        CHDMint& vDMint,
        bool generate)
{
    EnsureMintWalletAvailable();

    while (true) {
        CWalletDB walletdb(pwalletMain->strWalletFile);
        uint160 seedID;
        if (generate) {
            // Generate and store secrets deterministically in the following function.
            pwalletMain->zwallet->GenerateLelantusMint(walletdb, coin, vDMint, seedID);
        }

        // Get a copy of the 'public' portion of the coin. You should
        // embed this into a Lelantus 'MINT' transaction along with a series of currency inputs
        auto &pubCoin = coin.getPublicCoin();

        if (!pubCoin.validate()) {
            throw std::runtime_error("Unable to mint a lelantus coin.");
        }

        // Create script for coin
        CScript script;
        // opcode is inserted as 1 byte according to file script/script.h
        script << OP_LELANTUSMINT;

        // and this one will write the size in different byte lengths depending on the length of vector. If vector size is <0.4c, which is 76, will write the size of vector in just 1 byte. In our case the size is always 34, so must write that 34 in 1 byte.
        std::vector<unsigned char> vch = pubCoin.getValue().getvch();
        script.insert(script.end(), vch.begin(), vch.end()); //this uses 34 byte

        // generating schnorr proof
        CDataStream serializedSchnorrProof(SER_NETWORK, PROTOCOL_VERSION);
        lelantus::GenerateMintSchnorrProof(coin, serializedSchnorrProof);
        script.insert(script.end(), serializedSchnorrProof.begin(), serializedSchnorrProof.end()); //this uses 98 byte

        auto pubcoin = vDMint.GetPubcoinValue() +
                       lelantus::Params::get_default()->get_h1() * Scalar(vDMint.GetAmount()).negate();
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
        script.insert(script.end(), serializedHash.begin(), serializedHash.end());

        // overall Lelantus mint script size is 1 + 34 + 98 + 32 = 165 byte
        return {script, CAmount(coin.getV()), false};
    }
}

// coinsIn has to be sorted in descending order.
int CWallet::GetRequiredCoinCountForAmount(
        const CAmount& required,
        const std::vector<sigma::CoinDenomination>& denominations) {
    CAmount val = required;
    int result = 0;
    for (std::size_t i = 0; i < denominations.size(); i++)
    {
        CAmount denom;
        DenominationToInteger(denominations[i], denom);
        while (val >= denom) {
            val -= denom;
            result++;
        }
    }

    return result;
}

/** \brief denominations has to be sorted in descending order. Each denomination can be used multiple times.
 *
 *  \returns The amount which was possible to actually mint.
 */
CAmount CWallet::SelectMintCoinsForAmount(
        const CAmount& required,
        const std::vector<sigma::CoinDenomination>& denominations,
        std::vector<sigma::CoinDenomination>& coinsOut) {
    CAmount val = required;
    for (std::size_t i = 0; i < denominations.size(); i++)
    {
        CAmount denom;
        DenominationToInteger(denominations[i], denom);
        while (val >= denom)
        {
            val -= denom;
            coinsOut.push_back(denominations[i]);
        }
    }

    return required - val;
}

/** \brief coinsIn has to be sorted in descending order. Each coin can be used only once.
 *
 *  \returns The amount which was possible to actually spend.
 */
CAmount CWallet::SelectSpendCoinsForAmount(
        const CAmount& required,
        const std::list<CSigmaEntry>& coinsIn,
        std::vector<CSigmaEntry>& coinsOut) {
    CAmount val = required;
    for (auto coinIt = coinsIn.begin(); coinIt != coinsIn.end(); coinIt++)
    {
        if (coinIt->IsUsed)
          continue;
        CAmount denom = coinIt->get_denomination_value();
        if (val >= denom)
        {
            val -= denom;
            coinsOut.push_back(*coinIt);
        }
    }

    return required - val;
}

// Calculate total balance in a different way from GetBalance. The biggest
// difference is that GetBalance sums up all unspent TxOuts paying to the
// wallet, while this sums up both spent and unspent TxOuts paying to the
// wallet, and then subtracts the values of TxIns spending from the wallet. This
// also has fewer restrictions on which unconfirmed transactions are considered
// trusted.
CAmount CWallet::GetLegacyBalance(const isminefilter& filter, int minDepth, const std::string* account) const
{
    LOCK2(cs_main, cs_wallet);

    CAmount balance = 0;
    for (const auto& entry : mapWallet) {
        const CWalletTx& wtx = entry.second;
        const int depth = wtx.GetDepthInMainChain();
        if (depth < 0 || !CheckFinalTx(*wtx.tx) || wtx.GetBlocksToMaturity() > 0) {
            continue;
        }

        // Loop through tx outputs and add incoming payments. For outgoing txs,
        // treat change outputs specially, as part of the amount debited.
        CAmount debit = wtx.GetDebit(filter);
        const bool outgoing = debit > 0;
        for (const CTxOut& out : wtx.tx->vout) {
            if (outgoing && IsChange(wtx.tx->GetHash(), out)) {
                debit -= out.nValue;
            } else if (IsMine(out) & filter && depth >= minDepth && (!account || *account == GetAccountName(out.scriptPubKey))) {
                balance += out.nValue;
            }
        }

        // For outgoing txs, subtract amount debited.
        if (outgoing && (!account || *account == wtx.strFromAccount)) {
            balance -= debit;
        }
    }

    if (account) {
        balance += CWalletDB(strWalletFile).GetAccountCreditDebit(*account);
    }

    return balance;
}

std::list<CSigmaEntry> CWallet::GetAvailableCoins(const CCoinControl *coinControl, bool includeUnsafe, bool forEstimation) const {
    EnsureMintWalletAvailable();
    LOCK2(cs_main, cs_wallet);
    CWalletDB walletdb(strWalletFile);
    std::list<CSigmaEntry> coins;
    std::vector<CMintMeta> vecMints = zwallet->GetTracker().ListMints(true, true, false);
    std::list<CMintMeta> listMints(vecMints.begin(), vecMints.end());
    for (const CMintMeta& mint : listMints) {
        CSigmaEntry entry;
        GetMint(mint.hashSerial, entry, forEstimation);
        coins.push_back(entry);
    }

    std::set<COutPoint> lockedCoins = setLockedCoins;

    // Filter out coins which are not confirmed, I.E. do not have at least 2 blocks
    // above them, after they were minted.
    // Also filter out used coins.
    // Finally filter out coins that have not been selected from CoinControl should that be used
    coins.remove_if([lockedCoins, coinControl, includeUnsafe](const CSigmaEntry& coin) {
        sigma::CSigmaState* sigmaState = sigma::CSigmaState::GetState();
        if (coin.IsUsed)
            return true;

        int coinHeight, coinId;
        std::tie(coinHeight, coinId) =  sigmaState->GetMintedCoinHeightAndId(
            sigma::PublicCoin(coin.value, coin.get_denomination()));

        // Check group size
        uint256 hashOut;
        std::vector<sigma::PublicCoin> coinOuts;
        sigmaState->GetCoinSetForSpend(
            &chainActive,
            chainActive.Height() - (ZC_MINT_CONFIRMATIONS - 1), // required 2 confirmation for mint to spend
            coin.get_denomination(),
            coinId,
            hashOut,
            coinOuts
        );

        if (!includeUnsafe && coinOuts.size() < 2) {
            return true;
        }

        if (coinHeight == -1) {
            // Coin still in the mempool.
            return true;
        }

        if (coinHeight + (ZC_MINT_CONFIRMATIONS - 1) > chainActive.Height()) {
            // Remove the coin from the candidates list, since it does not have the
            // required number of confirmations.
            return true;
        }

        COutPoint outPoint;
        sigma::PublicCoin pubCoin(coin.value, coin.get_denomination());
        sigma::GetOutPoint(outPoint, pubCoin);

        if(lockedCoins.count(outPoint) > 0){
            return true;
        }

        if(coinControl != NULL){
            if(coinControl->HasSelected()){
                if(!coinControl->IsSelected(outPoint)){
                    return true;
                }
            }
        }

        return false;
    });

    return coins;
}

std::list<CLelantusEntry> CWallet::GetAvailableLelantusCoins(const CCoinControl *coinControl, bool includeUnsafe, bool forEstimation) const {
    EnsureMintWalletAvailable();

    LOCK2(cs_main, cs_wallet);
    CWalletDB walletdb(strWalletFile);
    std::list<CLelantusEntry> coins;
    std::vector<CLelantusMintMeta> vecMints = zwallet->GetTracker().ListLelantusMints(true, true, false);
    for (const CLelantusMintMeta& mint : vecMints) {
        CLelantusEntry entry;
        GetMint(mint.hashSerial, entry, forEstimation);
        if(entry.amount != 0) // ignore 0 mints which where created to increase privacy
            coins.push_back(entry);
    }

    std::set<COutPoint> lockedCoins = setLockedCoins;

    // Filter out coins which are not confirmed, I.E. do not have at least 2 blocks
    // above them, after they were minted.
    // Also filter out used coins.
    // Finally filter out coins that have not been selected from CoinControl should that be used
    coins.remove_if([lockedCoins, coinControl, includeUnsafe](const CLelantusEntry& coin) {
        lelantus::CLelantusState* state = lelantus::CLelantusState::GetState();
        if (coin.IsUsed)
            return true;

        int coinHeight, coinId;
        std::tie(coinHeight, coinId) =  state->GetMintedCoinHeightAndId(lelantus::PublicCoin(coin.value));

        // Check group size
        uint256 hashOut;
        std::vector<lelantus::PublicCoin> coinOuts;
        std::vector<unsigned char> setHash;
        state->GetCoinSetForSpend(
            &chainActive,
            chainActive.Height() - (ZC_MINT_CONFIRMATIONS - 1), // required 2 confirmation for mint to spend
            coinId,
            hashOut,
            coinOuts,
            setHash
        );

        if (!includeUnsafe && coinOuts.size() < 2) {
            return true;
        }

        if (coinHeight == -1) {
            // Coin still in the mempool.
            return true;
        }

        if (coinHeight + (ZC_MINT_CONFIRMATIONS - 1) > chainActive.Height()) {
            // Remove the coin from the candidates list, since it does not have the
            // required number of confirmations.
            return true;
        }

        COutPoint outPoint;
        lelantus::PublicCoin pubCoin(coin.value);
        lelantus::GetOutPoint(outPoint, pubCoin);

        if(lockedCoins.count(outPoint) > 0){
            return true;
        }

        if(coinControl != NULL){
            if(coinControl->HasSelected()){
                if(!coinControl->IsSelected(outPoint)){
                    return true;
                }
            }
        }

        return false;
    });

    return coins;
}

std::vector<unsigned char> GetAESKey(const secp_primitives::GroupElement& pubcoin) {
    uint32_t keyPath = primitives::GetPubCoinValueHash(pubcoin).GetFirstUint32();
    CKey secret;
    {
        pwalletMain->GetKeyFromKeypath(BIP44_MINT_VALUE_INDEX, keyPath, secret);
    }

    std::vector<unsigned char> result(CHMAC_SHA512::OUTPUT_SIZE);

    CHMAC_SHA512(secret.begin(), secret.size()).Finalize(&result[0]);
    return result;
}

std::vector<unsigned char> CWallet::EncryptMintAmount(uint64_t amount, const secp_primitives::GroupElement& pubcoin) const {
    LOCK(cs_wallet);
    std::vector<unsigned char> key = GetAESKey(pubcoin);
    AES256Encrypt enc(key.data());
    std::vector<unsigned char> ciphertext(16);
    std::vector<unsigned char> plaintext(16);
    memcpy(plaintext.data(), &amount, 8);
    enc.Encrypt(ciphertext.data(), plaintext.data());
    return ciphertext;
}

bool CWallet::DecryptMintAmount(const std::vector<unsigned char>& encryptedValue, const secp_primitives::GroupElement& pubcoin, uint64_t& amount) const {
    if (IsLocked() || hdChain.masterKeyID.IsNull()) {
        amount = 0;
        return true;
    }

    LOCK(cs_wallet);
    std::vector<unsigned char> key = GetAESKey(pubcoin);
    AES256Decrypt dec(key.data());
    std::vector<unsigned char> plaintext(16);
    dec.Decrypt(plaintext.data(), encryptedValue.data());
    memcpy(&amount, plaintext.data(), 8);
    return true;
}


template<typename Iterator>
static CAmount CalculateCoinsBalance(Iterator begin, Iterator end) {
    CAmount balance(0);
    for (auto start = begin; start != end; start++) {
        balance += start->get_denomination_value();
    }
    return balance;
}

template<typename Iterator>
static CAmount CalculateLelantusCoinsBalance(Iterator begin, Iterator end) {
    CAmount balance(0);
    for (auto start = begin; start != end; start++) {
        balance += start->amount;
    }
    return balance;
}

bool CWallet::GetCoinsToSpend(
        CAmount required,
        std::vector<CSigmaEntry>& coinsToSpend_out,
        std::vector<sigma::CoinDenomination>& coinsToMint_out,
        std::list<CSigmaEntry>& coins,
        const size_t coinsToSpendLimit,
        const CAmount amountToSpendLimit,
        const CCoinControl *coinControl) const
{
    // Sanity check to make sure this function is never called with a too large
    // amount to spend, resulting to a possible crash due to out of memory condition.
    if (!MoneyRange(required)) {
        throw std::invalid_argument("Request to spend more than 21 MLN firos.\n");
    }

    if (!MoneyRange(amountToSpendLimit)) {
        throw std::invalid_argument(_("Amount limit is exceed max money"));
    }

    // We have Coins denomination * 10^8, we divide with 0.05 * 10^8 and add one coin of
    // denomination 100 (also divide by 0.05 * 10^8)
    constexpr CAmount zeros(5000000);

    // Rounding, Anything below 0.05 coin goes to the miners as a fee.
    int roundedRequired = required / zeros;
    if (required % zeros != 0) {
        ++roundedRequired;
    }

    int limitVal = amountToSpendLimit / zeros;

    if (roundedRequired > limitVal) {
        throw std::invalid_argument(
            _("Required amount exceed value spend limit"));
    }

    CAmount availableBalance = CalculateCoinsBalance(coins.begin(), coins.end());

    if (roundedRequired * zeros > availableBalance) {
        throw InsufficientFunds();
    }

    // sort by highest denomination. if it is same denomination we will prefer the previous block
    auto comparer = [](const CSigmaEntry& a, const CSigmaEntry& b) -> bool {
        return a.get_denomination_value() != b.get_denomination_value() ? a.get_denomination_value() > b.get_denomination_value() : a.nHeight < b.nHeight;
    };
    coins.sort(comparer);

    std::vector<sigma::CoinDenomination> denominations;
    sigma::GetAllDenoms(denominations);

    // Value of the largest coin, I.E. 100 for now.
    CAmount max_coin_value;
    if (!DenominationToInteger(denominations[0], max_coin_value)) {
        throw std::runtime_error("Unknown sigma denomination.\n");
    }

    int val = roundedRequired + max_coin_value / zeros;

    // val represent max value in range that we will search which may be over limit.
    // then we trim it out because we never use it.
    val = std::min(val, limitVal);

    // We need only last 2 rows of matrix of knapsack algorithm.
    std::vector<uint64_t> prev_row;
    prev_row.resize(val + 1);

    std::vector<uint64_t> next_row(val + 1, (INT_MAX - 1) / 2);

    auto coinIt = coins.rbegin();
    next_row[0] = 0;
    next_row[coinIt->get_denomination_value() / zeros] = 1;
    ++coinIt;

    for (; coinIt != coins.rend(); coinIt++) {
        std::swap(prev_row, next_row);
        CAmount denom_i = coinIt->get_denomination_value() / zeros;
        for (int j = 1; j <= val; j++) {
            next_row[j] = prev_row[j];
            if (j >= denom_i &&  next_row[j] > prev_row[j - denom_i] + 1) {
                    next_row[j] = prev_row[j - denom_i] + 1;
            }
        }
    }

    int index = val;
    uint64_t best_spend_val = 0;

    // If coinControl, want to use all inputs
    bool coinControlUsed = false;
    if(coinControl != NULL){
        if(coinControl->HasSelected()){
            auto coinIt = coins.rbegin();
            for (; coinIt != coins.rend(); coinIt++) {
                best_spend_val += coinIt->get_denomination_value();
            }
            coinControlUsed = true;
        }
    }
    if(!coinControlUsed) {
        best_spend_val = val;
        int minimum = INT_MAX - 1;
        while(index >= roundedRequired) {
            int temp_min = next_row[index] + GetRequiredCoinCountForAmount(
                (index - roundedRequired) * zeros, denominations);
            if (minimum > temp_min && next_row[index] != (INT_MAX - 1) / 2 && next_row[index] <= coinsToSpendLimit) {
                best_spend_val = index;
                minimum = temp_min;
            }
            --index;
        }
        best_spend_val *= zeros;

        if (minimum == INT_MAX - 1)
            throw std::invalid_argument(
                _("Can not choose coins within limit."));
    }

    if (SelectMintCoinsForAmount(best_spend_val - roundedRequired * zeros, denominations, coinsToMint_out) != best_spend_val - roundedRequired * zeros) {
        throw std::invalid_argument(
            _("Problem with coin selection for re-mint while spending."));
    }
    if (SelectSpendCoinsForAmount(best_spend_val, coins, coinsToSpend_out) != best_spend_val) {
        throw std::invalid_argument(
            _("Problem with coin selection for spend."));
    }

    return true;
}

bool CWallet::GetCoinsToJoinSplit(
        CAmount required,
        std::vector<CLelantusEntry>& coinsToSpend_out,
        CAmount& changeToMint,
        std::list<CLelantusEntry> coins,
        const size_t coinsToSpendLimit,
        const CAmount amountToSpendLimit,
        const CCoinControl *coinControl) const
{

    EnsureMintWalletAvailable();
    Consensus::Params consensusParams = Params().GetConsensus();

    if (required > consensusParams.nMaxValueLelantusSpendPerTransaction) {
        throw std::invalid_argument(_("The required amount exceeds spend limit"));
    }

    CAmount availableBalance = CalculateLelantusCoinsBalance(coins.begin(), coins.end());

    if (required > availableBalance) {
        throw InsufficientFunds();
    }

    // sort by biggest amount. if it is same amount we will prefer the older block
    auto comparer = [](const CLelantusEntry& a, const CLelantusEntry& b) -> bool {
        return a.amount != b.amount ? a.amount > b.amount : a.nHeight < b.nHeight;
    };
    coins.sort(comparer);

    CAmount spend_val(0);

    std::list<CLelantusEntry> coinsToSpend;

    // If coinControl, want to use all inputs
    bool coinControlUsed = false;
    if(coinControl != NULL) {
        if(coinControl->HasSelected()) {
            auto coinIt = coins.rbegin();
            for (; coinIt != coins.rend(); coinIt++) {
                spend_val += coinIt->amount;
            }
            coinControlUsed = true;
            coinsToSpend.insert(coinsToSpend.begin(), coins.begin(), coins.end());
        }
    }

    if(!coinControlUsed) {
        while (spend_val < required) {
            if(coins.empty())
                break;

            CLelantusEntry choosen;
            CAmount need = required - spend_val;

            auto itr = coins.begin();
            if(need >= itr->amount) {
                choosen = *itr;
                coins.erase(itr);
            } else {
                for (auto coinIt = coins.rbegin(); coinIt != coins.rend(); coinIt++) {
                    auto nextItr = coinIt;
                    nextItr++;

                    if (coinIt->amount >= need && (nextItr == coins.rend() || nextItr->amount != coinIt->amount)) {
                        choosen = *coinIt;
                        coins.erase(std::next(coinIt).base());
                        break;
                    }
                }
            }

            spend_val += choosen.amount;
            coinsToSpend.push_back(choosen);
        }
    }

    // sort by group id ay ascending order. it is mandatory for creting proper joinsplit
    auto idComparer = [](const CLelantusEntry& a, const CLelantusEntry& b) -> bool {
        return a.id < b.id;
    };
    coinsToSpend.sort(idComparer);

    changeToMint = spend_val - required;
    coinsToSpend_out.insert(coinsToSpend_out.begin(), coinsToSpend.begin(), coinsToSpend.end());

    return true;
}

CAmount CWallet::GetUnconfirmedBalance() const {
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (std::map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx *pcoin = &(*it).second;
            if (!pcoin->IsTrusted() && pcoin->GetDepthInMainChain() == 0 &&
                (pcoin->InMempool() || pcoin->InStempool()))
                nTotal += pcoin->GetAvailableCredit();
        }
    }
    return nTotal;
}

CAmount CWallet::GetImmatureBalance() const {
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (std::map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx *pcoin = &(*it).second;
            nTotal += pcoin->GetImmatureCredit();
        }
    }
    return nTotal;
}

CAmount CWallet::GetWatchOnlyBalance() const {
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (std::map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx *pcoin = &(*it).second;
            if (pcoin->IsTrusted())
                nTotal += pcoin->GetAvailableWatchOnlyCredit();
        }
    }

    return nTotal;
}

CAmount CWallet::GetUnconfirmedWatchOnlyBalance() const {
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (std::map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx *pcoin = &(*it).second;
            if (!pcoin->IsTrusted() && pcoin->GetDepthInMainChain() == 0 &&
                (pcoin->InMempool() || pcoin->InStempool()))
                nTotal += pcoin->GetAvailableWatchOnlyCredit();
        }
    }
    return nTotal;
}

CAmount CWallet::GetImmatureWatchOnlyBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (std::map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            nTotal += pcoin->GetImmatureWatchOnlyCredit();
        }
    }
    return nTotal;
}

void CWallet::AvailableCoins(std::vector <COutput> &vCoins, bool fOnlyConfirmed, const CCoinControl *coinControl, bool fIncludeZeroValue) const
{
    static const int ZNODE_COIN_REQUIRED  = 1000;
    vCoins.clear();
    CoinType nCoinType = coinControl ? coinControl->nCoinType : CoinType::ALL_COINS;

    {
        LOCK2(cs_main, cs_wallet);
        for (std::map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const uint256& wtxid = it->first;
            const CWalletTx* pcoin = &(*it).second;

            if (!CheckFinalTx(*pcoin))
                continue;

            if (fOnlyConfirmed && !pcoin->IsTrusted())
                continue;

            if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity() > 0)
                continue;

            int nDepth = pcoin->GetDepthInMainChain(false);
            // do not use IX for inputs that have less then INSTANTSEND_CONFIRMATIONS_REQUIRED blockchain confirmations
//            if (fUseInstantSend && nDepth < INSTANTSEND_CONFIRMATIONS_REQUIRED)
//                continue;

            // We should not consider coins from transactions that are replacing
            // other transactions.
            //
            // Example: There is a transaction A which is replaced by bumpfee
            // transaction B. In this case, we want to prevent creation of
            // a transaction B' which spends an output of B.
            //
            // Reason: If transaction A were initially confirmed, transactions B
            // and B' would no longer be valid, so the user would have to create
            // a new transaction C to replace B'. However, in the case of a
            // one-block reorg, transactions B' and C might BOTH be accepted,
            // when the user only wanted one of them. Specifically, there could
            // be a 1-block reorg away from the chain where transactions A and C
            // were accepted to another chain where B, B', and C were all
            // accepted.
            if (nDepth == 0 && fOnlyConfirmed && pcoin->mapValue.count("replaces_txid")) {
                continue;
            }

            // Similarly, we should not consider coins from transactions that
            // have been replaced. In the example above, we would want to prevent
            // creation of a transaction A' spending an output of A, because if
            // transaction B were initially confirmed, conflicting with A and
            // A', we wouldn't want to the user to create a transaction D
            // intending to replace A', but potentially resulting in a scenario
            // where A, A', and D could all be accepted (instead of just B and
            // D, or just A and A' like the user would want).
            if (nDepth == 0 && fOnlyConfirmed && pcoin->mapValue.count("replaced_by_txid")) {
                continue;
            }

            for (unsigned int i = 0; i < pcoin->tx->vout.size(); i++) {
                bool found = false;
                if(nCoinType == CoinType::ALL_COINS){
                    // We are now taking ALL_COINS to mean everything sans mints
                    found = !(pcoin->tx->vout[i].scriptPubKey.IsZerocoinMint()
                            || pcoin->tx->vout[i].scriptPubKey.IsSigmaMint()
                            || pcoin->tx->vout[i].scriptPubKey.IsLelantusMint()
                            || pcoin->tx->vout[i].scriptPubKey.IsLelantusJMint())
                            || pcoin->tx->vout[i].scriptPubKey.IsZerocoinRemint();
                } else if(nCoinType == CoinType::ONLY_MINTS){
                    // Do not consider anything other than mints
                    found = (pcoin->tx->vout[i].scriptPubKey.IsZerocoinMint()
                            || pcoin->tx->vout[i].scriptPubKey.IsSigmaMint()
                            || pcoin->tx->vout[i].scriptPubKey.IsZerocoinRemint()
                            || pcoin->tx->vout[i].scriptPubKey.IsLelantusMint()
                            || pcoin->tx->vout[i].scriptPubKey.IsLelantusJMint());
                } else if (nCoinType == CoinType::ONLY_NOT1000IFMN) {
                    found = !(fMasternodeMode && pcoin->tx->vout[i].nValue == ZNODE_COIN_REQUIRED * COIN);
                } else if (nCoinType == CoinType::ONLY_NONDENOMINATED_NOT1000IFMN) {
                    if (fMasternodeMode) found = pcoin->tx->vout[i].nValue != ZNODE_COIN_REQUIRED * COIN; // do not use Hot MN funds
		} else if (nCoinType == CoinType::ONLY_1000) {
                    found = pcoin->tx->vout[i].nValue == ZNODE_COIN_REQUIRED * COIN;
                } else {
                    found = true;
                }
                if (!found) continue;

                isminetype mine = IsMine(pcoin->tx->vout[i]);


                if (!(IsSpent(wtxid, i)) && mine != ISMINE_NO &&
                    (!IsLockedCoin((*it).first, i) || nCoinType == CoinType::ONLY_1000) &&
                    (pcoin->tx->vout[i].nValue > 0 || fIncludeZeroValue || (pcoin->tx->vout[i].scriptPubKey.IsLelantusJMint() && GetCredit(pcoin->tx->vout[i], ISMINE_SPENDABLE) > 0)) &&
                    (!coinControl || !coinControl->HasSelected() || coinControl->fAllowOtherInputs || coinControl->IsSelected(COutPoint((*it).first, i)))) {
                        vCoins.push_back(COutput(pcoin, i, nDepth,
                                                 ((mine & ISMINE_SPENDABLE) != ISMINE_NO) ||
                                                  (coinControl && coinControl->fAllowWatchOnly && (mine & ISMINE_WATCH_SOLVABLE) != ISMINE_NO),
                                                 (mine & (ISMINE_SPENDABLE | ISMINE_WATCH_SOLVABLE)) != ISMINE_NO));
                }
            }
        }
    }
}

void CWallet::AvailableCoinsForLMint(std::vector<std::pair<CAmount, std::vector<COutput>>>& valueAndUTXO, const CCoinControl *coinControl) const
{
    valueAndUTXO.clear();
    std::vector<COutput> vAvailableCoins;
    AvailableCoins(vAvailableCoins, true, coinControl);

    std::map<CTxDestination, std::pair<CAmount, std::vector<COutput>>> mapAddrToUTXO;
    for(const auto& coin : vAvailableCoins)
    {
        CTxDestination address;
        const auto& scriptPubKey = coin.tx->tx->vout[coin.i].scriptPubKey;

        if (!ExtractDestination(scriptPubKey, address) && !scriptPubKey.IsUnspendable())
            continue;

        auto& element = mapAddrToUTXO[address];
        if(element.second.empty())
            element.first = coin.tx->tx->vout[coin.i].nValue;
        else
            element.first += coin.tx->tx->vout[coin.i].nValue;
        element.second.push_back(coin);
    }

    valueAndUTXO.reserve(mapAddrToUTXO.size());
    for(const auto& element : mapAddrToUTXO)
        valueAndUTXO.emplace_back(element.second);

    std::sort(valueAndUTXO.begin(), valueAndUTXO.end(), [](const std::pair<CAmount,std::vector<COutput>> &left, const std::pair<CAmount,std::vector<COutput>> &right) {
        return left.first > right.first;
    });

}

bool CWallet::GetZnodeVinAndKeys(CTxIn &txinRet, CPubKey &pubKeyRet, CKey &keyRet, std::string strTxHash,
                                 std::string strOutputIndex) {
    // wait for reindex and/or import to finish
    if (fImporting || fReindex) return false;

    // Find possible candidates
    std::vector <COutput> vPossibleCoins;
    CCoinControl coinControl;
    coinControl.nCoinType = CoinType::ONLY_1000;
    AvailableCoins(vPossibleCoins, true, &coinControl, false);
    if (vPossibleCoins.empty()) {
        LogPrintf("CWallet::GetZnodeVinAndKeys -- Could not locate any valid znode vin\n");
        return false;
    }

    if (strTxHash.empty()) // No output specified, select the first one
        return GetVinAndKeysFromOutput(vPossibleCoins[0], txinRet, pubKeyRet, keyRet);

    // Find specific vin
    uint256 txHash = uint256S(strTxHash);
    int nOutputIndex = atoi(strOutputIndex.c_str());

    BOOST_FOREACH(COutput & out, vPossibleCoins)
    if (out.tx->GetHash() == txHash && out.i == nOutputIndex) // found it!
        return GetVinAndKeysFromOutput(out, txinRet, pubKeyRet, keyRet);

    LogPrintf("CWallet::GetZnodeVinAndKeys -- Could not locate specified znode vin\n");
    return false;
}

bool CWallet::GetVinAndKeysFromOutput(COutput out, CTxIn &txinRet, CPubKey &pubKeyRet, CKey &keyRet) {
    // wait for reindex and/or import to finish
    if (fImporting || fReindex) return false;

    CScript pubScript;

    txinRet = CTxIn(out.tx->GetHash(), out.i);
    pubScript = out.tx->tx->vout[out.i].scriptPubKey; // the inputs PubKey

    CTxDestination address1;
    ExtractDestination(pubScript, address1);
    CBitcoinAddress address2(address1);

    CKeyID keyID;
    if (!address2.GetKeyID(keyID)) {
        LogPrintf("CWallet::GetVinAndKeysFromOutput -- Address does not refer to a key\n");
        return false;
    }

    if (!GetKey(keyID, keyRet)) {
        LogPrintf("CWallet::GetVinAndKeysFromOutput -- Private key for address is not known\n");
        return false;
    }

    pubKeyRet = keyRet.GetPubKey();
    return true;
}

//[firo]
void CWallet::ListAvailableSigmaMintCoins(std::vector<COutput> &vCoins, bool fOnlyConfirmed) const {
    EnsureMintWalletAvailable();

    vCoins.clear();
    LOCK2(cs_main, cs_wallet);
    std::list<CSigmaEntry> listOwnCoins;
    CWalletDB walletdb(pwalletMain->strWalletFile);
    listOwnCoins = zwallet->GetTracker().MintsAsSigmaEntries(true, false);
    LogPrintf("listOwnCoins.size()=%s\n", listOwnCoins.size());
    for (std::map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
        const CWalletTx *pcoin = &(*it).second;
//        LogPrintf("pcoin=%s\n", pcoin->GetHash().ToString());
        if (!CheckFinalTx(*pcoin)) {
            LogPrintf("!CheckFinalTx(*pcoin)=%s\n", !CheckFinalTx(*pcoin));
            continue;
        }

        if (fOnlyConfirmed && !pcoin->IsTrusted()) {
            LogPrintf("fOnlyConfirmed = %s, !pcoin->IsTrusted()\n", fOnlyConfirmed, !pcoin->IsTrusted());
            continue;
        }

        if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity() > 0) {
            LogPrintf("Not trusted\n");
            continue;
        }

        int nDepth = pcoin->GetDepthInMainChain();
        if (nDepth < 0) {
            LogPrintf("nDepth=%s\n", nDepth);
            continue;
        }
        LogPrintf("pcoin->tx->vout.size()=%s\n", pcoin->tx->vout.size());

        for (unsigned int i = 0; i < pcoin->tx->vout.size(); i++) {
            if (pcoin->tx->vout[i].scriptPubKey.IsSigmaMint()) {
                CTxOut txout = pcoin->tx->vout[i];
                secp_primitives::GroupElement pubCoin = sigma::ParseSigmaMintScript(
                    txout.scriptPubKey);
                LogPrintf("Pubcoin=%s\n", pubCoin.tostring());
                // CHECKING PROCESS
                BOOST_FOREACH(const CSigmaEntry &ownCoinItem, listOwnCoins) {
                   if (ownCoinItem.value == pubCoin && ownCoinItem.IsUsed == false &&
                        ownCoinItem.randomness != uint64_t(0) && ownCoinItem.serialNumber != uint64_t(0)) {
                        vCoins.push_back(COutput(pcoin, i, nDepth, true, true));
                        LogPrintf("-->OK\n");
                    }
                }
            }
        }
    }
}

void CWallet::ListAvailableLelantusMintCoins(std::vector<COutput> &vCoins, bool fOnlyConfirmed) const {
    EnsureMintWalletAvailable();

    vCoins.clear();
    LOCK2(cs_main, cs_wallet);
    std::list<CLelantusEntry> listOwnCoins;
    CWalletDB walletdb(pwalletMain->strWalletFile);
    listOwnCoins = zwallet->GetTracker().MintsAsLelantusEntries(true, false);
    LogPrintf("listOwnCoins.size()=%s\n", listOwnCoins.size());
    for (std::map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
        const CWalletTx *pcoin = &(*it).second;
//        LogPrintf("pcoin=%s\n", pcoin->GetHash().ToString());
        if (!CheckFinalTx(*pcoin)) {
            LogPrintf("!CheckFinalTx(*pcoin)=%s\n", !CheckFinalTx(*pcoin));
            continue;
        }

        if (fOnlyConfirmed && !pcoin->IsTrusted()) {
            LogPrintf("fOnlyConfirmed = %s, !pcoin->IsTrusted() = %s\n", fOnlyConfirmed, !pcoin->IsTrusted());
            continue;
        }

        if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity() > 0) {
            LogPrintf("Not trusted\n");
            continue;
        }

        int nDepth = pcoin->GetDepthInMainChain();
        if (nDepth < 0) {
            LogPrintf("nDepth=%s\n", nDepth);
            continue;
        }
        LogPrintf("pcoin->tx->vout.size()=%s\n", pcoin->tx->vout.size());

        for (unsigned int i = 0; i < pcoin->tx->vout.size(); i++) {
            if (pcoin->tx->vout[i].scriptPubKey.IsLelantusMint() || pcoin->tx->vout[i].scriptPubKey.IsLelantusJMint()) {
                CTxOut txout = pcoin->tx->vout[i];
                secp_primitives::GroupElement pubCoin;
                lelantus::ParseLelantusMintScript(txout.scriptPubKey, pubCoin);
                LogPrintf("Pubcoin=%s\n", pubCoin.tostring());
                // CHECKING PROCESS
                BOOST_FOREACH(const CLelantusEntry& ownCoinItem, listOwnCoins) {
                    if (ownCoinItem.value == pubCoin && ownCoinItem.IsUsed == false &&
                        !ownCoinItem.randomness.isZero() && !ownCoinItem.serialNumber.isZero()) {
                        vCoins.push_back(COutput(pcoin, i, nDepth, true, true));
                        LogPrintf("-->OK\n");
                    }
                }
            }
        }
    }
}

static void ApproximateBestSubset(std::vector<std::pair<CAmount, std::pair<const CWalletTx*,unsigned int> > >vValue, const CAmount& nTotalLower, const CAmount& nTargetValue,
                                  std::vector<char>& vfBest, CAmount& nBest, int iterations = 1000)
{
    std::vector<char> vfIncluded;

    vfBest.assign(vValue.size(), true);
    nBest = nTotalLower;

    FastRandomContext insecure_rand;

    for (int nRep = 0; nRep < iterations && nBest != nTargetValue; nRep++) {
        vfIncluded.assign(vValue.size(), false);
        CAmount nTotal = 0;
        bool fReachedTarget = false;
        for (int nPass = 0; nPass < 2 && !fReachedTarget; nPass++)
        {
            for (unsigned int i = 0; i < vValue.size(); i++)
            {
                //The solver here uses a randomized algorithm,
                //the randomness serves no real security purpose but is just
                //needed to prevent degenerate behavior and it is important
                //that the rng is fast. We do not use a constant random sequence,
                //because there may be some privacy improvement by making
                //the selection random.
                if (nPass == 0 ? insecure_rand.rand32()&1 : !vfIncluded[i])
                {
                    nTotal += vValue[i].first;
                    vfIncluded[i] = true;
                    if (nTotal >= nTargetValue)
                    {
                        fReachedTarget = true;
                        if (nTotal < nBest)
                        {
                            nBest = nTotal;
                            vfBest = vfIncluded;
                        }
                        nTotal -= vValue[i].first;
                        vfIncluded[i] = false;
                    }
                }
            }
        }
    }
}

bool CWallet::SelectCoinsMinConf(const CAmount& nTargetValue, const int nConfMine, const int nConfTheirs, const uint64_t nMaxAncestors, std::vector<COutput> vCoins,
                                 std::set<std::pair<const CWalletTx*,unsigned int> >& setCoinsRet, CAmount& nValueRet) const
{
    setCoinsRet.clear();
    nValueRet = 0;

    // List of values less than target
    std::pair<CAmount, std::pair<const CWalletTx*,unsigned int> > coinLowestLarger;
    coinLowestLarger.first = std::numeric_limits<CAmount>::max();
    coinLowestLarger.second.first = NULL;
    std::vector<std::pair<CAmount, std::pair<const CWalletTx*,unsigned int> > > vValue;
    CAmount nTotalLower = 0;

    Shuffle(vCoins.begin(), vCoins.end(), FastRandomContext());

    BOOST_FOREACH(const COutput &output, vCoins)
    {
        if (!output.fSpendable)
            continue;

        const CWalletTx *pcoin = output.tx;

        if (output.nDepth < ((pcoin->IsFromMe(ISMINE_ALL) || pcoin->tx->IsLelantusMint()) ? nConfMine : nConfTheirs))
            continue;

        if (!mempool.TransactionWithinChainLimit(pcoin->GetHash(), nMaxAncestors))
            continue;

        int i = output.i;
        CAmount n = pcoin->tx->vout[i].nValue;

        std::pair<CAmount,std::pair<const CWalletTx*,unsigned int> > coin = std::make_pair(n,std::make_pair(pcoin, i));

        if (n == nTargetValue)
        {
            setCoinsRet.insert(coin.second);
            nValueRet += coin.first;
            return true;
        }
        else if (n < nTargetValue + MIN_CHANGE)
        {
            vValue.push_back(coin);
            nTotalLower += n;
        }
        else if (n < coinLowestLarger.first)
        {
            coinLowestLarger = coin;
        }
    }

    if (nTotalLower == nTargetValue)
    {
        for (unsigned int i = 0; i < vValue.size(); ++i)
        {
            setCoinsRet.insert(vValue[i].second);
            nValueRet += vValue[i].first;
        }
        return true;
    }

    if (nTotalLower < nTargetValue)
    {
        if (coinLowestLarger.second.first == NULL)
            return false;
        setCoinsRet.insert(coinLowestLarger.second);
        nValueRet += coinLowestLarger.first;
        return true;
    }

    // Solve subset sum by stochastic approximation
    std::sort(vValue.begin(), vValue.end(), CompareValueOnly());
    std::reverse(vValue.begin(), vValue.end());
    std::vector<char> vfBest;
    CAmount nBest;

    ApproximateBestSubset(vValue, nTotalLower, nTargetValue, vfBest, nBest);
    if (nBest != nTargetValue && nTotalLower >= nTargetValue + MIN_CHANGE)
        ApproximateBestSubset(vValue, nTotalLower, nTargetValue + MIN_CHANGE, vfBest, nBest);

    // If we have a bigger coin and (either the stochastic approximation didn't find a good solution,
    //                                   or the next bigger coin is closer), return the bigger coin
    if (coinLowestLarger.second.first &&
        ((nBest != nTargetValue && nBest < nTargetValue + MIN_CHANGE) || coinLowestLarger.first <= nBest))
    {
        setCoinsRet.insert(coinLowestLarger.second);
        nValueRet += coinLowestLarger.first;
    }
    else {
        for (unsigned int i = 0; i < vValue.size(); i++)
            if (vfBest[i])
            {
                setCoinsRet.insert(vValue[i].second);
                nValueRet += vValue[i].first;
            }

        LogPrint("selectcoins", "SelectCoins() best subset: ");
        for (unsigned int i = 0; i < vValue.size(); i++)
            if (vfBest[i])
                LogPrint("selectcoins", "%s ", FormatMoney(vValue[i].first));
        LogPrint("selectcoins", "total %s\n", FormatMoney(nBest));
    }

    return true;
}

bool CWallet::SelectCoins(const std::vector<COutput>& vAvailableCoins, const CAmount& nTargetValue, std::set<std::pair<const CWalletTx*,unsigned int> >& setCoinsRet, CAmount& nValueRet, const CCoinControl* coinControl) const
{
    std::vector<COutput> vCoins(vAvailableCoins);
    CoinType nCoinType = coinControl ? coinControl->nCoinType : CoinType::ALL_COINS;

    // coin control -> return all selected outputs (we want all selected to go into the transaction for sure)
    if (coinControl && coinControl->HasSelected() && !coinControl->fAllowOtherInputs)
    {
        BOOST_FOREACH(const COutput& out, vCoins)
        {
            if (!out.fSpendable)
                 continue;
            nValueRet += out.tx->tx->vout[out.i].nValue;
            setCoinsRet.insert(std::make_pair(out.tx, out.i));
        }
        return (nValueRet >= nTargetValue);
    }

    // calculate value from preset inputs and store them
    std::set<std::pair<const CWalletTx*, uint32_t> > setPresetCoins;
    CAmount nValueFromPresetInputs = 0;

    std::vector<COutPoint> vPresetInputs;
    if (coinControl)
        coinControl->ListSelected(vPresetInputs);
    BOOST_FOREACH(const COutPoint& outpoint, vPresetInputs)
    {
        std::map<uint256, CWalletTx>::const_iterator it = mapWallet.find(outpoint.hash);
        if (it != mapWallet.end())
        {
            const CWalletTx* pcoin = &it->second;
            // Clearly invalid input, fail
            if (pcoin->tx->vout.size() <= outpoint.n)
                return false;
            nValueFromPresetInputs += pcoin->tx->vout[outpoint.n].nValue;
            setPresetCoins.insert(std::make_pair(pcoin, outpoint.n));
        } else
            return false; // TODO: Allow non-wallet inputs
    }

    // remove preset inputs from vCoins
    for (std::vector<COutput>::iterator it = vCoins.begin(); it != vCoins.end() && coinControl && coinControl->HasSelected();)
    {
        if (setPresetCoins.count(std::make_pair(it->tx, it->i)))
            it = vCoins.erase(it);
        else
            ++it;
    }

    size_t nMaxChainLength = std::min(GetArg("-limitancestorcount", DEFAULT_ANCESTOR_LIMIT), GetArg("-limitdescendantcount", DEFAULT_DESCENDANT_LIMIT));
    bool fRejectLongChains = GetBoolArg("-walletrejectlongchains", DEFAULT_WALLET_REJECT_LONG_CHAINS);

    bool res = nTargetValue <= nValueFromPresetInputs ||
        SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, 1, 6, 0, vCoins, setCoinsRet, nValueRet) ||
        SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, 1, 1, 0, vCoins, setCoinsRet, nValueRet) ||
        (bSpendZeroConfChange && SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, 0, 1, 2, vCoins, setCoinsRet, nValueRet)) ||
        (bSpendZeroConfChange && SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, 0, 1, std::min((size_t)4, nMaxChainLength/3), vCoins, setCoinsRet, nValueRet)) ||
        (bSpendZeroConfChange && SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, 0, 1, nMaxChainLength/2, vCoins, setCoinsRet, nValueRet)) ||
        (bSpendZeroConfChange && SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, 0, 1, nMaxChainLength, vCoins, setCoinsRet, nValueRet)) ||
        (bSpendZeroConfChange && !fRejectLongChains && SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, 0, 1, std::numeric_limits<uint64_t>::max(), vCoins, setCoinsRet, nValueRet));

    // because SelectCoinsMinConf clears the setCoinsRet, we now add the possible inputs to the coinset
    setCoinsRet.insert(setPresetCoins.begin(), setPresetCoins.end());

    // add preset inputs to the total value selected
    nValueRet += nValueFromPresetInputs;

    return res;
}

bool CWallet::FundTransaction(CMutableTransaction& tx, CAmount& nFeeRet, bool overrideEstimatedFeeRate, const CFeeRate& specificFeeRate, int& nChangePosInOut, std::string& strFailReason, bool includeWatching, bool lockUnspents, const std::set<int>& setSubtractFeeFromOutputs, bool keepReserveKey, const CTxDestination& destChange)
{
    std::vector<CRecipient> vecSend;

    // Turn the txout set into a CRecipient vector
    for (size_t idx = 0; idx < tx.vout.size(); idx++)
    {
        const CTxOut& txOut = tx.vout[idx];
        CRecipient recipient = {txOut.scriptPubKey, txOut.nValue, setSubtractFeeFromOutputs.count(idx) == 1};
        vecSend.push_back(recipient);
    }

    CCoinControl coinControl;
    coinControl.destChange = destChange;
    coinControl.fAllowOtherInputs = true;
    coinControl.fAllowWatchOnly = includeWatching;
    coinControl.fOverrideFeeRate = overrideEstimatedFeeRate;
    coinControl.nFeeRate = specificFeeRate;

    BOOST_FOREACH(const CTxIn& txin, tx.vin)
        coinControl.Select(txin.prevout);

    int nExtraPayloadSize = 0;
    if (tx.nVersion == 3 && tx.nType != TRANSACTION_NORMAL)
        nExtraPayloadSize = (int)tx.vExtraPayload.size();

    CReserveKey reservekey(this);
    CWalletTx wtx;
    if (!CreateTransaction(vecSend, wtx, reservekey, nFeeRet, nChangePosInOut, strFailReason, &coinControl, nExtraPayloadSize))
        return false;

    if (nChangePosInOut != -1)
        tx.vout.insert(tx.vout.begin() + nChangePosInOut, wtx.tx->vout[nChangePosInOut]);

    // Copy output sizes from new transaction; they may have had the fee subtracted from them
    for (unsigned int idx = 0; idx < tx.vout.size(); idx++)
        tx.vout[idx].nValue = wtx.tx->vout[idx].nValue;

    // Add new txins (keeping original txin scriptSig/order)
    BOOST_FOREACH(const CTxIn& txin, wtx.tx->vin)
    {
        if (!coinControl.IsSelected(txin.prevout))
        {
            tx.vin.push_back(txin);

            if (lockUnspents)
            {
              LOCK2(cs_main, cs_wallet);
              LockCoin(txin.prevout);
            }
        }
    }

    // optionally keep the change output key
    if (keepReserveKey)
        reservekey.KeepKey();

    return true;
}

bool CWallet::ConvertList(std::vector <CTxIn> vecTxIn, std::vector <CAmount> &vecAmounts) {
    BOOST_FOREACH(CTxIn txin, vecTxIn) {
        if (mapWallet.count(txin.prevout.hash)) {
            CWalletTx &wtx = mapWallet[txin.prevout.hash];
            if (txin.prevout.n < wtx.tx->vout.size()) {
                vecAmounts.push_back(wtx.tx->vout[txin.prevout.n].nValue);
            }
        } else {
            LogPrintf("CWallet::ConvertList -- Couldn't find transaction\n");
        }
    }
    return true;
}

bool CWallet::CreateTransaction(const std::vector<CRecipient>& vecSend, CWalletTx& wtxNew, CReserveKey& reservekey, CAmount& nFeeRet,
                                int& nChangePosInOut, std::string& strFailReason, const CCoinControl* coinControl, bool sign, int nExtraPayloadSize)
{
    // TODO: upgrade dash version
    CAmount nFeePay = 0;

    CAmount nValue = 0;
    int nChangePosRequest = nChangePosInOut;
    unsigned int nSubtractFeeFromAmount = 0;
    for (const auto& recipient : vecSend)
    {
        if (nValue < 0 || recipient.nAmount < 0)
        {
            strFailReason = _("Transaction amounts must not be negative");
            return false;
        }
        nValue += recipient.nAmount;

        if (recipient.fSubtractFeeFromAmount)
            nSubtractFeeFromAmount++;
    }
    if (vecSend.empty())
    {
        strFailReason = _("Transaction must have at least one recipient");
        return false;
    }

    wtxNew.fTimeReceivedIsTxTime = true;
    wtxNew.BindWallet(this);
    CMutableTransaction txNew;

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

    txNew.nLockTime = chainActive.Height();

    // Secondly occasionally randomly pick a nLockTime even further back, so
    // that transactions that are delayed after signing for whatever reason,
    // e.g. high-latency mix networks and some CoinJoin implementations, have
    // better privacy.
    if (GetRandInt(10) == 0)
        txNew.nLockTime = std::max(0, (int)txNew.nLockTime - GetRandInt(100));

    assert(txNew.nLockTime <= (unsigned int)chainActive.Height());
    assert(txNew.nLockTime < LOCKTIME_THRESHOLD);

    {
        std::set<std::pair<const CWalletTx*, unsigned int>> setCoins;
        LOCK2(cs_main, cs_wallet);
        {
            std::vector<COutput> vAvailableCoins;
            AvailableCoins(vAvailableCoins, true, coinControl, false);

            nFeeRet = 0;
            if(nFeePay > 0) nFeeRet = nFeePay;
            double dPriority = 0;
            // Start with no fee and loop until there is enough fee
            while (true)
            {
                nChangePosInOut = nChangePosRequest;
                txNew.vin.clear();
                txNew.vout.clear();
                wtxNew.fFromMe = true;
                bool fFirst = true;

                CAmount nValueToSelect = nValue;
                if (nSubtractFeeFromAmount == 0)
                    nValueToSelect += nFeeRet;
                // vouts to the payees
                for (const auto& recipient : vecSend)
                {
                    CTxOut txout(recipient.nAmount, recipient.scriptPubKey);

                    if (recipient.fSubtractFeeFromAmount)
                    {
                        txout.nValue -= nFeeRet / nSubtractFeeFromAmount; // Subtract fee equally from each selected recipient

                        if (fFirst) // first receiver pays the remainder not divisible by output count
                        {
                            fFirst = false;
                            txout.nValue -= nFeeRet % nSubtractFeeFromAmount;
                        }
                    }

                    if (txout.IsDust(dustRelayFee))
                    {
                        if (recipient.fSubtractFeeFromAmount && nFeeRet > 0)
                        {
                            if (txout.nValue < 0)
                                strFailReason = _("The transaction amount is too small to pay the fee");
                            else
                                strFailReason = _("The transaction amount is too small to send after the fee has been deducted");
                        }
                        else
                            strFailReason = _("Transaction amount too small");
                        return false;
                    }
                    txNew.vout.push_back(txout);
                }

                // Choose coins to use
                CAmount nValueIn = 0;
                setCoins.clear();
                if (!SelectCoins(vAvailableCoins, nValueToSelect, setCoins, nValueIn, coinControl))
                {
                    strFailReason = _("Insufficient funds");
                    return false;
                }

                const CAmount nChange = nValueIn - nValueToSelect;
                CTxOut newTxOut;

                if (nChange > 0)
                {
                    // Fill a vout to ourself
                    // TODO: pass in scriptChange instead of reservekey so
                    // change transaction isn't always pay-to-dash-address
                    CScript scriptChange;

                    // coin control: send change to custom address
                    if (coinControl && !boost::get<CNoDestination>(&coinControl->destChange))
                        scriptChange = GetScriptForDestination(coinControl->destChange);

                    // no coin control: send change to newly generated address
                    else
                    {
                        // Note: We use a new key here to keep it from being obvious which side is the change.
                        //  The drawback is that by not reusing a previous key, the change may be lost if a
                        //  backup is restored, if the backup doesn't have the new private key for the change.
                        //  If we reused the old key, it would be possible to add code to look for and
                        //  rediscover unknown transactions that were written with keys of ours to recover
                        //  post-backup change.

                        // Reserve a new key pair from key pool
                        CPubKey vchPubKey;
                        bool ret;
                        ret = reservekey.GetReservedKey(vchPubKey);
                        if (!ret)
                        {
                            strFailReason = _("Keypool ran out, please call keypoolrefill first");
                            return false;
                        }

                        scriptChange = GetScriptForDestination(vchPubKey.GetID());
                    }

                    newTxOut = CTxOut(nChange, scriptChange);

                    // We do not move dust-change to fees, because the sender would end up paying more than requested.
                    // This would be against the purpose of the all-inclusive feature.
                    // So instead we raise the change and deduct from the recipient.
                    if (nSubtractFeeFromAmount > 0 && newTxOut.IsDust(dustRelayFee))
                    {
                        CAmount nDust = newTxOut.GetDustThreshold(dustRelayFee) - newTxOut.nValue;
                        newTxOut.nValue += nDust; // raise change until no more dust
                        for (unsigned int i = 0; i < vecSend.size(); i++) // subtract from first recipient
                        {
                            if (vecSend[i].fSubtractFeeFromAmount)
                            {
                                txNew.vout[i].nValue -= nDust;
                                if (txNew.vout[i].IsDust(dustRelayFee))
                                {
                                    strFailReason = _("The transaction amount is too small to send after the fee has been deducted");
                                    return false;
                                }
                                break;
                            }
                        }
                    }

                    // Never create dust outputs; if we would, just
                    // add the dust to the fee.
                    if (newTxOut.IsDust(dustRelayFee))
                    {
                        nChangePosInOut = -1;
                        nFeeRet += nChange;
                        reservekey.ReturnKey();
                    }
                    else
                    {
                        if (nChangePosInOut == -1)
                        {
                            // Insert change txn at random position:
                            nChangePosInOut = GetRandInt(txNew.vout.size()+1);
                        }
                        else if ((unsigned int)nChangePosInOut > txNew.vout.size())
                        {
                            strFailReason = _("Change index out of range");
                            return false;
                        }

                        std::vector<CTxOut>::iterator position = txNew.vout.begin()+nChangePosInOut;
                        txNew.vout.insert(position, newTxOut);
                    }
                } else {
                    reservekey.ReturnKey();
                    nChangePosInOut = -1;
                }

                // Fill vin
                //
                // Note how the sequence number is set to max()-1 so that the
                // nLockTime set above actually works.
                //
                // BIP125 defines opt-in RBF as any nSequence < maxint-1, so
                // we use the highest possible value in that range (maxint-2)
                // to avoid conflicting with other possible uses of nSequence,
                // and in the spirit of "smallest possible change from prior
                // behavior."
                for (const auto& coin : setCoins)
                    txNew.vin.push_back(CTxIn(coin.first->GetHash(),coin.second,CScript(),
                                              std::numeric_limits<unsigned int>::max() - (fWalletRbf ? 2 : 1)));

                // Fill in dummy signatures for fee calculation.
                if (!DummySignTx(txNew, setCoins)) {
                    strFailReason = _("Signing transaction failed");
                    return false;
                }

                unsigned int nBytes = ::GetSerializeSize(txNew, SER_NETWORK, PROTOCOL_VERSION);

                if (nExtraPayloadSize != 0) {
                    // account for extra payload in fee calculation
                    nBytes += GetSizeOfCompactSize(nExtraPayloadSize) + nExtraPayloadSize;
                }

                if (nBytes > MAX_STANDARD_TX_SIZE) {
                    // Do not create oversized transactions (bad-txns-oversize).
                    strFailReason = _("Transaction too large");
                    return false;
                }

                CTransaction txNewConst(txNew);
                dPriority = txNewConst.ComputePriority(dPriority, nBytes);

                // Remove scriptSigs to eliminate the fee calculation dummy signatures
                for (auto& vin : txNew.vin) {
                    vin.scriptSig = CScript();
                    vin.scriptWitness.SetNull();
                }

                // Allow to override the default confirmation target over the CoinControl instance
                int currentConfirmationTarget = nTxConfirmTarget;
                if (coinControl && coinControl->nConfirmTarget > 0)
                    currentConfirmationTarget = coinControl->nConfirmTarget;

                // Can we complete this as a free transaction?
                if (fSendFreeTransactions && nBytes <= MAX_FREE_TRANSACTION_CREATE_SIZE)
                {
                    // Not enough fee: enough priority?
                    double dPriorityNeeded = mempool.estimateSmartPriority(currentConfirmationTarget);
                    // Require at least hard-coded AllowFree.
                    if (dPriority >= dPriorityNeeded && AllowFree(dPriority))
                        break;
                }

                CAmount nFeeNeeded = GetMinimumFee(nBytes, currentConfirmationTarget, mempool);
                if (coinControl && nFeeNeeded > 0 && coinControl->nMinimumTotalFee > nFeeNeeded) {
                    nFeeNeeded = coinControl->nMinimumTotalFee;
                }
                if (coinControl && coinControl->fOverrideFeeRate)
                    nFeeNeeded = coinControl->nFeeRate.GetFee(nBytes);

                // If we made it here and we aren't even able to meet the relay fee on the next pass, give up
                // because we must be at the maximum allowed fee.
                if (nFeeNeeded < ::minRelayTxFee.GetFee(nBytes))
                {
                    strFailReason = _("Transaction too large for fee policy");
                    return false;
                }

                if (nFeeRet >= nFeeNeeded) {
                    // Reduce fee to only the needed amount if we have change
                    // output to increase.  This prevents potential overpayment
                    // in fees if the coins selected to meet nFeeNeeded result
                    // in a transaction that requires less fee than the prior
                    // iteration.
                    // TODO: The case where nSubtractFeeFromAmount > 0 remains
                    // to be addressed because it requires returning the fee to
                    // the payees and not the change output.
                    // TODO: The case where there is no change output remains
                    // to be addressed so we avoid creating too small an output.
                    if (nFeeRet > nFeeNeeded && nChangePosInOut != -1 && nSubtractFeeFromAmount == 0) {
                        CAmount extraFeePaid = nFeeRet - nFeeNeeded;
                        std::vector<CTxOut>::iterator change_position = txNew.vout.begin()+nChangePosInOut;
                        change_position->nValue += extraFeePaid;
                        nFeeRet -= extraFeePaid;
                    }
                    break; // Done, enough fee included.
                }

                // Try to reduce change to include necessary fee
                if (nChangePosInOut != -1 && nSubtractFeeFromAmount == 0) {
                    CAmount additionalFeeNeeded = nFeeNeeded - nFeeRet;
                    std::vector<CTxOut>::iterator change_position = txNew.vout.begin()+nChangePosInOut;
                    // Only reduce change if remaining amount is still a large enough output.
                    if (change_position->nValue >= MIN_FINAL_CHANGE + additionalFeeNeeded) {
                        change_position->nValue -= additionalFeeNeeded;
                        nFeeRet += additionalFeeNeeded;
                        break; // Done, able to increase fee from change
                    }
                }

                // Include more fee and try again.
                nFeeRet = nFeeNeeded;
                continue;
            }
        }

        if (sign)
        {
            CTransaction txNewConst(txNew);
            int nIn = 0;
            for (const auto& coin : setCoins)
            {
                const CScript& scriptPubKey = coin.first->tx->vout[coin.second].scriptPubKey;
                SignatureData sigdata;

                if (!ProduceSignature(TransactionSignatureCreator(this, &txNewConst, nIn, coin.first->tx->vout[coin.second].nValue, SIGHASH_ALL), scriptPubKey, sigdata))
                {
                    strFailReason = _("Signing transaction failed");
                    return false;
                } else {
                    UpdateTransaction(txNew, nIn, sigdata);
                }

                nIn++;
            }
        }

        // Embed the constructed transaction data in wtxNew.
        wtxNew.SetTx(MakeTransactionRef(std::move(txNew)));
    }

    if (GetBoolArg("-walletrejectlongchains", DEFAULT_WALLET_REJECT_LONG_CHAINS)) {
        // Lastly, ensure this tx will pass the mempool's chain limits
        LockPoints lp;
        CTxMemPoolEntry entry(wtxNew.tx, 0, 0, 0, 0, false, 0, lp);

        CTxMemPool::setEntries setAncestors;
        size_t nLimitAncestors = GetArg("-limitancestorcount", DEFAULT_ANCESTOR_LIMIT);
        size_t nLimitAncestorSize = GetArg("-limitancestorsize", DEFAULT_ANCESTOR_SIZE_LIMIT)*1000;
        size_t nLimitDescendants = GetArg("-limitdescendantcount", DEFAULT_DESCENDANT_LIMIT);
        size_t nLimitDescendantSize = GetArg("-limitdescendantsize", DEFAULT_DESCENDANT_SIZE_LIMIT)*1000;
        std::string errString;
        if (!mempool.CalculateMemPoolAncestors(entry, setAncestors, nLimitAncestors, nLimitAncestorSize, nLimitDescendants, nLimitDescendantSize, errString)) {
            strFailReason = _("Transaction has too long of a mempool chain");
            return false;
        }
    }
    return true;
}

/**
 * Call after CreateTransaction unless you want to abort
 */
bool CWallet::CommitTransaction(CWalletTx& wtxNew, CReserveKey& reservekey, CConnman* connman, CValidationState& state)
{
    {
        LOCK2(cs_main, cs_wallet);
        LogPrintf("CommitTransaction:\n%s", wtxNew.tx->ToString());
        {
            // Take key pair from key pool so it won't be used again
            reservekey.KeepKey();

            // Add tx to wallet, because if it has change it's also ours,
            // otherwise just for transaction history.
            AddToWallet(wtxNew);

            // Notify that old coins are spent
            BOOST_FOREACH(const CTxIn& txin, wtxNew.tx->vin)
            {
                // Skip inputs of anonymized transactions
                if (txin.prevout.hash.IsNull())
                    continue;

                CWalletTx &coin = mapWallet[txin.prevout.hash];
                coin.BindWallet(this);
                NotifyTransactionChanged(this, coin.GetHash(), CT_UPDATED);
            }
        }

        // Track how many getdata requests our transaction gets
        mapRequestCount[wtxNew.GetHash()] = 0;

        if (fBroadcastTransactions)
        {
            // Broadcast
            if (!wtxNew.AcceptToMemoryPool(maxTxFee, state)) {
                LogPrintf("CommitTransaction(): Transaction cannot be broadcast immediately, %s\n", state.GetRejectReason());
                // TODO: if we expect the failure to be long term or permanent, instead delete wtx from the wallet and return failure.
            } else {
                wtxNew.RelayWalletTransaction(connman);
            }
        }
    }
    return true;
}

bool CWallet::EraseFromWallet(uint256 hash) {
    if (!fFileBacked)
        return false;
    {
        LOCK(cs_wallet);
        if (mapWallet.erase(hash))
            CWalletDB(strWalletFile).EraseTx(hash);
    }
    return true;
}

/**
 * @brief CWallet::CreateMintTransaction
 * @param vecSend
 * @param wtxNew
 * @param reservekey
 * @param nFeeRet
 * @param strFailReason
 * @param coinControl
 * @return
 */
bool CWallet::CreateMintTransaction(const std::vector <CRecipient> &vecSend, CWalletTx &wtxNew,
                                            CReserveKey &reservekey,
                                            CAmount &nFeeRet, int &nChangePosInOut, std::string &strFailReason,
                                            const CCoinControl *coinControl, bool sign) {
    CAmount nValue = 0;
    int nChangePosRequest = nChangePosInOut;
    unsigned int nSubtractFeeFromAmount = 0;
    BOOST_FOREACH(const CRecipient &recipient, vecSend)
    {
        if (nValue < 0 || recipient.nAmount < 0) {
            strFailReason = _("Transaction amounts must be positive");
            return false;
        }
        nValue += recipient.nAmount;
    }
    if (vecSend.empty() || nValue < 0) {
        strFailReason = _("Transaction amounts must be positive");
        return false;
    }
    wtxNew.fTimeReceivedIsTxTime = true;
    wtxNew.BindWallet(this);
    CMutableTransaction txNew;
    txNew.nLockTime = chainActive.Height();
    if (GetRandInt(10) == 0)
        txNew.nLockTime = std::max(0, (int) txNew.nLockTime - GetRandInt(100));

    assert(txNew.nLockTime <= (unsigned int) chainActive.Height());
    assert(txNew.nLockTime < LOCKTIME_THRESHOLD);

    {
        LOCK2(cs_main, cs_wallet);
        {
            std::vector<COutput> vAvailableCoins;
            AvailableCoins(vAvailableCoins, true, coinControl);

            nFeeRet = payTxFee.GetFeePerK();
            LogPrintf("nFeeRet=%s\n", nFeeRet);
            // Start with no fee and loop until there is enough fee
            while (true)
            {
                nChangePosInOut = nChangePosRequest;
                txNew.vin.clear();
                txNew.vout.clear();

                wtxNew.fFromMe = true;
                wtxNew.changes.clear();

                CAmount nValueToSelect = nValue + nFeeRet;
                double dPriority = 0;
                // vouts to the payees
                BOOST_FOREACH(const CRecipient &recipient, vecSend)
                {
                    CTxOut txout(recipient.nAmount, recipient.scriptPubKey);
                    LogPrintf("txout:%s\n", txout.ToString());

                    if (txout.IsDust(::minRelayTxFee)) {
                        if (recipient.fSubtractFeeFromAmount && nFeeRet > 0) {
                            if (txout.nValue < 0)
                                strFailReason = _("The transaction amount is too small to pay the fee");
                            else
                                strFailReason = _(
                                        "The transaction amount is too small to send after the fee has been deducted");
                        } else
                            strFailReason = _("Transaction amount too small");
                        return false;
                    }
                    txNew.vout.push_back(txout);
                }

                // Choose coins to use
                std::set<std::pair<const CWalletTx*,unsigned int> > setCoins;
                CAmount nValueIn = 0;
                if (!SelectCoins(vAvailableCoins, nValueToSelect, setCoins, nValueIn, coinControl))
                {
                    if (nValueIn < nValueToSelect) {
                        strFailReason = _("Insufficient funds");
                    }
                    return false;
                }
                BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int) pcoin, setCoins)
                {
                    CAmount nCredit = pcoin.first->tx->vout[pcoin.second].nValue;
                    //The coin age after the next block (depth+1) is used instead of the current,
                    //reflecting an assumption the user would accept a bit more delay for
                    //a chance at a free transaction.
                    //But mempool inputs might still be in the mempool, so their age stays 0
                    int age = pcoin.first->GetDepthInMainChain();
                    assert(age >= 0);
                    if (age != 0)
                        age += 1;
                    dPriority += (double)nCredit * age;
                }

                CAmount nChange = nValueIn - nValueToSelect;

                if (nChange > 0) {
                    // Fill a vout to ourself
                    // TODO: pass in scriptChange instead of reservekey so
                    // change transaction isn't always pay-to-bitcoin-address
                    CScript scriptChange;

                    // coin control: send change to custom address
                    if (coinControl && !boost::get<CNoDestination>(&coinControl->destChange))
                        scriptChange = GetScriptForDestination(coinControl->destChange);

                    // send change to one of the specified change addresses
                    else if (IsArgSet("-change") && mapMultiArgs.at("-change").size() > 0) {
                        CBitcoinAddress address(mapMultiArgs.at("change")[GetRandInt(mapMultiArgs.at("-change").size())]);
                        CKeyID keyID;
                        if (!address.GetKeyID(keyID)) {
                            strFailReason = _("Bad change address");
                            return false;
                        }
                        scriptChange = GetScriptForDestination(keyID);
                    }

                    // no coin control: send change to newly generated address
                    else
                    {
                        // Note: We use a new key here to keep it from being obvious which side is the change.
                        //  The drawback is that by not reusing a previous key, the change may be lost if a
                        //  backup is restored, if the backup doesn't have the new private key for the change.
                        //  If we reused the old key, it would be possible to add code to look for and
                        //  rediscover unknown transactions that were written with keys of ours to recover
                        //  post-backup change.

                        // Reserve a new key pair from key pool
                        CPubKey vchPubKey;
                        bool ret;
                        ret = reservekey.GetReservedKey(vchPubKey);
                        if (!ret)
                        {
                            strFailReason = _("Keypool ran out, please call keypoolrefill first");
                            return false;
                        }

                        scriptChange = GetScriptForDestination(vchPubKey.GetID());
                    }

                    CTxOut newTxOut(nChange, scriptChange);

                    // We do not move dust-change to fees, because the sender would end up paying more than requested.
                    // This would be against the purpose of the all-inclusive feature.
                    // So instead we raise the change and deduct from the recipient.
                    if (nSubtractFeeFromAmount > 0 && newTxOut.IsDust(::minRelayTxFee))
                    {
                        CAmount nDust = newTxOut.GetDustThreshold(::minRelayTxFee) - newTxOut.nValue;
                        newTxOut.nValue += nDust; // raise change until no more dust
                        for (unsigned int i = 0; i < vecSend.size(); i++) // subtract from first recipient
                        {
                            if (vecSend[i].fSubtractFeeFromAmount)
                            {
                                txNew.vout[i].nValue -= nDust;
                                if (txNew.vout[i].IsDust(::minRelayTxFee))
                                {
                                    strFailReason = _("The transaction amount is too small to send after the fee has been deducted");
                                    return false;
                                }
                                break;
                            }
                        }
                    }

                    // Never create dust outputs; if we would, just
                    // add the dust to the fee.
                    if (newTxOut.IsDust(::minRelayTxFee))
                    {
                        nChangePosInOut = -1;
                        nFeeRet += nChange;
                        reservekey.ReturnKey();
                    }
                    else
                    {
                        if (nChangePosInOut == -1)
                        {
                            // Insert change txn at random position:
                            nChangePosInOut = GetRandInt(txNew.vout.size()+1);
                        }
                        else if ((unsigned int)nChangePosInOut > txNew.vout.size())
                        {
                            strFailReason = _("Change index out of range");
                            return false;
                        }

                        std::vector<CTxOut>::iterator position = txNew.vout.begin()+nChangePosInOut;
                        txNew.vout.insert(position, newTxOut);
                        wtxNew.changes.insert(static_cast<uint32_t>(nChangePosInOut));
                    }
                }
                else
                    reservekey.ReturnKey();

                // Fill vin
                //
                // Note how the sequence number is set to max()-1 so that the
                // nLockTime set above actually works.
                BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins)
                    txNew.vin.push_back(CTxIn(coin.first->GetHash(),coin.second,CScript(),
                                              std::numeric_limits<unsigned int>::max()-1));

                // Sign
                int nIn = 0;
                CTransaction txNewConst(txNew);
                BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins)
                {
                    bool signSuccess;
                    const CScript& scriptPubKey = coin.first->tx->vout[coin.second].scriptPubKey;
                    SignatureData sigdata;
                    if (sign)
                        signSuccess = ProduceSignature(TransactionSignatureCreator(this, &txNewConst, nIn, coin.first->tx->vout[coin.second].nValue, SIGHASH_ALL), scriptPubKey, sigdata);
                    else
                        signSuccess = ProduceSignature(DummySignatureCreator(this), scriptPubKey, sigdata);

                    if (!signSuccess)
                    {
                        strFailReason = _("Signing transaction failed");
                        return false;
                    } else {
                        UpdateTransaction(txNew, nIn, sigdata);
                    }
                    nIn++;
                }
                unsigned int nBytes = GetVirtualTransactionSize(txNew);
                // Remove scriptSigs if we used dummy signatures for fee calculation
                if (!sign) {
                    BOOST_FOREACH(CTxIn & vin, txNew.vin)
                    vin.scriptSig = CScript();
                }
                // Embed the constructed transaction data in wtxNew.
                wtxNew.SetTx(MakeTransactionRef(std::move(txNew)));

                // Limit size
                if (GetTransactionWeight(*wtxNew.tx) >= MAX_STANDARD_TX_WEIGHT) {
                    strFailReason = _("Transaction too large");
                    return false;
                }
                dPriority = wtxNew.tx->ComputePriority(dPriority, nBytes);

                // Can we complete this as a free transaction?
                if (fSendFreeTransactions && nBytes <= MAX_FREE_TRANSACTION_CREATE_SIZE) {
                    // Not enough fee: enough priority?
                    double dPriorityNeeded = mempool.estimateSmartPriority(nTxConfirmTarget);
                    // Require at least hard-coded AllowFree.
                    if (dPriority >= dPriorityNeeded && AllowFree(dPriority))
                        break;
                }
                CAmount nFeeNeeded = GetMinimumFee(nBytes, nTxConfirmTarget, mempool);
                if (coinControl && nFeeNeeded > 0 && coinControl->nMinimumTotalFee > nFeeNeeded) {
                    nFeeNeeded = coinControl->nMinimumTotalFee;
                }
                if (coinControl && coinControl->fOverrideFeeRate)
                    nFeeNeeded = coinControl->nFeeRate.GetFee(nBytes);
                if (nFeeRet >= nFeeNeeded)
                    break; // Done, enough fee included.

                // Include more fee and try again.
                nFeeRet = nFeeNeeded;
                continue;
            }
        }
    }

    if (GetBoolArg("-walletrejectlongchains", DEFAULT_WALLET_REJECT_LONG_CHAINS)) {
        // Lastly, ensure this tx will pass the mempool's chain limits
        LockPoints lp;
        CTxMemPoolEntry entry(MakeTransactionRef(txNew), 0, 0, 0, 0, false, 0, lp);
        CTxMemPool::setEntries setAncestors;
        size_t nLimitAncestors = GetArg("-limitancestorcount", DEFAULT_ANCESTOR_LIMIT);
        size_t nLimitAncestorSize = GetArg("-limitancestorsize", DEFAULT_ANCESTOR_SIZE_LIMIT) * 1000;
        size_t nLimitDescendants = GetArg("-limitdescendantcount", DEFAULT_DESCENDANT_LIMIT);
        size_t nLimitDescendantSize = GetArg("-limitdescendantsize", DEFAULT_DESCENDANT_SIZE_LIMIT) * 1000;
        std::string errString;
        if (!mempool.CalculateMemPoolAncestors(entry, setAncestors, nLimitAncestors, nLimitAncestorSize,
                                               nLimitDescendants, nLimitDescendantSize, errString)) {
            strFailReason = _("Transaction has too long of a mempool chain");
            return false;
        }
    }
    return true;
}

bool CWallet::CreateLelantusMintTransactions(
    CAmount valueToMint,
    std::vector<std::pair<CWalletTx, CAmount>>& wtxAndFee,
    CAmount& nAllFeeRet,
    std::vector<CHDMint>& dMints,
    std::list<CReserveKey>& reservekeys,
    int& nChangePosInOut,
    std::string& strFailReason,
    const CCoinControl *coinControl,
    bool autoMintAll,
    bool sign)
{
    const auto& lelantusParams = lelantus::Params::get_default();

    int nChangePosRequest = nChangePosInOut;

    // Create transaction template
    CWalletTx wtxNew;
    wtxNew.fTimeReceivedIsTxTime = true;
    wtxNew.BindWallet(this);

    CMutableTransaction txNew;
    txNew.nLockTime = chainActive.Height();

    assert(txNew.nLockTime <= (unsigned int) chainActive.Height());
    assert(txNew.nLockTime < LOCKTIME_THRESHOLD);

    {
        LOCK2(cs_main, cs_wallet);
        {
            std::list<CWalletTx> cacheWtxs;
            std::vector<std::pair<CAmount, std::vector<COutput>>> valueAndUTXO;
            AvailableCoinsForLMint(valueAndUTXO, coinControl);

            Shuffle(valueAndUTXO.begin(), valueAndUTXO.end(), FastRandomContext());

            while (!valueAndUTXO.empty()) {

                // initialize
                CWalletTx wtx = wtxNew;
                CMutableTransaction tx = txNew;

                reservekeys.emplace_back(this);
                auto &reservekey = reservekeys.back();

                if (GetRandInt(10) == 0)
                    tx.nLockTime = std::max(0, (int) tx.nLockTime - GetRandInt(100));

                CHDMint dMint;

                auto nFeeRet = 0;
                LogPrintf("nFeeRet=%s\n", nFeeRet);

                auto itr = valueAndUTXO.begin();

                CAmount valueToMintInTx = std::min(
                        ::Params().GetConsensus().nMaxValueLelantusMint,
                        itr->first);

                if (!autoMintAll) {
                    valueToMintInTx = std::min(valueToMintInTx, valueToMint);
                }

                CAmount nValueToSelect, mintedValue;

                std::set<std::pair<const CWalletTx *, unsigned int>> setCoins;
                bool skipCoin = false;
                // Start with no fee and loop until there is enough fee
                while (true) {
                    mintedValue = valueToMintInTx;
                    nValueToSelect = mintedValue + nFeeRet;

                    // if have no enough coins in this group then subtract fee from mint
                    if (nValueToSelect > itr->first) {
                        mintedValue -= nFeeRet;
                        nValueToSelect = mintedValue + nFeeRet;
                    }

                    if (!MoneyRange(mintedValue) || mintedValue == 0) {
                        valueAndUTXO.erase(itr);
                        skipCoin = true;
                        break;
                    }

                    nChangePosInOut = nChangePosRequest;
                    tx.vin.clear();
                    tx.vout.clear();

                    wtx.fFromMe = true;
                    wtx.changes.clear();

                    setCoins.clear();

                    // create recipient using random private coin to mock script sig
                    lelantus::PrivateCoin privCoin(lelantusParams, mintedValue);
                    auto recipient = CWallet::CreateLelantusMintRecipient(privCoin, dMint, false);

                    double dPriority = 0;

                    // vout to create mint
                    CTxOut txout(recipient.nAmount, recipient.scriptPubKey);

                    if (txout.IsDust(::minRelayTxFee)) {
                        strFailReason = _("Transaction amount too small");
                        return false;
                    }

                    tx.vout.push_back(txout);

                    // Choose coins to use

                    CAmount nValueIn = 0;
                    if (!SelectCoins(itr->second, nValueToSelect, setCoins, nValueIn, coinControl)) {

                        if (nValueIn < nValueToSelect) {
                            strFailReason = _("Insufficient funds");
                        }
                        return false;
                    }

                    for (auto const &pcoin : setCoins) {
                        CAmount nCredit = pcoin.first->tx->vout[pcoin.second].nValue;
                        //The coin age after the next block (depth+1) is used instead of the current,
                        //reflecting an assumption the user would accept a bit more delay for
                        //a chance at a free transaction.
                        //But mempool inputs might still be in the mempool, so their age stays 0
                        int age = pcoin.first->GetDepthInMainChain();
                        assert(age >= 0);
                        if (age != 0)
                            age += 1;
                        dPriority += (double) nCredit * age;
                    }

                    CAmount nChange = nValueIn - nValueToSelect;

                    if (nChange > 0) {
                        // Fill a vout to ourself
                        // TODO: pass in scriptChange instead of reservekey so
                        // change transaction isn't always pay-to-bitcoin-address
                        CScript scriptChange;

                        // coin control: send change to custom address
                        if (coinControl && !boost::get<CNoDestination>(&coinControl->destChange))
                            scriptChange = GetScriptForDestination(coinControl->destChange);

                            // send change to one of the specified change addresses
                        else if (IsArgSet("-change") && mapMultiArgs.at("-change").size() > 0) {
                            CBitcoinAddress address(
                                    mapMultiArgs.at("change")[GetRandInt(mapMultiArgs.at("-change").size())]);
                            CKeyID keyID;
                            if (!address.GetKeyID(keyID)) {
                                strFailReason = _("Bad change address");
                                return false;
                            }
                            scriptChange = GetScriptForDestination(keyID);
                        }

                            // no coin control: send change to newly generated address
                        else {
                            // Note: We use a new key here to keep it from being obvious which side is the change.
                            //  The drawback is that by not reusing a previous key, the change may be lost if a
                            //  backup is restored, if the backup doesn't have the new private key for the change.
                            //  If we reused the old key, it would be possible to add code to look for and
                            //  rediscover unknown transactions that were written with keys of ours to recover
                            //  post-backup change.

                            // Reserve a new key pair from key pool
                            CPubKey vchPubKey;
                            bool ret;
                            ret = reservekey.GetReservedKey(vchPubKey);
                            if (!ret) {
                                strFailReason = _("Keypool ran out, please call keypoolrefill first");
                                return false;
                            }

                            scriptChange = GetScriptForDestination(vchPubKey.GetID());
                        }

                        CTxOut newTxOut(nChange, scriptChange);

                        // Never create dust outputs; if we would, just
                        // add the dust to the fee.
                        if (newTxOut.IsDust(::minRelayTxFee)) {
                            nChangePosInOut = -1;
                            nFeeRet += nChange;
                            reservekey.ReturnKey();
                        } else {

                            if (nChangePosInOut == -1) {

                                // Insert change txn at random position:
                                nChangePosInOut = GetRandInt(tx.vout.size() + 1);
                            } else if ((unsigned int) nChangePosInOut > tx.vout.size()) {

                                strFailReason = _("Change index out of range");
                                return false;
                            }

                            std::vector<CTxOut>::iterator position = tx.vout.begin() + nChangePosInOut;
                            tx.vout.insert(position, newTxOut);
                            wtx.changes.insert(static_cast<uint32_t>(nChangePosInOut));
                        }
                    } else {
                        reservekey.ReturnKey();
                    }

                    // Fill vin
                    //
                    // Note how the sequence number is set to max()-1 so that the
                    // nLockTime set above actually works.
                    for (const auto &coin : setCoins) {
                        tx.vin.push_back(CTxIn(
                                coin.first->GetHash(),
                                coin.second,
                                CScript(),
                                std::numeric_limits<unsigned int>::max() - 1));
                    }

                    // Fill in dummy signatures for fee calculation.
                    if (!DummySignTx(tx, setCoins)) {
                        strFailReason = _("Signing transaction failed");
                        return false;
                    }

                    unsigned int nBytes = GetVirtualTransactionSize(tx);

                    // Limit size
                    CTransaction txConst(tx);
                    if (GetTransactionWeight(txConst) >= MAX_STANDARD_TX_WEIGHT) {
                        strFailReason = _("Transaction too large");
                        return false;
                    }
                    dPriority = txConst.ComputePriority(dPriority, nBytes);

                    // Remove scriptSigs to eliminate the fee calculation dummy signatures
                    for (auto &vin : tx.vin) {
                        vin.scriptSig = CScript();
                        vin.scriptWitness.SetNull();
                    }

                    // Can we complete this as a free transaction?
                    if (fSendFreeTransactions && nBytes <= MAX_FREE_TRANSACTION_CREATE_SIZE) {
                        // Not enough fee: enough priority?
                        double dPriorityNeeded = mempool.estimateSmartPriority(nTxConfirmTarget);
                        // Require at least hard-coded AllowFree.
                        if (dPriority >= dPriorityNeeded && AllowFree(dPriority))
                            break;
                    }
                    CAmount nFeeNeeded = GetMinimumFee(nBytes, nTxConfirmTarget, mempool);

                    if (coinControl && nFeeNeeded > 0 && coinControl->nMinimumTotalFee > nFeeNeeded) {
                        nFeeNeeded = coinControl->nMinimumTotalFee;
                    }

                    if (coinControl && coinControl->fOverrideFeeRate)
                        nFeeNeeded = coinControl->nFeeRate.GetFee(nBytes);

                    // If we made it here and we aren't even able to meet the relay fee on the next pass, give up
                    // because we must be at the maximum allowed fee.
                    if (nFeeNeeded < ::minRelayTxFee.GetFee(nBytes)) {
                        strFailReason = _("Transaction too large for fee policy");
                        return false;
                    }

                    if (nFeeRet >= nFeeNeeded) {
                        for (auto &usedCoin : setCoins) {
                            for (auto coin = itr->second.begin(); coin != itr->second.end(); coin++) {
                                if (usedCoin.first == coin->tx && usedCoin.second == coin->i) {
                                    itr->first -= coin->tx->tx->vout[coin->i].nValue;
                                    itr->second.erase(coin);
                                    break;
                                }
                            }
                        }

                        if (itr->second.empty()) {
                            valueAndUTXO.erase(itr);
                        }

                        // Generate hdMint
                        recipient = CWallet::CreateLelantusMintRecipient(privCoin, dMint);

                        // vout to mint
                        txout = CTxOut(recipient.nAmount, recipient.scriptPubKey);
                        LogPrintf("txout: %s\n", txout.ToString());

                        for (size_t i = 0; i != tx.vout.size(); i++) {
                            if (tx.vout[i].scriptPubKey.IsLelantusMint()) {
                                tx.vout[i] = txout;
                            }
                        }

                        break; // Done, enough fee included.
                    }

                    // Include more fee and try again.
                    nFeeRet = nFeeNeeded;
                    continue;
                }

                if(skipCoin)
                    continue;

                if (GetBoolArg("-walletrejectlongchains", DEFAULT_WALLET_REJECT_LONG_CHAINS)) {
                    // Lastly, ensure this tx will pass the mempool's chain limits
                    LockPoints lp;
                    CTxMemPoolEntry entry(MakeTransactionRef(tx), 0, 0, 0, 0, false, 0, lp);
                    CTxMemPool::setEntries setAncestors;
                    size_t nLimitAncestors = GetArg("-limitancestorcount", DEFAULT_ANCESTOR_LIMIT);
                    size_t nLimitAncestorSize = GetArg("-limitancestorsize", DEFAULT_ANCESTOR_SIZE_LIMIT) * 1000;
                    size_t nLimitDescendants = GetArg("-limitdescendantcount", DEFAULT_DESCENDANT_LIMIT);
                    size_t nLimitDescendantSize =
                            GetArg("-limitdescendantsize", DEFAULT_DESCENDANT_SIZE_LIMIT) * 1000;
                    std::string errString;
                    if (!mempool.CalculateMemPoolAncestors(entry, setAncestors, nLimitAncestors, nLimitAncestorSize,
                                                           nLimitDescendants, nLimitDescendantSize, errString)) {
                        strFailReason = _("Transaction has too long of a mempool chain");
                        return false;
                    }
                }

                // Sign
                int nIn = 0;
                CTransaction txNewConst(tx);
                for (const auto &coin : setCoins) {
                    bool signSuccess = false;
                    const CScript &scriptPubKey = coin.first->tx->vout[coin.second].scriptPubKey;
                    SignatureData sigdata;
                    if (sign)
                        signSuccess = ProduceSignature(TransactionSignatureCreator(this, &txNewConst, nIn,
                                                                                   coin.first->tx->vout[coin.second].nValue,
                                                                                   SIGHASH_ALL), scriptPubKey,
                                                       sigdata);
                    else
                        signSuccess = ProduceSignature(DummySignatureCreator(this), scriptPubKey, sigdata);

                    if (!signSuccess) {
                        strFailReason = _("Signing transaction failed");
                        return false;
                    } else {
                        UpdateTransaction(tx, nIn, sigdata);
                    }
                    nIn++;
                }

                wtx.SetTx(MakeTransactionRef(std::move(tx)));

                wtxAndFee.push_back(std::make_pair(wtx, nFeeRet));

                if (nChangePosInOut >= 0) {
                    // Cache wtx to somewhere because COutput use pointer of it.
                    cacheWtxs.push_back(wtx);
                    auto &wtx = cacheWtxs.back();

                    COutput out(&wtx, nChangePosInOut, wtx.GetDepthInMainChain(false), true, true);
                    auto val = wtx.tx->vout[nChangePosInOut].nValue;

                    bool added = false;
                    for (auto &utxos : valueAndUTXO) {
                        auto const &o = utxos.second.front();
                        if (o.tx->tx->vout[o.i].scriptPubKey == wtx.tx->vout[nChangePosInOut].scriptPubKey) {
                            utxos.first += val;
                            utxos.second.push_back(out);

                            added = true;
                        }
                    }

                    if (!added) {
                        valueAndUTXO.push_back({val, {out}});
                    }
                }

                nAllFeeRet += nFeeRet;
                dMints.push_back(dMint);
                if(!autoMintAll) {
                    valueToMint -= mintedValue;
                    if (valueToMint == 0)
                        break;
                }
            }
        }
    }

    if (!autoMintAll && valueToMint > 0) {
        return false;
    }

    return true;
}

bool
CWallet::CreateMintTransaction(CScript pubCoin, int64_t nValue, CWalletTx &wtxNew, CReserveKey &reservekey,
                                       int64_t &nFeeRet, std::string &strFailReason,
                                       const CCoinControl *coinControl) {
    std::vector <CRecipient> vecSend;
    CRecipient recipient = {pubCoin, nValue, false};
    vecSend.push_back(recipient);
    int nChangePosRet = -1;
    return CreateMintTransaction(vecSend, wtxNew, reservekey, nFeeRet, nChangePosRet, strFailReason,
                                         coinControl);
}

CWalletTx CWallet::CreateSigmaSpendTransaction(
    const std::vector<CRecipient>& recipients,
    CAmount& fee,
    std::vector<CSigmaEntry>& selected,
    std::vector<CHDMint>& changes,
    bool& fChangeAddedToFee,
    const CCoinControl *coinControl)
{
    // sanity check
    EnsureMintWalletAvailable();

    if (IsLocked()) {
        throw std::runtime_error(_("Wallet locked"));
    }

    // create transaction
    SigmaSpendBuilder builder(*this, *zwallet, coinControl);
    CWalletDB walletdb(strWalletFile);
    CWalletTx tx = builder.Build(recipients, fee, fChangeAddedToFee, walletdb);
    selected = builder.selected;
    changes = builder.changes;

    return tx;
}

std::string CWallet::MintAndStoreSigma(const std::vector<CRecipient>& vecSend,
                                       const std::vector<sigma::PrivateCoin>& privCoins,
                                       std::vector<CHDMint> vDMints,
                                       CWalletTx &wtxNew, bool fAskFee,
                                       const CCoinControl *coinControl) {
    std::string strError;

    EnsureMintWalletAvailable();

    if (IsLocked()) {
        strError = _("Error: Wallet locked, unable to create transaction!");
        LogPrintf("MintSigma() : %s", strError);
        return strError;
    }

    int totalValue = 0;
    BOOST_FOREACH(CRecipient recipient, vecSend){
        // Check amount
        if (recipient.nAmount <= 0)
            return _("Invalid amount");

        LogPrintf("MintSigma: value = %s\n", recipient.nAmount);
        totalValue += recipient.nAmount;

    }

    if ((totalValue + payTxFee.GetFeePerK()) > GetBalance())
        return _("Insufficient funds");

    LogPrintf("payTxFee.GetFeePerK()=%s\n", payTxFee.GetFeePerK());
    CReserveKey reservekey(this);
    int64_t nFeeRequired = 0;

    int nChangePosRet = -1;

    if (!CreateMintTransaction(vecSend, wtxNew, reservekey, nFeeRequired, nChangePosRet, strError, coinControl)) {
        LogPrintf("nFeeRequired=%s\n", nFeeRequired);
        if (totalValue + nFeeRequired > GetBalance())
            return strprintf(
                    _("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds!"),
                    FormatMoney(nFeeRequired).c_str());
        return strError;
    }

    if (fAskFee && !uiInterface.ThreadSafeAskFee(nFeeRequired)){
        LogPrintf("MintSigma: returning aborted..\n");
        return "ABORTED";
    }

    CValidationState state;
    if (!CommitTransaction(wtxNew, reservekey, g_connman.get(), state)) {
        return _(
                "Error: The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");
    } else {
        LogPrintf("CommitTransaction success!\n");
    }


    //update mints with full transaction hash and then database them
    CWalletDB walletdb(pwalletMain->strWalletFile);
    for (CHDMint dMint : vDMints) {
        dMint.SetTxHash(wtxNew.GetHash());
        zwallet->GetTracker().Add(walletdb, dMint, true);
        NotifyZerocoinChanged(this,
             dMint.GetPubcoinValue().GetHex(),
            "New (" + std::to_string(dMint.GetAmount()) + " mint)",
            CT_NEW);
    }

    // Update nCountNextUse in HDMint wallet database
    zwallet->UpdateCountDB(walletdb);

    return "";
}

std::string CWallet::MintAndStoreLelantus(const CAmount& value,
                                          std::vector<std::pair<CWalletTx, CAmount>>& wtxAndFee,
                                          std::vector<CHDMint>& mints,
                                          bool autoMintAll,
                                          bool fAskFee,
                                          const CCoinControl *coinControl) {
    std::string strError;

    EnsureMintWalletAvailable();

    if (IsLocked()) {
        strError = _("Error: Wallet locked, unable to create transaction!");
        LogPrintf("MintLelantus() : %s", strError);
        return strError;
    }


    if ((value + payTxFee.GetFeePerK()) > GetBalance())
        return _("Insufficient funds");

    LogPrintf("payTxFee.GetFeePerK()=%s\n", payTxFee.GetFeePerK());
    int64_t nFeeRequired = 0;

    int nChangePosRet = -1;

    std::vector<CHDMint> dMints;
    std::list<CReserveKey> reservekeys;
    if (!CreateLelantusMintTransactions(value, wtxAndFee, nFeeRequired, dMints, reservekeys, nChangePosRet, strError, coinControl, autoMintAll)) {
        return strError;
    }

    if (fAskFee && !uiInterface.ThreadSafeAskFee(nFeeRequired)){
        LogPrintf("MintLelantus: returning aborted..\n");
        return "ABORTED";
    }

    CValidationState state;
    CWalletDB walletdb(pwalletMain->strWalletFile);

    auto reservekey = reservekeys.begin();
    for(size_t i = 0; i < wtxAndFee.size(); i++) {
        if (!CommitTransaction(wtxAndFee[i].first, *reservekey++, g_connman.get(), state)) {
            return _(
                    "Error: The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");
        } else {
            LogPrintf("CommitTransaction success!\n");
        }

        //update mints with full transaction hash and then database them
        CHDMint dMintTmp = dMints[i];
        mints.push_back(dMints[i]);
        dMintTmp.SetTxHash(wtxAndFee[i].first.GetHash());
        zwallet->GetTracker().AddLelantus(walletdb, dMintTmp, true);
        NotifyZerocoinChanged(this,
            dMintTmp.GetPubcoinValue().GetHex(),
            "New (" + std::to_string(dMintTmp.GetAmount()) + " mint)",
            CT_NEW);
    }
    // Update nCountNextUse in HDMint wallet database
    zwallet->UpdateCountDB(walletdb);

    return "";
}

std::vector<CSigmaEntry> CWallet::SpendSigma(const std::vector<CRecipient>& recipients, CWalletTx& result)
{
    CAmount fee;

    return SpendSigma(recipients, result, fee);
}

std::vector<CSigmaEntry> CWallet::SpendSigma(
    const std::vector<CRecipient>& recipients,
    CWalletTx& result,
    CAmount& fee)
{
    // create transaction
    std::vector<CSigmaEntry> coins;
    std::vector<CHDMint> changes;
    bool fChangeAddedToFee;
    result = CreateSigmaSpendTransaction(recipients, fee, coins, changes, fChangeAddedToFee);

    CommitSigmaTransaction(result, coins, changes);

    return coins;
}

bool CWallet::CommitSigmaTransaction(CWalletTx& wtxNew, std::vector<CSigmaEntry>& selectedCoins, std::vector<CHDMint>& changes) {
    EnsureMintWalletAvailable();

    // commit
    try {
        CValidationState state;
        CReserveKey reserveKey(this);
        CommitTransaction(wtxNew, reserveKey, g_connman.get(), state);
    } catch (...) {
        auto error = _(
            "Error: The transaction was rejected! This might happen if some of "
            "the coins in your wallet were already spent, such as if you used "
            "a copy of wallet.dat and coins were spent in the copy but not "
            "marked as spent here."
        );

        std::throw_with_nested(std::runtime_error(error));
    }

    // mark selected coins as used
    sigma::CSigmaState* sigmaState = sigma::CSigmaState::GetState();
    CWalletDB db(strWalletFile);

    for (auto& coin : selectedCoins) {
        // get coin id & height
        int height, id;

        std::tie(height, id) = sigmaState->GetMintedCoinHeightAndId(sigma::PublicCoin(
            coin.value, coin.get_denomination()));

        // add CSigmaSpendEntry
        CSigmaSpendEntry spend;

        spend.coinSerial = coin.serialNumber;
        spend.hashTx = wtxNew.GetHash();
        spend.pubCoin = coin.value;
        spend.id = id;
        spend.set_denomination_value(coin.get_denomination_value());

        if (!db.WriteCoinSpendSerialEntry(spend)) {
            throw std::runtime_error(_("Failed to write coin serial number into wallet"));
        }

        //Set spent mint as used in memory
        uint256 hashPubcoin = primitives::GetPubCoinValueHash(coin.value);
        zwallet->GetTracker().SetPubcoinUsed(hashPubcoin, wtxNew.GetHash());
        CMintMeta metaCheck;
        zwallet->GetTracker().GetMetaFromPubcoin(hashPubcoin, metaCheck);
        if (!metaCheck.isUsed) {
            std::string strError = "Error, mint with pubcoin hash " + hashPubcoin.GetHex() + " did not get marked as used";
            LogPrintf("SpendSigma() : %s\n", strError.c_str());
        }

        //Set spent mint as used in DB
        zwallet->GetTracker().UpdateState(metaCheck);

        // update CSigmaEntry
        coin.IsUsed = true;
        coin.id = id;
        coin.nHeight = height;

        // raise event
        NotifyZerocoinChanged(
            this,
            coin.value.GetHex(),
            "Used (" + std::to_string(coin.get_denomination()) + " mint)",
            CT_UPDATED);
    }

    for (auto& change : changes) {
        change.SetTxHash(wtxNew.GetHash());
        zwallet->GetTracker().Add(db, change, true);

        // raise event
        NotifyZerocoinChanged(this,
            change.GetPubcoinValue().GetHex(),
            "New (" + std::to_string(change.GetAmount()) + " mint)",
            CT_NEW);
    }

    // Update nCountNextUse in HDMint wallet database
    zwallet->UpdateCountDB(db);

    return true;
}

std::vector<CLelantusEntry> CWallet::JoinSplitLelantus(const std::vector<CRecipient>& recipients, const std::vector<CAmount>& newMints, CWalletTx& result) {
    // create transaction
    std::vector<CLelantusEntry> spendCoins; //spends
    std::vector<CSigmaEntry> sigmaSpendCoins;
    std::vector<CHDMint> mintCoins; // new mints
    CAmount fee;
    result = CreateLelantusJoinSplitTransaction(recipients, fee, newMints, spendCoins, sigmaSpendCoins, mintCoins);

    CommitLelantusTransaction(result, spendCoins, sigmaSpendCoins, mintCoins);

    return spendCoins;
}

CWalletTx CWallet::CreateLelantusJoinSplitTransaction(
        const std::vector<CRecipient>& recipients,
        CAmount &fee,
        const std::vector<CAmount>& newMints,
        std::vector<CLelantusEntry>& spendCoins,
        std::vector<CSigmaEntry>& sigmaSpendCoins,
        std::vector<CHDMint>& mintCoins,
        const CCoinControl *coinControl,
        std::function<void(CTxOut & , LelantusJoinSplitBuilder const &)> modifier)
{
    // sanity check
    EnsureMintWalletAvailable();

    if (IsLocked()) {
        throw std::runtime_error(_("Wallet locked"));
    }

    // create transaction
    LelantusJoinSplitBuilder builder(*this, *zwallet, coinControl);

    CWalletTx tx = builder.Build(recipients, fee, newMints, modifier);
    spendCoins = builder.spendCoins;
    sigmaSpendCoins = builder.sigmaSpendCoins;
    mintCoins = builder.mintCoins;

    return tx;
}

std::pair<CAmount, unsigned int> CWallet::EstimateJoinSplitFee(
        CAmount required,
        bool subtractFeeFromAmount,
        std::list<CSigmaEntry> sigmaCoins,
        std::list<CLelantusEntry> coins,
        const CCoinControl *coinControl) {
    CAmount fee;
    unsigned size;
    std::vector<CLelantusEntry> spendCoins;
    std::vector<CSigmaEntry> sigmaSpendCoins;

    CAmount availableSigmaBalance(0);
    for (auto coin : sigmaCoins) {
        availableSigmaBalance += coin.get_denomination_value();
    }

    for (fee = payTxFee.GetFeePerK();;) {
        CAmount currentRequired = required;

        if (!subtractFeeFromAmount)
            currentRequired += fee;

        spendCoins.clear();
        sigmaSpendCoins.clear();
        auto &consensusParams = Params().GetConsensus();
        CAmount changeToMint = 0;

        std::vector<sigma::CoinDenomination> denomChanges;
        try {
            if (availableSigmaBalance > 0) {
                CAmount inputFromSigma;
                if (currentRequired > availableSigmaBalance)
                    inputFromSigma = availableSigmaBalance;
                else
                    inputFromSigma = currentRequired;
                this->GetCoinsToSpend(inputFromSigma, sigmaSpendCoins, denomChanges, sigmaCoins, //try to spend sigma first
                                       consensusParams.nMaxLelantusInputPerTransaction,
                                       consensusParams.nMaxValueLelantusSpendPerTransaction, coinControl);
                currentRequired -= inputFromSigma;
            }

            if (currentRequired > 0) {
                if (!this->GetCoinsToJoinSplit(currentRequired, spendCoins, changeToMint, coins,
                                                consensusParams.nMaxLelantusInputPerTransaction,
                                                consensusParams.nMaxValueLelantusSpendPerTransaction, coinControl)) {
                    return std::make_pair(0, 0);
                }
            }
        } catch (std::runtime_error const &) {
        }

        // 1054 is constant part, mainly Schnorr and Range proofs, 2560 is for each sigma/aux data
        // 179 other parts of tx, assuming 1 utxo and 1 jmint
        size = 1054 + 2560 * (spendCoins.size() + sigmaSpendCoins.size()) + 179;
        CAmount feeNeeded = CWallet::GetMinimumFee(size, nTxConfirmTarget, mempool);

        if (fee >= feeNeeded) {
            break;
        }

        fee = feeNeeded;

        if(subtractFeeFromAmount)
            break;
    }

    return std::make_pair(fee, size);
}

bool CWallet::CommitLelantusTransaction(CWalletTx& wtxNew, std::vector<CLelantusEntry>& spendCoins, std::vector<CSigmaEntry>& sigmaSpendCoins, std::vector<CHDMint>& mintCoins) {
    EnsureMintWalletAvailable();

    // commit
    try {
        CValidationState state;
        CReserveKey reserveKey(this);
        CommitTransaction(wtxNew, reserveKey, g_connman.get(), state);
    } catch (...) {
        auto error = _(
                "Error: The transaction was rejected! This might happen if some of "
                "the coins in your wallet were already spent, such as if you used "
                "a copy of wallet.dat and coins were spent in the copy but not "
                "marked as spent here."
        );

        std::throw_with_nested(std::runtime_error(error));
    }

    // mark selected coins as used
    lelantus::CLelantusState* lelantusState = lelantus::CLelantusState::GetState();
    CWalletDB db(strWalletFile);

    for (auto& coin : spendCoins) {
        // get coin id & height
        int height, id;

        std::tie(height, id) = lelantusState->GetMintedCoinHeightAndId(lelantus::PublicCoin(coin.value));

        // add CLelantusSpendEntry
        CLelantusSpendEntry spend;

        spend.coinSerial = coin.serialNumber;
        spend.hashTx = wtxNew.GetHash();
        spend.pubCoin = coin.value;
        spend.id = id;
        spend.amount = coin.amount;

        if (!db.WriteLelantusSpendSerialEntry(spend)) {
            throw std::runtime_error(_("Failed to write coin serial number into wallet"));
        }

        //Set spent mint as used in memory
        uint256 hashPubcoin = primitives::GetPubCoinValueHash(coin.value);
        zwallet->GetTracker().SetLelantusPubcoinUsed(hashPubcoin, wtxNew.GetHash());
        CLelantusMintMeta metaCheck;
        zwallet->GetTracker().GetLelantusMetaFromPubcoin(hashPubcoin, metaCheck);
        if (!metaCheck.isUsed) {
            std::string strError = "Error, mint with pubcoin hash " + hashPubcoin.GetHex() + " did not get marked as used";
            LogPrintf("SpendLelantus() : %s\n", strError.c_str());
        }

        //Set spent mint as used in DB
        zwallet->GetTracker().UpdateState(metaCheck);

        // update CLelantusEntry
        coin.IsUsed = true;
        coin.id = id;
        coin.nHeight = height;

        // raise event
        NotifyZerocoinChanged(
                this,
                coin.value.GetHex(),
                "Used (" + std::to_string(coin.amount) + " mint)",
                CT_UPDATED);
    }

    sigma::CSigmaState* sigmaState = sigma::CSigmaState::GetState();
    for (auto& coin : sigmaSpendCoins) {
        // get coin id & height
        int height, id;

        std::tie(height, id) = sigmaState->GetMintedCoinHeightAndId(sigma::PublicCoin(
            coin.value, coin.get_denomination()));

        // add CSigmaSpendEntry
        CSigmaSpendEntry spend;

        spend.coinSerial = coin.serialNumber;
        spend.hashTx = wtxNew.GetHash();
        spend.pubCoin = coin.value;
        spend.id = id;
        spend.set_denomination_value(coin.get_denomination_value());

        if (!db.WriteCoinSpendSerialEntry(spend)) {
            throw std::runtime_error(_("Failed to write coin serial number into wallet"));
        }

        //Set spent mint as used in memory
        uint256 hashPubcoin = primitives::GetPubCoinValueHash(coin.value);
        zwallet->GetTracker().SetPubcoinUsed(hashPubcoin, wtxNew.GetHash());
        CMintMeta metaCheck;
        zwallet->GetTracker().GetMetaFromPubcoin(hashPubcoin, metaCheck);
        if (!metaCheck.isUsed) {
            std::string strError = "Error, mint with pubcoin hash " + hashPubcoin.GetHex() + " did not get marked as used";
            LogPrintf("SpendZerocoin() : %s\n", strError.c_str());
        }

        //Set spent mint as used in DB
        zwallet->GetTracker().UpdateState(metaCheck);

        // update CSigmaEntry
        coin.IsUsed = true;
        coin.id = id;
        coin.nHeight = height;

        // raise event
        NotifyZerocoinChanged(
            this,
            coin.value.GetHex(),
            "Used (" + std::to_string(coin.get_denomination()) + " mint)",
            CT_UPDATED);
    }

    for (auto& coin : mintCoins) {
        coin.SetTxHash(wtxNew.GetHash());
        zwallet->GetTracker().AddLelantus(db, coin, true);

        // raise event
        NotifyZerocoinChanged(this,
                              coin.GetPubcoinValue().GetHex(),
                              "New (" + std::to_string(coin.GetAmount()) + " mint)",
                              CT_NEW);
    }

    // Update nCountNextUse in HDMint wallet database
    zwallet->UpdateCountDB(db);

    return true;
}


bool CWallet::GetMint(const uint256& hashSerial, CSigmaEntry& sigmaEntry, bool forEstimation) const
{
    EnsureMintWalletAvailable();

    if (IsLocked() && !forEstimation) {
        return false;
    }

    CMintMeta meta;
    if(!zwallet->GetTracker().GetMetaFromSerial(hashSerial, meta))
        return error("%s: serialhash %s is not in tracker", __func__, hashSerial.GetHex());

    CWalletDB walletdb(strWalletFile);
     if (meta.isDeterministic) {
        CHDMint dMint;
        if (!walletdb.ReadHDMint(meta.GetPubCoinValueHash(), false, dMint))
            return error("%s: failed to read deterministic mint", __func__);
        if (!zwallet->RegenerateMint(walletdb, dMint, sigmaEntry, forEstimation))
            return error("%s: failed to generate mint", __func__);

         return true;
    } else if (!walletdb.ReadSigmaEntry(meta.GetPubCoinValue(), sigmaEntry)) {
        return error("%s: failed to read sigmamint from database", __func__);
    }

     return true;
}

bool CWallet::GetMint(const uint256& hashSerial, CLelantusEntry& mint, bool forEstimation) const
{
    EnsureMintWalletAvailable();

    if (IsLocked() && !forEstimation) {
        return false;
    }

    CLelantusMintMeta meta;
    if(!zwallet->GetTracker().GetMetaFromSerial(hashSerial, meta))
        return error("%s: serialhash %s is not in tracker", __func__, hashSerial.GetHex());

    CWalletDB walletdb(strWalletFile);

    CHDMint dMint;
    if (!walletdb.ReadHDMint(meta.GetPubCoinValueHash(), true, dMint))
        return error("%s: failed to read deterministic Lelantus mint", __func__);
    if (!zwallet->RegenerateMint(walletdb, dMint, mint, forEstimation))
        return error("%s: failed to generate Lelantus mint", __func__);
    return true;

}

void CWallet::ListAccountCreditDebit(const std::string& strAccount, std::list<CAccountingEntry>& entries) {
    CWalletDB walletdb(strWalletFile);
    return walletdb.ListAccountCreditDebit(strAccount, entries);
}

bool CWallet::AddAccountingEntry(const CAccountingEntry& acentry)
{
    CWalletDB walletdb(strWalletFile);

    return AddAccountingEntry(acentry, &walletdb);
}

bool CWallet::AddAccountingEntry(const CAccountingEntry& acentry, CWalletDB *pwalletdb)
{
    if (!pwalletdb->WriteAccountingEntry_Backend(acentry))
        return false;

    laccentries.push_back(acentry);
    CAccountingEntry & entry = laccentries.back();
    wtxOrdered.insert(make_pair(entry.nOrderPos, TxPair((CWalletTx*)0, &entry)));

    return true;
}

CAmount CWallet::GetRequiredFee(unsigned int nTxBytes)
{
    return std::max(minTxFee.GetFee(nTxBytes), ::minRelayTxFee.GetFee(nTxBytes));
}

CAmount CWallet::GetMinimumFee(unsigned int nTxBytes, unsigned int nConfirmTarget, const CTxMemPool& pool)
{
    // payTxFee is the user-set global for desired feerate
    return GetMinimumFee(nTxBytes, nConfirmTarget, pool, payTxFee.GetFee(nTxBytes));
}

CAmount CWallet::GetMinimumFee(unsigned int nTxBytes, unsigned int nConfirmTarget, const CTxMemPool& pool, CAmount targetFee)
{
    CAmount nFeeNeeded = targetFee;
    // User didn't set: use -txconfirmtarget to estimate...
    if (nFeeNeeded == 0) {
        int estimateFoundTarget = nConfirmTarget;
        nFeeNeeded = pool.estimateSmartFee(nConfirmTarget, &estimateFoundTarget).GetFee(nTxBytes);
        // ... unless we don't have enough mempool data for estimatefee, then use fallbackFee
        if (nFeeNeeded == 0)
            nFeeNeeded = fallbackFee.GetFee(nTxBytes);
    }
    // prevent user from paying a fee below minRelayTxFee or minTxFee
    nFeeNeeded = std::max(nFeeNeeded, GetRequiredFee(nTxBytes));
    // But always obey the maximum
    if (nFeeNeeded > maxTxFee)
        nFeeNeeded = maxTxFee;

    return nFeeNeeded;
}

DBErrors CWallet::LoadWallet(bool& fFirstRunRet)
{
    if (!fFileBacked)
        return DB_LOAD_OK;
    fFirstRunRet = false;
    DBErrors nLoadWalletRet = CWalletDB(strWalletFile,"cr+").LoadWallet(this);
    if (nLoadWalletRet == DB_NEED_REWRITE)
    {
        if (CDB::Rewrite(strWalletFile, "\x04pool"))
        {
            LOCK(cs_wallet);
            setKeyPool.clear();
            // Note: can't top-up keypool here, because wallet is locked.
            // User will be prompted to unlock wallet the next operation
            // that requires a new key.
        }
    }

    {
        LOCK2(cs_main, cs_wallet);
        for (auto& pair : mapWallet) {
            for(unsigned int i = 0; i < pair.second.tx->vout.size(); ++i) {
                if (IsMine(pair.second.tx->vout[i]) && !IsSpent(pair.first, i)) {
                    setWalletUTXO.insert(COutPoint(pair.first, i));
                }
            }
        }
    }

    if (nLoadWalletRet != DB_LOAD_OK)
        return nLoadWalletRet;
    fFirstRunRet = !vchDefaultKey.IsValid();

    uiInterface.LoadWallet(this);

    return DB_LOAD_OK;
}

// Goes through all wallet transactions and checks if they are masternode collaterals, in which case these are locked
// This avoids accidential spending of collaterals. They can still be unlocked manually if a spend is really intended.
void CWallet::AutoLockMasternodeCollaterals()
{
    auto mnList = deterministicMNManager->GetListAtChainTip();

    LOCK2(cs_main, cs_wallet);
    for (const auto& pair : mapWallet) {
        for (unsigned int i = 0; i < pair.second.tx->vout.size(); ++i) {
            if (IsMine(pair.second.tx->vout[i]) && !IsSpent(pair.first, i)) {
                if (deterministicMNManager->IsProTxWithCollateral(pair.second.tx, i) || mnList.HasMNByCollateral(COutPoint(pair.first, i))) {
                    LockCoin(COutPoint(pair.first, i));
                }
            }
        }
    }
}

DBErrors CWallet::ZapSelectTx(std::vector<uint256>& vHashIn, std::vector<uint256>& vHashOut)
{
    if (!fFileBacked)
        return DB_LOAD_OK;
    DBErrors nZapSelectTxRet = CWalletDB(strWalletFile,"cr+").ZapSelectTx(this, vHashIn, vHashOut);
    if (nZapSelectTxRet == DB_NEED_REWRITE)
    {
        if (CDB::Rewrite(strWalletFile, "\x04pool"))
        {
            LOCK(cs_wallet);
            setKeyPool.clear();
            // Note: can't top-up keypool here, because wallet is locked.
            // User will be prompted to unlock wallet the next operation
            // that requires a new key.
        }
    }

    if (nZapSelectTxRet != DB_LOAD_OK)
        return nZapSelectTxRet;

    MarkDirty();

    return DB_LOAD_OK;

}

DBErrors CWallet::ZapWalletTx(std::vector<CWalletTx>& vWtx)
{
    if (!fFileBacked)
        return DB_LOAD_OK;
    DBErrors nZapWalletTxRet = CWalletDB(strWalletFile,"cr+").ZapWalletTx(this, vWtx);
    if (nZapWalletTxRet == DB_NEED_REWRITE)
    {
        if (CDB::Rewrite(strWalletFile, "\x04pool"))
        {
            LOCK(cs_wallet);
            setKeyPool.clear();
            // Note: can't top-up keypool here, because wallet is locked.
            // User will be prompted to unlock wallet the next operation
            // that requires a new key.
        }
    }

    if (nZapWalletTxRet != DB_LOAD_OK)
        return nZapWalletTxRet;

    return DB_LOAD_OK;
}

DBErrors CWallet::ZapSigmaMints() {
    if (!fFileBacked)
        return DB_LOAD_OK;
    DBErrors nZapSigmaMintRet = CWalletDB(strWalletFile, "cr+").ZapSigmaMints(this);
    if (nZapSigmaMintRet != DB_LOAD_OK){
        LogPrintf("Failed to remmove Sigma mints from CWalletDB");
        return nZapSigmaMintRet;
    }

    return DB_LOAD_OK;
}

DBErrors CWallet::ZapLelantusMints() {
    if (!fFileBacked)
        return DB_LOAD_OK;
    DBErrors nZapLelantusMintRet = CWalletDB(strWalletFile, "cr+").ZapLelantusMints(this);
    if (nZapLelantusMintRet != DB_LOAD_OK){
        LogPrintf("Failed to remove Lelantus mints from CWalletDB");
        return nZapLelantusMintRet;
    }

    return DB_LOAD_OK;
}


bool CWallet::SetAddressBook(const CTxDestination& address, const std::string& strName, const std::string& strPurpose)
{
    bool fUpdated = false;
    {
        LOCK(cs_wallet); // mapAddressBook
        std::map<CTxDestination, CAddressBookData>::iterator mi = mapAddressBook.find(address);
        fUpdated = mi != mapAddressBook.end();
        mapAddressBook[address].name = strName;
        if (!strPurpose.empty()) /* update purpose only if requested */
            mapAddressBook[address].purpose = strPurpose;
    }
    NotifyAddressBookChanged(this, address, strName, ::IsMine(*this, address) != ISMINE_NO,
                             strPurpose, (fUpdated ? CT_UPDATED : CT_NEW) );
    if (!fFileBacked)
        return false;
    if (!strPurpose.empty() && !CWalletDB(strWalletFile).WritePurpose(CBitcoinAddress(address).ToString(), strPurpose))
        return false;
    return CWalletDB(strWalletFile).WriteName(CBitcoinAddress(address).ToString(), strName);
}

bool CWallet::DelAddressBook(const CTxDestination& address)
{
    {
        LOCK(cs_wallet); // mapAddressBook

        if(fFileBacked)
        {
            // Delete destdata tuples associated with address
            std::string strAddress = CBitcoinAddress(address).ToString();
            BOOST_FOREACH(const PAIRTYPE(std::string, std::string) &item, mapAddressBook[address].destdata)
            {
                CWalletDB(strWalletFile).EraseDestData(strAddress, item.first);
            }
        }
        mapAddressBook.erase(address);
    }

    NotifyAddressBookChanged(this, address, "", ::IsMine(*this, address) != ISMINE_NO, "", CT_DELETED);

    if (!fFileBacked)
        return false;
    CWalletDB(strWalletFile).ErasePurpose(CBitcoinAddress(address).ToString());
    return CWalletDB(strWalletFile).EraseName(CBitcoinAddress(address).ToString());
}

const std::string& CWallet::GetAccountName(const CScript& scriptPubKey) const
{
    CTxDestination address;
    if (ExtractDestination(scriptPubKey, address) && !scriptPubKey.IsUnspendable()) {
        auto mi = mapAddressBook.find(address);
        if (mi != mapAddressBook.end()) {
            return mi->second.name;
        }
    }
    // A scriptPubKey that doesn't have an entry in the address book is
    // associated with the default account ("").
    const static std::string DEFAULT_ACCOUNT_NAME;
    return DEFAULT_ACCOUNT_NAME;
}

bool CWallet::SetDefaultKey(const CPubKey &vchPubKey)
{
    if (fFileBacked)
    {
        if (!CWalletDB(strWalletFile).WriteDefaultKey(vchPubKey))
            return false;
    }
    vchDefaultKey = vchPubKey;
    return true;
}

/**
 * Mark old keypool keys as used,
 * and generate all new keys
 */
bool CWallet::NewKeyPool()
{
    {
        LOCK(cs_wallet);
        CWalletDB walletdb(strWalletFile);
        BOOST_FOREACH(int64_t nIndex, setKeyPool)
            walletdb.ErasePool(nIndex);
        setKeyPool.clear();

        if (IsLocked())
            return false;

        int64_t nKeys = std::max(GetArg("-keypool", DEFAULT_KEYPOOL_SIZE), (int64_t)0);
        for (int i = 0; i < nKeys; i++)
        {
            int64_t nIndex = i+1;
            walletdb.WritePool(nIndex, CKeyPool(GenerateNewKey()));
            setKeyPool.insert(nIndex);
        }
        LogPrintf("CWallet::NewKeyPool wrote %d new keys\n", nKeys);
    }
    return true;
}

bool CWallet::TopUpKeyPool(unsigned int kpSize)
{
    {
        LOCK(cs_wallet);

        if (IsLocked())
            return false;

        CWalletDB walletdb(strWalletFile);

        // Top up key pool
        unsigned int nTargetSize;
        if (kpSize > 0)
            nTargetSize = kpSize;
        else
            nTargetSize = std::max(GetArg("-keypool", DEFAULT_KEYPOOL_SIZE), (int64_t) 0);

        while (setKeyPool.size() < (nTargetSize + 1))
        {
            int64_t nEnd = 1;
            if (!setKeyPool.empty())
                nEnd = *(--setKeyPool.end()) + 1;
            if (!walletdb.WritePool(nEnd, CKeyPool(GenerateNewKey())))
                throw std::runtime_error(std::string(__func__) + ": writing generated key failed");
            setKeyPool.insert(nEnd);
            LogPrintf("keypool added key %d, size=%u\n", nEnd, setKeyPool.size());
        }
    }
    return true;
}

void CWallet::ReserveKeyFromKeyPool(int64_t& nIndex, CKeyPool& keypool)
{
    nIndex = -1;
    keypool.vchPubKey = CPubKey();
    {
        LOCK(cs_wallet);

        if (!IsLocked())
            TopUpKeyPool();

        // Get the oldest key
        if(setKeyPool.empty())
            return;

        CWalletDB walletdb(strWalletFile);

        nIndex = *(setKeyPool.begin());
        setKeyPool.erase(setKeyPool.begin());
        if (!walletdb.ReadPool(nIndex, keypool))
            throw std::runtime_error(std::string(__func__) + ": read failed");
        if (!HaveKey(keypool.vchPubKey.GetID()))
            throw std::runtime_error(std::string(__func__) + ": unknown key in key pool");
        assert(keypool.vchPubKey.IsValid());
        LogPrintf("keypool reserve %d\n", nIndex);
    }
}

void CWallet::KeepKey(int64_t nIndex)
{
    // Remove from key pool
    if (fFileBacked)
    {
        CWalletDB walletdb(strWalletFile);
        walletdb.ErasePool(nIndex);
    }
    LogPrintf("keypool keep %d\n", nIndex);
}

void CWallet::ReturnKey(int64_t nIndex)
{
    // Return to key pool
    {
        LOCK(cs_wallet);
        setKeyPool.insert(nIndex);
    }
    LogPrintf("keypool return %d\n", nIndex);
}

bool CWallet::GetKeyFromPool(CPubKey& result)
{
    int64_t nIndex = 0;
    CKeyPool keypool;
    {
        LOCK(cs_wallet);
        ReserveKeyFromKeyPool(nIndex, keypool);
        if (nIndex == -1)
        {
            if (IsLocked()) return false;
            result = GenerateNewKey();
            return true;
        }
        KeepKey(nIndex);
        result = keypool.vchPubKey;
    }
    return true;
}

int64_t CWallet::GetOldestKeyPoolTime()
{
    LOCK(cs_wallet);

    // if the keypool is empty, return <NOW>
    if (setKeyPool.empty())
        return GetTime();

    // load oldest key from keypool, get time and return
    CKeyPool keypool;
    CWalletDB walletdb(strWalletFile);
    int64_t nIndex = *(setKeyPool.begin());
    if (!walletdb.ReadPool(nIndex, keypool))
        throw std::runtime_error(std::string(__func__) + ": read oldest key in keypool failed");
    assert(keypool.vchPubKey.IsValid());
    return keypool.nTime;
}

std::map<CTxDestination, CAmount> CWallet::GetAddressBalances()
{
    std::map<CTxDestination, CAmount> balances;

    {
        LOCK(cs_wallet);
        BOOST_FOREACH(PAIRTYPE(uint256, CWalletTx) walletEntry, mapWallet)
        {
            CWalletTx *pcoin = &walletEntry.second;

            if (!pcoin->IsTrusted())
                continue;

            if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity() > 0)
                continue;

            int nDepth = pcoin->GetDepthInMainChain();
            if (nDepth < (pcoin->IsFromMe(ISMINE_ALL) ? 0 : 1))
                continue;

            for (unsigned int i = 0; i < pcoin->tx->vout.size(); i++)
            {
                CTxDestination addr;
                if (!IsMine(pcoin->tx->vout[i]))
                    continue;
                if(!ExtractDestination(pcoin->tx->vout[i].scriptPubKey, addr))
                    continue;

                CAmount n = IsSpent(walletEntry.first, i) ? 0 : pcoin->tx->vout[i].nValue;

                if (!balances.count(addr))
                    balances[addr] = 0;
                balances[addr] += n;
            }
        }
    }

    return balances;
}

std::set< std::set<CTxDestination> > CWallet::GetAddressGroupings()
{
    AssertLockHeld(cs_wallet); // mapWallet
    std::set< std::set<CTxDestination> > groupings;
    std::set<CTxDestination> grouping;

    BOOST_FOREACH(PAIRTYPE(uint256, CWalletTx) walletEntry, mapWallet)
    {
        CWalletTx *pcoin = &walletEntry.second;

        if (pcoin->tx->vin.size() > 0 &&
            !(pcoin->tx->IsZerocoinSpend() || pcoin->tx->IsSigmaSpend() || pcoin->tx->IsZerocoinRemint()) || pcoin->tx->IsLelantusJoinSplit()) { /* Spends have no standard input */
            bool any_mine = false;
            // group all input addresses with each other
            BOOST_FOREACH(CTxIn txin, pcoin->tx->vin)
            {
                CTxDestination address;
                if(!IsMine(txin)) /* If this input isn't mine, ignore it */
                    continue;
                if(!ExtractDestination(mapWallet[txin.prevout.hash].tx->vout[txin.prevout.n].scriptPubKey, address))
                    continue;
                grouping.insert(address);
                any_mine = true;
            }

            // group change with input addresses
            if (any_mine)
            {
                for (uint32_t i = 0; i < pcoin->tx->vout.size(); i++) {
                    if (pcoin->IsChange(i)) {
                        CTxDestination addr;
                        if (!ExtractDestination(pcoin->tx->vout[i].scriptPubKey, addr)) {
                            continue;
                        }
                        grouping.insert(addr);
                    }
                }
            }
            if (grouping.size() > 0)
            {
                groupings.insert(grouping);
                grouping.clear();
            }
        }

        // group lone addrs by themselves
        for (unsigned int i = 0; i < pcoin->tx->vout.size(); i++)
            if (IsMine(pcoin->tx->vout[i]))
            {
                CTxDestination address;
                if(!ExtractDestination(pcoin->tx->vout[i].scriptPubKey, address))
                    continue;
                grouping.insert(address);
                groupings.insert(grouping);
                grouping.clear();
            }
    }

    std::set< std::set<CTxDestination>* > uniqueGroupings; // a set of pointers to groups of addresses
    std::map< CTxDestination, std::set<CTxDestination>* > setmap;  // map addresses to the unique group containing it
    BOOST_FOREACH(std::set<CTxDestination> _grouping, groupings)
    {
        // make a set of all the groups hit by this new group
        std::set< std::set<CTxDestination>* > hits;
        std::map< CTxDestination, std::set<CTxDestination>* >::iterator it;
        BOOST_FOREACH(CTxDestination address, _grouping)
            if ((it = setmap.find(address)) != setmap.end())
                hits.insert((*it).second);

        // merge all hit groups into a new single group and delete old groups
        std::set<CTxDestination>* merged = new std::set<CTxDestination>(_grouping);
        BOOST_FOREACH(std::set<CTxDestination>* hit, hits)
        {
            merged->insert(hit->begin(), hit->end());
            uniqueGroupings.erase(hit);
            delete hit;
        }
        uniqueGroupings.insert(merged);

        // update setmap
        BOOST_FOREACH(CTxDestination element, *merged)
            setmap[element] = merged;
    }

    std::set< std::set<CTxDestination> > ret;
    BOOST_FOREACH(std::set<CTxDestination>* uniqueGrouping, uniqueGroupings)
    {
        ret.insert(*uniqueGrouping);
        delete uniqueGrouping;
    }

    return ret;
}

std::set<CTxDestination> CWallet::GetAccountAddresses(const std::string& strAccount) const
{
    LOCK(cs_wallet);
    std::set<CTxDestination> result;
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, CAddressBookData)& item, mapAddressBook)
    {
        const CTxDestination& address = item.first;
        const std::string& strName = item.second.name;
        if (strName == strAccount)
            result.insert(address);
    }
    return result;
}

bool CReserveKey::GetReservedKey(CPubKey& pubkey)
{
    if (nIndex == -1)
    {
        CKeyPool keypool;
        pwallet->ReserveKeyFromKeyPool(nIndex, keypool);
        if (nIndex != -1)
            vchPubKey = keypool.vchPubKey;
        else {
            return false;
        }
    }
    assert(vchPubKey.IsValid());
    pubkey = vchPubKey;
    return true;
}

void CReserveKey::KeepKey()
{
    if (nIndex != -1)
        pwallet->KeepKey(nIndex);
    nIndex = -1;
    vchPubKey = CPubKey();
}

void CReserveKey::ReturnKey()
{
    if (nIndex != -1)
        pwallet->ReturnKey(nIndex);
    nIndex = -1;
    vchPubKey = CPubKey();
}

void CWallet::GetAllReserveKeys(std::set<CKeyID>& setAddress) const
{
    setAddress.clear();

    CWalletDB walletdb(strWalletFile);

    LOCK2(cs_main, cs_wallet);
    BOOST_FOREACH(const int64_t& id, setKeyPool)
    {
        CKeyPool keypool;
        if (!walletdb.ReadPool(id, keypool))
            throw std::runtime_error(std::string(__func__) + ": read failed");
        assert(keypool.vchPubKey.IsValid());
        CKeyID keyID = keypool.vchPubKey.GetID();
        if (!HaveKey(keyID))
            throw std::runtime_error(std::string(__func__) + ": unknown key in key pool");
        setAddress.insert(keyID);
    }
}

bool CWallet::UpdatedTransaction(const uint256 &hashTx)
{
    {
        LOCK(cs_wallet);
        // Only notify UI if this transaction is in this wallet
        std::map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(hashTx);
        if (mi != mapWallet.end()) {
            NotifyTransactionChanged(this, hashTx, CT_UPDATED);
            return true;
        }
    }
    return false;
}

void CWallet::GetScriptForMining(boost::shared_ptr<CReserveScript> &script)
{
    boost::shared_ptr<CReserveKey> rKey(new CReserveKey(this));
    CPubKey pubkey;
    if (!rKey->GetReservedKey(pubkey))
        return;

    script = rKey;
    script->reserveScript = CScript() << ToByteVector(pubkey) << OP_CHECKSIG;
}

void CWallet::LockCoin(const COutPoint& output)
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    setLockedCoins.insert(output);
}

void CWallet::UnlockCoin(const COutPoint& output)
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    setLockedCoins.erase(output);
}

void CWallet::UnlockAllCoins()
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    setLockedCoins.clear();
}

bool CWallet::IsLockedCoin(uint256 hash, unsigned int n) const
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    COutPoint outpt(hash, n);

    return (setLockedCoins.count(outpt) > 0);
}

void CWallet::ListLockedCoins(std::vector<COutPoint>& vOutpts)
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    for (std::set<COutPoint>::iterator it = setLockedCoins.begin();
         it != setLockedCoins.end(); it++) {
        COutPoint outpt = (*it);
        vOutpts.push_back(outpt);
    }
}

bool CWallet::HasMasternode(){

    auto mnList = deterministicMNManager->GetListForBlock(chainActive.Tip());

    AssertLockHeld(cs_wallet);
    for (const auto &o : setWalletUTXO) {
        if (mapWallet.count(o.hash)) {
            const auto &p = mapWallet[o.hash];
            if (deterministicMNManager->IsProTxWithCollateral(p.tx, o.n) || mnList.HasMNByCollateral(o)) {
                return true;
            }
        }
    }

    return false;
}

void CWallet::ListProTxCoins(std::vector<COutPoint>& vOutpts)
{
    auto mnList = deterministicMNManager->GetListForBlock(chainActive.Tip());

    AssertLockHeld(cs_wallet);
    for (const auto &o : setWalletUTXO) {
        if (mapWallet.count(o.hash)) {
            const auto &p = mapWallet[o.hash];
            if (deterministicMNManager->IsProTxWithCollateral(p.tx, o.n) || mnList.HasMNByCollateral(o)) {
                vOutpts.emplace_back(o);
            }
        }
    }
}

/** @} */ // end of Actions

class CAffectedKeysVisitor : public boost::static_visitor<void> {
private:
    const CKeyStore &keystore;
    std::vector<CKeyID> &vKeys;

public:
    CAffectedKeysVisitor(const CKeyStore &keystoreIn, std::vector<CKeyID> &vKeysIn) : keystore(keystoreIn), vKeys(vKeysIn) {}

    void Process(const CScript &script) {
        txnouttype type;
        std::vector<CTxDestination> vDest;
        int nRequired;
        if (ExtractDestinations(script, type, vDest, nRequired)) {
            BOOST_FOREACH(const CTxDestination &dest, vDest)
                boost::apply_visitor(*this, dest);
        }
    }

    void operator()(const CKeyID &keyId) {
        if (keystore.HaveKey(keyId))
            vKeys.push_back(keyId);
    }

    void operator()(const CScriptID &scriptId) {
        CScript script;
        if (keystore.GetCScript(scriptId, script))
            Process(script);
    }

    void operator()(const CNoDestination &none) {}
};

void CWallet::GetKeyBirthTimes(std::map<CTxDestination, int64_t> &mapKeyBirth) const {
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    mapKeyBirth.clear();

    // get birth times for keys with metadata
    for (const auto& entry : mapKeyMetadata) {
        if (entry.second.nCreateTime) {
            mapKeyBirth[entry.first] = entry.second.nCreateTime;
        }
    }

    // map in which we'll infer heights of other keys
    CBlockIndex *pindexMax = chainActive[std::max(0, chainActive.Height() - 144)]; // the tip can be reorganized; use a 144-block safety margin
    std::map<CKeyID, CBlockIndex*> mapKeyFirstBlock;
    std::set<CKeyID> setKeys;
    GetKeys(setKeys);
    BOOST_FOREACH(const CKeyID &keyid, setKeys) {
        if (mapKeyBirth.count(keyid) == 0)
            mapKeyFirstBlock[keyid] = pindexMax;
    }
    setKeys.clear();

    // if there are no such keys, we're done
    if (mapKeyFirstBlock.empty())
        return;

    // find first block that affects those keys, if there are any left
    std::vector<CKeyID> vAffected;
    for (std::map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); it++) {
        // iterate over all wallet transactions...
        const CWalletTx &wtx = (*it).second;
        BlockMap::const_iterator blit = mapBlockIndex.find(wtx.hashBlock);
        if (blit != mapBlockIndex.end() && chainActive.Contains(blit->second)) {
            // ... which are already in a block
            int nHeight = blit->second->nHeight;
            BOOST_FOREACH(const CTxOut &txout, wtx.tx->vout) {
                // iterate over all their outputs
                CAffectedKeysVisitor(*this, vAffected).Process(txout.scriptPubKey);
                BOOST_FOREACH(const CKeyID &keyid, vAffected) {
                    // ... and all their affected keys
                    std::map<CKeyID, CBlockIndex*>::iterator rit = mapKeyFirstBlock.find(keyid);
                    if (rit != mapKeyFirstBlock.end() && nHeight < rit->second->nHeight)
                        rit->second = blit->second;
                }
                vAffected.clear();
            }
        }
    }

    // Extract block timestamps for those keys
    for (std::map<CKeyID, CBlockIndex*>::const_iterator it = mapKeyFirstBlock.begin(); it != mapKeyFirstBlock.end(); it++)
        mapKeyBirth[it->first] = it->second->GetBlockTime() - 7200; // block times can be 2h off
}

bool CWallet::AddDestData(const CTxDestination &dest, const std::string &key, const std::string &value)
{
    if (boost::get<CNoDestination>(&dest))
        return false;

    mapAddressBook[dest].destdata.insert(std::make_pair(key, value));
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).WriteDestData(CBitcoinAddress(dest).ToString(), key, value);
}

bool CWallet::EraseDestData(const CTxDestination &dest, const std::string &key)
{
    if (!mapAddressBook[dest].destdata.erase(key))
        return false;
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).EraseDestData(CBitcoinAddress(dest).ToString(), key);
}

bool CWallet::LoadDestData(const CTxDestination &dest, const std::string &key, const std::string &value)
{
    mapAddressBook[dest].destdata.insert(std::make_pair(key, value));
    return true;
}

bool CWallet::GetDestData(const CTxDestination &dest, const std::string &key, std::string *value) const
{
    std::map<CTxDestination, CAddressBookData>::const_iterator i = mapAddressBook.find(dest);
    if(i != mapAddressBook.end())
    {
        CAddressBookData::StringMap::const_iterator j = i->second.destdata.find(key);
        if(j != i->second.destdata.end())
        {
            if(value)
                *value = j->second;
            return true;
        }
    }
    return false;
}

std::string CWallet::GetWalletHelpString(bool showDebug)
{
    std::string strUsage = HelpMessageGroup(_("Wallet options:"));
    strUsage += HelpMessageOpt("-disablewallet", _("Do not load the wallet and disable wallet RPC calls"));
    strUsage += HelpMessageOpt("-keypool=<n>", strprintf(_("Set key pool size to <n> (default: %u)"), DEFAULT_KEYPOOL_SIZE));
    strUsage += HelpMessageOpt("-fallbackfee=<amt>", strprintf(_("A fee rate (in %s/kB) that will be used when fee estimation has insufficient data (default: %s)"),
                                                               CURRENCY_UNIT, FormatMoney(DEFAULT_FALLBACK_FEE)));
    strUsage += HelpMessageOpt("-mintxfee=<amt>", strprintf(_("Fees (in %s/kB) smaller than this are considered zero fee for transaction creation (default: %s)"),
                                                            CURRENCY_UNIT, FormatMoney(DEFAULT_TRANSACTION_MINFEE)));
    strUsage += HelpMessageOpt("-paytxfee=<amt>", strprintf(_("Fee (in %s/kB) to add to transactions you send (default: %s)"),
                                                            CURRENCY_UNIT, FormatMoney(payTxFee.GetFeePerK())));
    strUsage += HelpMessageOpt("-rescan", _("Rescan the block chain for missing wallet transactions on startup"));
    strUsage += HelpMessageOpt("-salvagewallet", _("Attempt to recover private keys from a corrupt wallet on startup"));
    if (showDebug)
        strUsage += HelpMessageOpt("-sendfreetransactions", strprintf(_("Send transactions as zero-fee transactions if possible (default: %u)"), DEFAULT_SEND_FREE_TRANSACTIONS));
    strUsage += HelpMessageOpt("-spendzeroconfchange", strprintf(_("Spend unconfirmed change when sending transactions (default: %u)"), DEFAULT_SPEND_ZEROCONF_CHANGE));
    strUsage += HelpMessageOpt("-txconfirmtarget=<n>", strprintf(_("If paytxfee is not set, include enough fee so transactions begin confirmation on average within n blocks (default: %u)"), DEFAULT_TX_CONFIRM_TARGET));
    strUsage += HelpMessageOpt("-usehd", _("Use hierarchical deterministic key generation (HD) after BIP32. Only has effect during wallet creation/first start") + " " + strprintf(_("(default: %u)"), DEFAULT_USE_HD_WALLET));
    strUsage += HelpMessageOpt("-usemnemonic", _("Use Mnemonic code for generating deterministic keys. Only has effect during wallet creation/first start") +
                               " " + strprintf(_("(default: %u)"), DEFAULT_USE_MNEMONIC));
    strUsage += HelpMessageOpt("-mnemonic=<text>", _("User defined mnemonic for HD wallet (bip39). Only has effect during wallet creation/first start (default: randomly generated)"));
    strUsage += HelpMessageOpt("-mnemonicpassphrase=<text>", _("User defined mnemonic passphrase for HD wallet (BIP39). Only has effect during wallet creation/first start (default: empty string)"));
    strUsage += HelpMessageOpt("-hdseed=<hex>", _("User defined seed for HD wallet (should be in hex). Only has effect during wallet creation/first start (default: randomly generated)"));
    strUsage += HelpMessageOpt("-batching", _("In case of sync/reindex verifies sigma/lelantus proofs with batch verification, default: true"));
    strUsage += HelpMessageOpt("-walletrbf", strprintf(_("Send transactions with full-RBF opt-in enabled (default: %u)"), DEFAULT_WALLET_RBF));
    strUsage += HelpMessageOpt("-upgradewallet", _("Upgrade wallet to latest format on startup"));
    strUsage += HelpMessageOpt("-wallet=<file>", _("Specify wallet file (within data directory)") + " " + strprintf(_("(default: %s)"), DEFAULT_WALLET_DAT));
    strUsage += HelpMessageOpt("-walletbroadcast", _("Make the wallet broadcast transactions") + " " + strprintf(_("(default: %u)"), DEFAULT_WALLETBROADCAST));
    strUsage += HelpMessageOpt("-walletnotify=<cmd>", _("Execute command when a wallet transaction changes (%s in cmd is replaced by TxID)"));
    strUsage += HelpMessageOpt("-zapwalletmints", _("Delete all Sigma mints and only recover those parts of the blockchain through -reindex on startup"));
    strUsage += HelpMessageOpt("-zapwallettxes=<mode>", _("Delete all wallet transactions and only recover those parts of the blockchain through -rescan on startup") +
                               " " + _("(1 = keep tx meta data e.g. account owner and payment request information, 2 = drop tx meta data)"));

    if (showDebug)
    {
        strUsage += HelpMessageGroup(_("Wallet debugging/testing options:"));

        strUsage += HelpMessageOpt("-dblogsize=<n>", strprintf("Flush wallet database activity from memory to disk log every <n> megabytes (default: %u)", DEFAULT_WALLET_DBLOGSIZE));
        strUsage += HelpMessageOpt("-flushwallet", strprintf("Run a thread to flush wallet periodically (default: %u)", DEFAULT_FLUSHWALLET));
        strUsage += HelpMessageOpt("-privdb", strprintf("Sets the DB_PRIVATE flag in the wallet db environment (default: %u)", DEFAULT_WALLET_PRIVDB));
        strUsage += HelpMessageOpt("-walletrejectlongchains", strprintf(_("Wallet will not create transactions that violate mempool chain limits (default: %u)"), DEFAULT_WALLET_REJECT_LONG_CHAINS));
    }

    return strUsage;
}

CWallet* CWallet::CreateWalletFromFile(const std::string walletFile)
{
    if (GetBoolArg("-zapwalletmints", false)) {
        uiInterface.InitMessage(_("Zapping all Sigma mints from wallet..."));

        CWallet *tempWallet = new CWallet(walletFile);
        DBErrors nZapMintRet = tempWallet->ZapSigmaMints();
        DBErrors nZapLelantusMintRet = tempWallet->ZapLelantusMints();
        if (nZapMintRet != DB_LOAD_OK || nZapLelantusMintRet != DB_LOAD_OK) {
            InitError(strprintf(_("Error loading %s: Wallet corrupted"), walletFile));
            return NULL;
        }

        delete tempWallet;
        tempWallet = NULL;
    }

    // needed to restore wallet transaction meta data after -zapwallettxes
    std::vector<CWalletTx> vWtx;

    if (GetBoolArg("-zapwallettxes", false)) {
        uiInterface.InitMessage(_("Zapping all transactions from wallet..."));

        CWallet *tempWallet = new CWallet(walletFile);
        DBErrors nZapWalletRet = tempWallet->ZapWalletTx(vWtx);
        if (nZapWalletRet != DB_LOAD_OK) {
            InitError(strprintf(_("Error loading %s: Wallet corrupted"), walletFile));
            return NULL;
        }

        delete tempWallet;
        tempWallet = NULL;
    }

    uiInterface.InitMessage(_("Loading wallet..."));

    int64_t nStart = GetTimeMillis();
    bool fFirstRun = true;
    bool fRecoverMnemonic = false;
    CWallet *walletInstance = new CWallet(walletFile);
    pwalletMain = walletInstance;

    DBErrors nLoadWalletRet = walletInstance->LoadWallet(fFirstRun);
    if (nLoadWalletRet != DB_LOAD_OK)
    {
        if (nLoadWalletRet == DB_CORRUPT) {
            InitError(strprintf(_("Error loading %s: Wallet corrupted"), walletFile));
            return NULL;
        }
        else if (nLoadWalletRet == DB_NONCRITICAL_ERROR)
        {
            InitWarning(strprintf(_("Error reading %s! All keys read correctly, but transaction data"
                                         " or address book entries might be missing or incorrect."),
                walletFile));
        }
        else if (nLoadWalletRet == DB_TOO_NEW) {
            InitError(strprintf(_("Error loading %s: Wallet requires newer version of %s"), walletFile, _(PACKAGE_NAME)));
            return NULL;
        }
        else if (nLoadWalletRet == DB_NEED_REWRITE)
        {
            InitError(strprintf(_("Wallet needed to be rewritten: restart %s to complete"), _(PACKAGE_NAME)));
            return NULL;
        }
        else {
            InitError(strprintf(_("Error loading %s"), walletFile));
            return NULL;
        }
    }

    if (GetBoolArg("-upgradewallet", fFirstRun))
    {
        int nMaxVersion = GetArg("-upgradewallet", 0);
        if (nMaxVersion == 0) // the -upgradewallet without argument case
        {
            LogPrintf("Performing wallet upgrade to %i\n", FEATURE_LATEST);
            nMaxVersion = CLIENT_VERSION;
            walletInstance->SetMinVersion(FEATURE_LATEST); // permanently upgrade the wallet immediately
        }
        else
            LogPrintf("Allowing wallet upgrade up to %i\n", nMaxVersion);
        if (nMaxVersion < walletInstance->GetVersion())
        {
            InitError(_("Cannot downgrade wallet"));
            return NULL;
        }
        walletInstance->SetMaxVersion(nMaxVersion);
    }

    if (fFirstRun)
    {
        // Create new keyUser and set as default key
        if (GetBoolArg("-usehd", DEFAULT_USE_HD_WALLET) && !walletInstance->IsHDEnabled()) {
            if(GetBoolArg("-usemnemonic", DEFAULT_USE_MNEMONIC)) {
                if (GetArg("-mnemonicpassphrase", "").size() > 256) {
                    throw std::runtime_error(std::string(__func__) + ": Mnemonic passphrase is too long, must be at most 256 characters");
                }
                // generate a new HD chain
                walletInstance->GenerateNewMnemonic();
                walletInstance->SetMinVersion(FEATURE_HD);
                /* set rescan to true.
                 * if blockchain data is not present it has no effect, but it's needed for a mnemonic restore where chain data is present.
                 */
                SoftSetBoolArg("-rescan", true);
                fRecoverMnemonic = true;
            }else{
            // generate a new master key
            CPubKey masterPubKey = walletInstance->GenerateNewHDMasterKey();
            if (!walletInstance->SetHDMasterKey(masterPubKey, CHDChain().VERSION_WITH_BIP44))
                throw std::runtime_error(std::string(__func__) + ": Storing master key failed");
            }
        }
        CPubKey newDefaultKey;
        if (walletInstance->GetKeyFromPool(newDefaultKey)) {
            walletInstance->SetDefaultKey(newDefaultKey);
            if (!walletInstance->SetAddressBook(walletInstance->vchDefaultKey.GetID(), "", "receive")) {
                InitError(_("Cannot write default address") += "\n");
                return NULL;
            }
        }

        walletInstance->SetBestChain(chainActive.GetLocator());
    }
    else if (IsArgSet("-usehd")) {
        bool useHD = GetBoolArg("-usehd", DEFAULT_USE_HD_WALLET);
        if (walletInstance->IsHDEnabled() && !useHD) {
            InitError(strprintf(_("Error loading %s: You can't disable HD on a already existing HD wallet"), walletFile));
            return NULL;
        }
        if (!walletInstance->IsHDEnabled() && useHD) {
            InitError(strprintf(_("Error loading %s: You can't enable HD on a already existing non-HD wallet"), walletFile));
            return NULL;
        }
    }

    LogPrintf(" wallet      %15dms\n", GetTimeMillis() - nStart);
    if (pwalletMain->IsHDSeedAvailable()) {
        walletInstance->zwallet = std::make_unique<CHDMintWallet>(pwalletMain->strWalletFile);
    }

    walletInstance->bip47wallet = std::make_shared<bip47::CWallet>(walletInstance->vchDefaultKey.GetHash());
    walletInstance->LoadBip47Wallet();
    if (fFirstRun) {
        int const defaultPcodeNumber = std::stoi(GetArg("-defaultpcodenumber", "0"));
        for(int i = 0; i < defaultPcodeNumber; ++i)
            walletInstance->GeneratePcode("Autogenerated RAP address " + std::to_string(i));
    }

    RegisterValidationInterface(walletInstance);

    CBlockIndex *pindexRescan = chainActive.Tip();
    if (GetBoolArg("-rescan", false))
        pindexRescan = chainActive.Genesis();
    else
    {
        CWalletDB walletdb(walletFile);
        CBlockLocator locator;
        if (walletdb.ReadBestBlock(locator))
            pindexRescan = FindForkInGlobalIndex(chainActive, locator);
        else
            pindexRescan = chainActive.Genesis();
    }
    if (chainActive.Tip() && chainActive.Tip() != pindexRescan)
    {
        //We can't rescan beyond non-pruned blocks, stop and throw an error
        //this might happen if a user uses a old wallet within a pruned node
        // or if he ran -disablewallet for a longer time, then decided to re-enable
        if (fPruneMode)
        {
            CBlockIndex *block = chainActive.Tip();
            while (block && block->pprev && (block->pprev->nStatus & BLOCK_HAVE_DATA) && block->pprev->nTx > 0 && pindexRescan != block)
                block = block->pprev;

            if (pindexRescan != block) {
                InitError(_("Prune: last wallet synchronisation goes beyond pruned data. You need to -reindex (download the whole blockchain again in case of pruned node)"));
                return NULL;
            }
        }

        uiInterface.InitMessage(_("Rescanning..."));
        LogPrintf("Rescanning last %i blocks (from block %i)...\n", chainActive.Height() - pindexRescan->nHeight, pindexRescan->nHeight);
        nStart = GetTimeMillis();
        walletInstance->ScanForWalletTransactions(pindexRescan, true, fRecoverMnemonic);
        LogPrintf(" rescan      %15dms\n", GetTimeMillis() - nStart);
        walletInstance->SetBestChain(chainActive.GetLocator());
        CWalletDB::IncrementUpdateCounter();

        // Restore wallet transaction metadata after -zapwallettxes=1
        if (GetBoolArg("-zapwallettxes", false))
        {
            std::string zwtValue = GetArg("-zapwallettxes", "1");
            if(zwtValue != "2") {
                CWalletDB walletdb(walletFile);

                BOOST_FOREACH(const CWalletTx &wtxOld, vWtx)
                {
                    uint256 hash = wtxOld.GetHash();
                    std::map<uint256, CWalletTx>::iterator mi = walletInstance->mapWallet.find(hash);
                    if (mi != walletInstance->mapWallet.end()) {
                        const CWalletTx *copyFrom = &wtxOld;
                        CWalletTx *copyTo = &mi->second;
                        copyTo->mapValue = copyFrom->mapValue;
                        copyTo->vOrderForm = copyFrom->vOrderForm;
                        copyTo->nTimeReceived = copyFrom->nTimeReceived;
                        copyTo->nTimeSmart = copyFrom->nTimeSmart;
                        copyTo->fFromMe = copyFrom->fFromMe;
                        copyTo->strFromAccount = copyFrom->strFromAccount;
                        copyTo->nOrderPos = copyFrom->nOrderPos;
                        walletdb.WriteTx(*copyTo);
                    }
                }
            }
        }
    }

    // recover addressbook
    if (fFirstRun)
    {
        for (std::map<uint256, CWalletTx>::iterator it = walletInstance->mapWallet.begin(); it != walletInstance->mapWallet.end(); ++it) {
            for (uint32_t i = 0; i < (*it).second.tx->vout.size(); i++) {
                const auto& txout = (*it).second.tx->vout[i];
                if(txout.scriptPubKey.IsMint() || (*it).second.changes.count(i))
                    continue;
                if (!walletInstance->IsMine(txout))
                    continue;
                CTxDestination addr;
                if(!ExtractDestination(txout.scriptPubKey, addr))
                    continue;
                if (walletInstance->mapAddressBook.count(addr) == 0)
                    walletInstance->SetAddressBook(addr, "", "receive");
            }
        }
    }

    walletInstance->SetBroadcastTransactions(GetBoolArg("-walletbroadcast", DEFAULT_WALLETBROADCAST));

    {
        LOCK(walletInstance->cs_wallet);
        LogPrintf("setKeyPool.size() = %u\n",      walletInstance->GetKeyPoolSize());
        LogPrintf("mapWallet.size() = %u\n",       walletInstance->mapWallet.size());
        LogPrintf("mapAddressBook.size() = %u\n",  walletInstance->mapAddressBook.size());
    }

    return walletInstance;
}

bool CWallet::InitLoadWallet()
{
    if (GetBoolArg("-disablewallet", DEFAULT_DISABLE_WALLET)) {
        pwalletMain = NULL;
        LogPrintf("Wallet disabled!\n");
        return true;
    }

    std::string walletFile = GetArg("-wallet", DEFAULT_WALLET_DAT);

    if (walletFile.find_first_of("/\\") != std::string::npos) {
        return InitError(_("-wallet parameter must only specify a filename (not a path)"));
    } else if (SanitizeString(walletFile, SAFE_CHARS_FILENAME) != walletFile) {
        return InitError(_("Invalid characters in -wallet filename"));
    }

    CWallet * const pwallet = CreateWalletFromFile(walletFile);
    if (!pwallet) {
        return false;
    }
    pwalletMain = pwallet;

    return true;
}

std::atomic<bool> CWallet::fFlushThreadRunning(false);

void CWallet::postInitProcess(boost::thread_group& threadGroup)
{
    // Add wallet transactions that aren't already in a block to mempool
    // Do this here as mempool requires genesis block to be loaded
    ReacceptWalletTransactions();

    // Run a thread to flush wallet periodically
    if (!CWallet::fFlushThreadRunning.exchange(true)) {
        threadGroup.create_thread(ThreadFlushWalletDB);
    }
}

bool CWallet::ParameterInteraction()
{
    if (GetBoolArg("-disablewallet", DEFAULT_DISABLE_WALLET))
        return true;

    if (GetBoolArg("-blocksonly", DEFAULT_BLOCKSONLY) && SoftSetBoolArg("-walletbroadcast", false)) {
        LogPrintf("%s: parameter interaction: -blocksonly=1 -> setting -walletbroadcast=0\n", __func__);
    }

    if (GetBoolArg("-salvagewallet", false) && SoftSetBoolArg("-rescan", true)) {
        // Rewrite just private keys: rescan to find transactions
        LogPrintf("%s: parameter interaction: -salvagewallet=1 -> setting -rescan=1\n", __func__);
    }

    // -zapwallettx implies a rescan
    if (GetBoolArg("-zapwallettxes", false) && SoftSetBoolArg("-rescan", true)) {
        LogPrintf("%s: parameter interaction: -zapwallettxes=<mode> -> setting -rescan=1\n", __func__);
    }

    if (GetBoolArg("-sysperms", false))
        return InitError("-sysperms is not allowed in combination with enabled wallet functionality");
    if (GetArg("-prune", 0) && GetBoolArg("-rescan", false))
        return InitError(_("Rescans are not possible in pruned mode. You will need to use -reindex which will download the whole blockchain again."));

    if (::minRelayTxFee.GetFeePerK() > HIGH_TX_FEE_PER_KB)
        InitWarning(AmountHighWarn("-minrelaytxfee") + " " +
                    _("The wallet will avoid paying less than the minimum relay fee."));

    if (IsArgSet("-mintxfee"))
    {
        CAmount n = 0;
        if (!ParseMoney(GetArg("-mintxfee", ""), n) || 0 == n)
            return InitError(AmountErrMsg("mintxfee", GetArg("-mintxfee", "")));
        if (n > HIGH_TX_FEE_PER_KB)
            InitWarning(AmountHighWarn("-mintxfee") + " " +
                        _("This is the minimum transaction fee you pay on every transaction."));
        CWallet::minTxFee = CFeeRate(n);
    }
    if (IsArgSet("-fallbackfee"))
    {
        CAmount nFeePerK = 0;
        if (!ParseMoney(GetArg("-fallbackfee", ""), nFeePerK))
            return InitError(strprintf(_("Invalid amount for -fallbackfee=<amount>: '%s'"), GetArg("-fallbackfee", "")));
        /*
        if (nFeePerK > HIGH_TX_FEE_PER_KB)
            InitWarning(AmountHighWarn("-fallbackfee") + " " +
                        _("This is the transaction fee you may pay when fee estimates are not available."));
        */
        CWallet::fallbackFee = CFeeRate(nFeePerK);
    }
    if (IsArgSet("-paytxfee"))
    {
        CAmount nFeePerK = 0;
        if (!ParseMoney(GetArg("-paytxfee", ""), nFeePerK))
            return InitError(AmountErrMsg("paytxfee", GetArg("-paytxfee", "")));
        /*
        if (nFeePerK > HIGH_TX_FEE_PER_KB)
            InitWarning(AmountHighWarn("-paytxfee") + " " +
                        _("This is the transaction fee you will pay if you send a transaction."));
        */

        payTxFee = CFeeRate(nFeePerK, 1000);
        if (payTxFee < ::minRelayTxFee)
        {
            return InitError(strprintf(_("Invalid amount for -paytxfee=<amount>: '%s' (must be at least %s)"),
                                       GetArg("-paytxfee", ""), ::minRelayTxFee.ToString()));
        }
    }
    if (IsArgSet("-maxtxfee"))
    {
        CAmount nMaxFee = 0;
        if (!ParseMoney(GetArg("-maxtxfee", ""), nMaxFee))
            return InitError(AmountErrMsg("maxtxfee", GetArg("-maxtxfee", "")));
        /*
        if (nMaxFee > HIGH_MAX_TX_FEE)
            InitWarning(_("-maxtxfee is set very high! Fees this large could be paid on a single transaction."));
        */
        maxTxFee = nMaxFee;
        if (CFeeRate(maxTxFee, 1000) < ::minRelayTxFee)
        {
            return InitError(strprintf(_("Invalid amount for -maxtxfee=<amount>: '%s' (must be at least the minrelay fee of %s to prevent stuck transactions)"),
                                       GetArg("-maxtxfee", ""), ::minRelayTxFee.ToString()));
        }
    }

    if (IsArgSet("-mininput"))
    {
        if (!ParseMoney(GetArg("-mininput", ""), nMinimumInputValue))
            return InitError(strprintf(_("Invalid amount for -mininput=<amount>: '%s'"), GetArg("-mininput", "").c_str()));
    }

    nTxConfirmTarget = GetArg("-txconfirmtarget", DEFAULT_TX_CONFIRM_TARGET);
    bSpendZeroConfChange = GetBoolArg("-spendzeroconfchange", DEFAULT_SPEND_ZEROCONF_CHANGE);
    fSendFreeTransactions = GetBoolArg("-sendfreetransactions", DEFAULT_SEND_FREE_TRANSACTIONS);
    fWalletRbf = GetBoolArg("-walletrbf", DEFAULT_WALLET_RBF);

    if (fSendFreeTransactions && GetArg("-limitfreerelay", DEFAULT_LIMITFREERELAY) <= 0)
        return InitError("Creation of free transactions with their relay disabled is not supported.");

    return true;
}

bool CWallet::BackupWallet(const std::string& strDest)
{
    if (!fFileBacked)
        return false;
    while (true)
    {
        {
            LOCK(bitdb.cs_db);
            if (!bitdb.mapFileUseCount.count(strWalletFile) || bitdb.mapFileUseCount[strWalletFile] == 0)
            {
                // Flush log data to the dat file
                bitdb.CloseDb(strWalletFile);
                bitdb.CheckpointLSN(strWalletFile);
                bitdb.mapFileUseCount.erase(strWalletFile);

                // Copy wallet file
                boost::filesystem::path pathSrc = GetDataDir() / strWalletFile;
                boost::filesystem::path pathDest(strDest);
                if (boost::filesystem::is_directory(pathDest))
                    pathDest /= strWalletFile;

                try {
#if BOOST_VERSION >= 104000
                    boost::filesystem::copy_file(pathSrc, pathDest, boost::filesystem::copy_option::overwrite_if_exists);
#else
                    boost::filesystem::copy_file(pathSrc, pathDest);
#endif
                    LogPrintf("copied %s to %s\n", strWalletFile, pathDest.string());
                    return true;
                } catch (const boost::filesystem::filesystem_error& e) {
                    LogPrintf("error copying %s to %s - %s\n", strWalletFile, pathDest.string(), e.what());
                    return false;
                }
            }
        }
        MilliSleep(100);
    }
    return false;
}

bip47::CPaymentCode CWallet::GeneratePcode(std::string const & label)
{
    if (!bip47wallet)
        throw WalletError("BIP47 wallet was not created during the initialization");

    bip47::CAccountReceiver & newAcc = bip47wallet->createReceivingAccount(label);
    {
        bip47::MyAddrContT addrs = newAcc.getMyNextAddresses();
        LOCK(cs_wallet);
        for(bip47::MyAddrContT::value_type const & addr : addrs) {
            AddKey(addr.second);
        }
    }
    CWalletDB(strWalletFile).WriteBip47Account(newAcc);
    NotifyPcodeCreated(bip47::CPaymentCodeDescription(newAcc.getAccountNum(), newAcc.getMyPcode(), newAcc.getLabel(), newAcc.getMyPcode().getNotificationAddress(), bip47::CPaymentCodeSide::Receiver));
    return newAcc.getMyPcode();
}

CWalletTx CWallet::PrepareAndSendNotificationTx(bip47::CPaymentCode const & theirPcode)
{
    bip47::CPaymentChannel pchannel = SetupPchannel(theirPcode);

    CWalletTx wtxNew;

    if (GetBroadcastTransactions() && !g_connman) {
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");
    }

    CBitcoinAddress const notifAddr = pchannel.getTheirPcode().getNotificationAddress();

    std::vector<CRecipient> recipients;
    std::vector<CAmount> newMints;

    CRecipient receiver;
    receiver.scriptPubKey = GetScriptForDestination(notifAddr.Get());
    receiver.nAmount = bip47::NotificationTxValue;
    receiver.fSubtractFeeFromAmount = false;

    recipients.emplace_back(receiver);
    CScript opReturnScript = CScript() << OP_RETURN << std::vector<unsigned char>(80); // Passing empty array to calc fees
    recipients.push_back({opReturnScript, 0, false});

    auto throwSigma =
        [](){throw std::runtime_error(std::string("There are unspent Sigma coins in your wallet. Using Sigma coins for BIP47 is not supported. Please spend your Sigma coins before establishing a BIP47 channel."));};

    try {
        std::vector<CLelantusEntry> spendCoins;
        std::vector<CSigmaEntry> sigmaSpendCoins;
        std::vector<CHDMint> mintCoins;
        CAmount fee;

        wtxNew = CreateLelantusJoinSplitTransaction(recipients, fee, newMints, spendCoins, sigmaSpendCoins, mintCoins, nullptr,
                [&pchannel, &throwSigma](CTxOut & out, LelantusJoinSplitBuilder const & builder) {
                    if(out.scriptPubKey[0] == OP_RETURN) {
                        CKey spendPrivKey;
                        if (builder.spendCoins.empty())
                            throwSigma();
                        spendPrivKey.Set(builder.spendCoins[0].ecdsaSecretKey.begin(), builder.spendCoins[0].ecdsaSecretKey.end(), false);
                        CDataStream ds(SER_NETWORK, 0);
                        ds << builder.spendCoins[0].serialNumber;
                        bip47::Bytes const pcode = pchannel.getMaskedPayload((unsigned char const *)ds.vch.data(), ds.vch.size(), spendPrivKey);
                        out.scriptPubKey = CScript() << OP_RETURN << pcode;
                    }
                });

        if (!sigmaSpendCoins.empty())
            throwSigma();

        if (spendCoins.empty())
            throw std::runtime_error(std::string("Cannot create a Lelantus spend to address: " + notifAddr.ToString()).c_str());

        CommitLelantusTransaction(wtxNew, spendCoins, sigmaSpendCoins, mintCoins);
        LogBip47("Paymentcode %s was sent to notification address: %s\n", pchannel.getMyPcode().toString().c_str(), notifAddr.ToString().c_str() );
    }
    catch (const InsufficientFunds& e)
    {
        throw e;
    }
    catch (const std::exception& e)
    {
        throw WalletError(e.what());
    }

    SetNotificationTxId(theirPcode, wtxNew.GetHash());
    return wtxNew;
}

std::vector<bip47::CPaymentCodeDescription> CWallet::ListPcodes()
{
    std::vector<bip47::CPaymentCodeDescription> result;
    if (!bip47wallet)
        return result;

    bip47wallet->enumerateReceivers(
        [&result](bip47::CAccountReceiver const & acc)->bool
        {
            result.emplace_back(acc.getAccountNum(), acc.getMyPcode(), acc.getLabel(), acc.getMyNotificationAddress(), bip47::CPaymentCodeSide::Receiver);
            return true;
        }
    );
    return result;
}

bip47::CPaymentChannel & CWallet::SetupPchannel(bip47::CPaymentCode const & theirPcode)
{
    if (!bip47wallet)
        throw WalletError("BIP47 wallet was not created during the initialization");

    bip47::CAccountSender & sender = bip47wallet->provideSendingAccount(theirPcode);
    CWalletDB(strWalletFile).WriteBip47Account(sender);
    return sender.getPaymentChannel();
}

void CWallet::SetNotificationTxId(bip47::CPaymentCode const & theirPcode, uint256 const & txid)
{
    if (!bip47wallet)
        throw WalletError("BIP47 wallet was not created during the initialization");

    bip47::CAccountSender & sender = bip47wallet->provideSendingAccount(theirPcode);
    sender.setNotificationTxId(txid);
    CWalletDB(strWalletFile).WriteBip47Account(sender);
}

namespace {
CBitcoinAddress HandleTheirNextAddress(bip47::CWallet & wallet, std::string const & strWalletFile, bip47::CPaymentCode const & theirPcode, bool storeNextAddress)
{
    boost::optional<bip47::CAccountSender*> existingAcc;
    wallet.enumerateSenders(
        [&theirPcode, &existingAcc](bip47::CAccountSender & acc)->bool
        {
            if(acc.getTheirPcode() == theirPcode) {
                existingAcc.emplace(&acc);
                return false;
            }
            return true;
        }
    );
    if(!existingAcc)
        throw std::runtime_error("There is no account setup for payment code " + theirPcode.toString());
    CBitcoinAddress result;
    if(storeNextAddress)
    {
        result = existingAcc.get()->generateTheirNextSecretAddress();
        LogBip47("Sending to secret address: %s\n", result.ToString());
    } else {
        result = existingAcc.get()->getTheirNextSecretAddress();
    }
    CWalletDB(strWalletFile).WriteBip47Account(*existingAcc.get());
    return result;
}
}

CBitcoinAddress CWallet::GetTheirNextAddress(bip47::CPaymentCode const & theirPcode) const
{
    if (!bip47wallet)
        throw WalletError("BIP47 wallet was not created during the initialization");

    return HandleTheirNextAddress(*bip47wallet, strWalletFile, theirPcode, false);
}

CBitcoinAddress CWallet::GenerateTheirNextAddress(bip47::CPaymentCode const & theirPcode)
{
    if (!bip47wallet)
        throw WalletError("BIP47 wallet was not created during the initialization");

    return HandleTheirNextAddress(*bip47wallet, strWalletFile, theirPcode, true);
}

void CWallet::LoadBip47Wallet()
{
    CWalletDB(strWalletFile).LoadBip47Accounts(*bip47wallet);
}

std::shared_ptr<bip47::CWallet const> CWallet::GetBip47Wallet() const
{
    return bip47wallet;
}

boost::optional<bip47::CPaymentCodeDescription> CWallet::FindPcode(bip47::CPaymentCode const & pcode) const
{
    boost::optional<bip47::CPaymentCodeDescription> result;
    if (!bip47wallet)
        return result;

    bip47wallet->enumerateReceivers(
        [&pcode, &result](bip47::CAccountReceiver & rec)->bool
        {
            if(rec.getMyPcode() == pcode) {
                result.emplace(rec.getAccountNum(), rec.getMyPcode(), rec.getLabel(), rec.getMyPcode().getNotificationAddress(), bip47::CPaymentCodeSide::Receiver);
                return false;
            }

            for(bip47::CPaymentChannel const & channel : rec.getPchannels()) {
                if(channel.getTheirPcode() == pcode) {
                    result.emplace(rec.getAccountNum(), rec.getMyPcode(), rec.getLabel(), rec.getMyPcode().getNotificationAddress(), bip47::CPaymentCodeSide::Receiver);
                    return false;
                }
            }
            return true;
        }
    );
    bip47wallet->enumerateSenders(
        [&pcode, &result, this](bip47::CAccountSender & sender)->bool
        {
            if(sender.getTheirPcode() == pcode) {
                std::string label = GetSendingPcodeLabel(sender.getTheirPcode());
                result.emplace(sender.getAccountNum(), sender.getTheirPcode(), label, sender.getTheirPcode().getNotificationAddress(), bip47::CPaymentCodeSide::Sender);
                return false;
            }
            return true;
        }
    );
    return result;
}

boost::optional<bip47::CPaymentCodeDescription> CWallet::FindPcode(CBitcoinAddress const & address) const
{
    boost::optional<bip47::CPaymentCodeDescription> result;
    if (!bip47wallet)
        return result;

    bip47wallet->enumerateReceivers(
        [&address, &result](bip47::CAccountReceiver & rec)->bool
        {
            bip47::MyAddrContT addrs = rec.getMyUsedAddresses();
            if (std::find_if(addrs.begin(), addrs.end(), bip47::FindByAddress(address)) != addrs.end())
            {
                result.emplace(rec.getAccountNum(), rec.getMyPcode(), rec.getLabel(), rec.getMyPcode().getNotificationAddress(), bip47::CPaymentCodeSide::Receiver);
                return false;
            }
            addrs = rec.getMyNextAddresses();
            if (std::find_if(addrs.begin(), addrs.end(), bip47::FindByAddress(address)) != addrs.end())
            {
                result.emplace(rec.getAccountNum(), rec.getMyPcode(), rec.getLabel(), rec.getMyPcode().getNotificationAddress(), bip47::CPaymentCodeSide::Receiver);
                return false;
            }
            return true;
        }
    );
    bip47wallet->enumerateSenders(
        [&address, &result, this](bip47::CAccountSender & sender)->bool
        {
            bip47::TheirAddrContT addrs = sender.getTheirUsedAddresses();
            if (std::find(addrs.begin(), addrs.end(), address) != addrs.end())
            {
                std::string label = GetSendingPcodeLabel(sender.getTheirPcode());
                result.emplace(sender.getAccountNum(), sender.getTheirPcode(), label, sender.getTheirPcode().getNotificationAddress(), bip47::CPaymentCodeSide::Sender);
                return false;
            }
            if (address == sender.getTheirNextSecretAddress() || address == sender.getTheirPcode().getNotificationAddress())
            {
                std::string label = GetSendingPcodeLabel(sender.getTheirPcode());
                result.emplace(sender.getAccountNum(), sender.getTheirPcode(), label, sender.getTheirPcode().getNotificationAddress(), bip47::CPaymentCodeSide::Sender);
                return false;
            }
            return true;
        }
    );
    return result;
}

bip47::CAccountReceiver const * CWallet::AddressUsed(CBitcoinAddress const & address)
{
    bip47::CAccountReceiver const * result = nullptr;
    if(!bip47wallet)
        return result;

    bip47wallet->enumerateReceivers(
        [&address, &result](bip47::CAccountReceiver & rec)->bool
        {
            bip47::MyAddrContT addrs = rec.getMyNextAddresses();
            if (std::find_if(addrs.begin(), addrs.end(), bip47::FindByAddress(address)) != addrs.end())
            {
                rec.addressUsed(address);
                result = &rec;
                return false;
            }
            return true;
        }
    );
    if (result)
        CWalletDB(strWalletFile).WriteBip47Account(*result);
    return result;
}

void CWallet::HandleBip47Transaction(CWalletTx const & wtx)
{
    bip47::Bytes masked = bip47::utils::GetMaskedPcode(wtx.tx);
    CKey key;
    bip47::CAccountReceiver * accFound = nullptr;
    int nRequired = 0;
    std::vector<CTxDestination> addresses;
    txnouttype typeRet = TX_NONSTANDARD;
    std::vector<CTxIn>::const_iterator ijsplit;
    std::vector<CTxOut>::const_iterator iregout;
    bool success = false;

    if (masked.empty()) goto notifTxExit;

    ijsplit = std::find_if(wtx.tx->vin.begin(), wtx.tx->vin.end(), [](CTxIn const & in){ return in.scriptSig.IsLelantusJoinSplit(); });
    if(ijsplit == wtx.tx->vin.end()) {
        LogBip47("Joinsplit input was not found in a potential notification tx: %s\n", wtx.tx->GetHash().ToString());
        goto notifTxExit;
    }

    iregout = std::find_if(wtx.tx->vout.begin(), wtx.tx->vout.end(), [](CTxOut const & out){ return out.scriptPubKey[0] != OP_RETURN && !out.scriptPubKey.IsLelantusJMint(); });
    if(iregout == wtx.tx->vout.end()) {
        LogBip47("Regular out was not found in a potential notification tx: %s\n", wtx.tx->GetHash().ToString());
        goto notifTxExit;
    }
    if(!ExtractDestinations(iregout->scriptPubKey, typeRet, addresses, nRequired)) {
        LogBip47("Cannot extract destinations for tx: %s\n", wtx.tx->GetHash().ToString());
        goto notifTxExit;
    }
    bip47wallet->enumerateReceivers(
        [&key, &addresses, &accFound](bip47::CAccountReceiver & acc)->bool
        {
            for (CBitcoinAddress addr : addresses) {
                if(acc.getMyNotificationAddress() == addr) {
                    key = acc.getMyNextAddresses()[0].second;
                    accFound = &acc;
                    return false;
                }
            }
            return true;
        }
    );
    if(!accFound) {
        LogBip47("There was no account set up to receive payments on address: %s\n", CBitcoinAddress(addresses[0]).ToString());
        goto notifTxExit;
    }
    if(!accFound->acceptMaskedPayload(masked, *ijsplit)){
        LogBip47("Could not accept this masked payload: %s\n", HexStr(masked));
        goto notifTxExit;
    }
    success = true;
notifTxExit:
    if (success) {
        LogBip47("The payment code has been accepted: %s\n", accFound->lastPcode().toString());
        HandleSecretAddresses(*this, *accFound);
        CWalletDB(strWalletFile).WriteBip47Account(*accFound);
        LockCoin(COutPoint(wtx.tx->GetHash(), std::distance(wtx.tx->vout.begin(), iregout))); //Locking the notif tx output to be spent only manually
    } else {
        // Checking if it uses a bip47 address
        for (CTxOut const & out : wtx.tx->vout) {
            std::vector<CTxDestination> addresses;
            txnouttype typeRet = TX_NONSTANDARD;
            int nRequired = 0;
            if (ExtractDestinations(out.scriptPubKey, typeRet, addresses, nRequired)) {
                for (CBitcoinAddress addr : addresses) {
                    bip47::CAccountReceiver const * rec = AddressUsed(addr);
                    if (rec) {
                        HandleSecretAddresses(*this, *rec);
                    }
                }
            }
        }
    }
}

void CWallet::LabelSendingPcode(bip47::CPaymentCode const & pcode_, std::string const & label, bool remove)
{
    std::string const pcodeLbl = bip47::PcodeLabel() + pcode_.toString();
    if (label.empty())
        remove = true;
    CWalletDB walletDb(strWalletFile);
    if (remove) {
        walletDb.EraseKV(pcodeLbl);
        LOCK(cs_wallet);
        mapCustomKeyValues.erase(pcodeLbl);
    } else {
        std::multimap<std::string, std::string>::iterator iter = mapCustomKeyValues.find(pcodeLbl);
        if (iter == mapCustomKeyValues.end()) {
            LOCK(cs_wallet);
            mapCustomKeyValues.insert(std::make_pair(pcodeLbl, label));
        } else {
            if (iter->second == label)
                return;
            iter->second = label;
        }
        walletDb.EraseKV(pcodeLbl);
        walletDb.WriteKV(pcodeLbl, label);
    }
    NotifyPcodeLabeled(pcode_.toString(), label, remove);
}

std::string CWallet::GetSendingPcodeLabel(bip47::CPaymentCode const & pcode) const
{
    std::string const pcodeLbl = bip47::PcodeLabel() + pcode.toString();
    LOCK(cs_wallet);
    std::multimap<std::string, std::string>::const_iterator iter = mapCustomKeyValues.find(pcodeLbl);
    if(iter == mapCustomKeyValues.end())
        return "";
    return iter->second;
}

void CWallet::LabelReceivingPcode(bip47::CPaymentCode const & pcode, std::string const & label)
{
    if (!bip47wallet)
        return;

    LOCK(cs_wallet);
    bip47::CAccountReceiver * result = nullptr;
    bip47wallet->enumerateReceivers(
        [&result, &pcode](bip47::CAccountReceiver & rec)->bool
        {
            if(rec.getMyPcode() == pcode)
            {
                result = &rec;
                return false;
            }
            return true;
        }
    );
    if(!result)
        return;
    result->setLabel(label);
    CWalletDB(strWalletFile).WriteBip47Account(*result);
}

size_t CWallet::SetUsedAddressNumber(bip47::CPaymentCode const & pcode, size_t number)
{
    boost::optional<size_t> resultSnd, resutRec;
    bip47wallet->enumerateSenders(
        [&pcode, &number, &resultSnd](bip47::CAccountSender & sender)->bool
        {
            if(sender.getTheirPcode() == pcode) {
                resultSnd.emplace(sender.setTheirUsedAddressNumber(number));
                return false;
            }
            return true;
        }
    );

    bip47::CAccountReceiver * receiver;
    bip47wallet->enumerateReceivers(
        [&pcode, &number, &resutRec, &receiver](bip47::CAccountReceiver & rec)->bool
        {
            resutRec = rec.setMyUsedAddressNumber(pcode, number);
            if(resutRec) {
                receiver = &rec;
                return false;
            }
            return true;
        }
    );
    if(resutRec) {
        HandleSecretAddresses(*this, *receiver);
        return *resutRec;
    }
    if(resultSnd)
        return *resultSnd;
    return 0;
}

/******************************************************************************/
/*                                                                            */
/*                            CKeyPool                                        */
/*                                                                            */
/******************************************************************************/


CKeyPool::CKeyPool()
{
    nTime = GetTime();
}

CKeyPool::CKeyPool(const CPubKey& vchPubKeyIn)
{
    nTime = GetTime();
    vchPubKey = vchPubKeyIn;
}

CWalletKey::CWalletKey(int64_t nExpires)
{
    nTimeCreated = (nExpires ? GetTime() : 0);
    nTimeExpires = nExpires;
}

void CMerkleTx::SetMerkleBranch(const CBlockIndex* pindex, int posInBlock)
{
    // Update the tx's hashBlock
    hashBlock = pindex->GetBlockHash();

    // set the position of the transaction in the block
    nIndex = posInBlock;
}

int CMerkleTx::GetDepthInMainChain(const CBlockIndex *&pindexRet, bool enableIX) const {
    int nResult;

    if (hashUnset())
        nResult = 0;
    else {
        AssertLockHeld(cs_main);

        // Find the block it claims to be in
        BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi == mapBlockIndex.end())
            nResult = 0;
        else {
            CBlockIndex *pindex = (*mi).second;
            if (!pindex || !chainActive.Contains(pindex))
                nResult = 0;
            else {
                pindexRet = pindex;
                nResult = ((nIndex == -1) ? (-1) : 1) * (chainActive.Height() - pindex->nHeight + 1);

                if (nResult == 0 && !mempool.exists(GetHash()))
                    return -1; // Not in chain, not in mempool
            }
        }
    }

    return nResult;
}

int CMerkleTx::GetDepthInMainChain(const CBlockIndex* &pindexRet) const
{
    if (hashUnset())
        return 0;

    AssertLockHeld(cs_main);

    // Find the block it claims to be in
    BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !chainActive.Contains(pindex))
        return 0;

    pindexRet = pindex;
    return ((nIndex == -1) ? (-1) : 1) * (chainActive.Height() - pindex->nHeight + 1);
}

int CMerkleTx::GetBlocksToMaturity() const
{
    if (!IsCoinBase())
        return 0;
    return std::max(0, (COINBASE_MATURITY+1) - GetDepthInMainChain());
}


bool CMerkleTx::AcceptToMemoryPool(const CAmount &nAbsurdFee, CValidationState &state)
{
    if (GetBoolArg("-dandelion", true)) {
        bool res = ::AcceptToMemoryPool(
            txpools.getStemTxPool(),
            state,
            tx,
            false,
            NULL, /* pfMissingInputs */
            NULL,
            false, /* fOverrideMempoolLimit */
            nAbsurdFee,
            true,
            false /* markFiroSpendTransactionSerial */
        );
        if (!res) {
            LogPrintf(
                "CMerkleTx::AcceptToMemoryPool, failed to add txn %s to dandelion stempool: %s.\n",
                GetHash().ToString(),
                state.GetRejectReason());
        }
        return res;
    } else {
        // Changes to mempool should also be made to Dandelion stempool
        return ::AcceptToMemoryPool(
            txpools,
            state,
            tx,
            false,
            NULL, /* pfMissingInputs */
            NULL,
            false, /* fOverrideMempoolLimit */
            nAbsurdFee,
            true,
            true);
    }
}

bool CompSigmaHeight(const CSigmaEntry &a, const CSigmaEntry &b) { return a.nHeight < b.nHeight; }
bool CompSigmaID(const CSigmaEntry &a, const CSigmaEntry &b) { return a.id < b.id; }
