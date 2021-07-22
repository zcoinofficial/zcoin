// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include "base58.h"
#include "consensus/validation.h"
#include "validation.h" // For CheckTransaction
#include "protocol.h"
#include "serialize.h"
#include "sync.h"
#include "util.h"
#include "utiltime.h"
#include "wallet/wallet.h"
#include "bip47/account.h"

#include <atomic>

#include <boost/version.hpp>
#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>
#include <boost/thread.hpp>

static uint64_t nAccountingEntryNumber = 0;

static std::atomic<unsigned int> nWalletDBUpdateCounter;

//
// CWalletDB
//

bool CWalletDB::WriteKV(const std::string& key, const std::string& value)
{
    nWalletDBUpdateCounter++;
    return Write(std::make_pair(std::string("kv"), key), value);
}

bool CWalletDB::EraseKV(const std::string& key)
{
    nWalletDBUpdateCounter++;
    return Erase(std::make_pair(std::string("kv"), key));
}

bool CWalletDB::WriteName(const std::string& strAddress, const std::string& strName)
{
    nWalletDBUpdateCounter++;
    return Write(std::make_pair(std::string("name"), strAddress), strName);
}

bool CWalletDB::EraseName(const std::string& strAddress)
{
    // This should only be used for sending addresses, never for receiving addresses,
    // receiving addresses must always have an address book entry if they're not change return.
    nWalletDBUpdateCounter++;
    return Erase(std::make_pair(std::string("name"), strAddress));
}

bool CWalletDB::WritePurpose(const std::string& strAddress, const std::string& strPurpose)
{
    nWalletDBUpdateCounter++;
    return Write(std::make_pair(std::string("purpose"), strAddress), strPurpose);
}

bool CWalletDB::ErasePurpose(const std::string& strPurpose)
{
    nWalletDBUpdateCounter++;
    return Erase(std::make_pair(std::string("purpose"), strPurpose));
}

bool CWalletDB::WriteTx(const CWalletTx& wtx)
{
    nWalletDBUpdateCounter++;
    return Write(std::make_pair(std::string("tx"), wtx.GetHash()), wtx);
}

bool CWalletDB::EraseTx(uint256 hash)
{
    nWalletDBUpdateCounter++;
    return Erase(std::make_pair(std::string("tx"), hash));
}

bool CWalletDB::WriteKey(const CPubKey& vchPubKey, const CPrivKey& vchPrivKey, const CKeyMetadata& keyMeta)
{
    nWalletDBUpdateCounter++;

    if (!Write(std::make_pair(std::string("keymeta"), vchPubKey),
               keyMeta, false))
        return false;

    // hash pubkey/privkey to accelerate wallet load
    std::vector<unsigned char> vchKey;
    vchKey.reserve(vchPubKey.size() + vchPrivKey.size());
    vchKey.insert(vchKey.end(), vchPubKey.begin(), vchPubKey.end());
    vchKey.insert(vchKey.end(), vchPrivKey.begin(), vchPrivKey.end());

    return Write(std::make_pair(std::string("key"), vchPubKey), std::make_pair(vchPrivKey, Hash(vchKey.begin(), vchKey.end())), false);
}

bool CWalletDB::WriteCryptedKey(const CPubKey& vchPubKey,
                                const std::vector<unsigned char>& vchCryptedSecret,
                                const CKeyMetadata &keyMeta)
{
    const bool fEraseUnencryptedKey = true;
    nWalletDBUpdateCounter++;

    if (!Write(std::make_pair(std::string("keymeta"), vchPubKey),
            keyMeta))
        return false;

    if (!Write(std::make_pair(std::string("ckey"), vchPubKey), vchCryptedSecret, false))
        return false;
    if (fEraseUnencryptedKey)
    {
        Erase(std::make_pair(std::string("key"), vchPubKey));
        Erase(std::make_pair(std::string("wkey"), vchPubKey));
    }
    return true;
}

bool CWalletDB::WriteMasterKey(unsigned int nID, const CMasterKey& kMasterKey)
{
    nWalletDBUpdateCounter++;
    return Write(std::make_pair(std::string("mkey"), nID), kMasterKey, true);
}

bool CWalletDB::WriteCScript(const uint160& hash, const CScript& redeemScript)
{
    nWalletDBUpdateCounter++;
    return Write(std::make_pair(std::string("cscript"), hash), *(const CScriptBase*)(&redeemScript), false);
}

bool CWalletDB::WriteWatchOnly(const CScript &dest, const CKeyMetadata& keyMeta)
{
    nWalletDBUpdateCounter++;
    if (!Write(std::make_pair(std::string("watchmeta"), *(const CScriptBase*)(&dest)), keyMeta))
        return false;
    return Write(std::make_pair(std::string("watchs"), *(const CScriptBase*)(&dest)), '1');
}

bool CWalletDB::EraseWatchOnly(const CScript &dest)
{
    nWalletDBUpdateCounter++;
    if (!Erase(std::make_pair(std::string("watchmeta"), *(const CScriptBase*)(&dest))))
        return false;
    return Erase(std::make_pair(std::string("watchs"), *(const CScriptBase*)(&dest)));
}

bool CWalletDB::WriteBestBlock(const CBlockLocator& locator)
{
    nWalletDBUpdateCounter++;
    Write(std::string("bestblock"), CBlockLocator()); // Write empty block locator so versions that require a merkle branch automatically rescan
    return Write(std::string("bestblock_nomerkle"), locator);
}

bool CWalletDB::ReadBestBlock(CBlockLocator& locator)
{
    if (Read(std::string("bestblock"), locator) && !locator.vHave.empty()) return true;
    return Read(std::string("bestblock_nomerkle"), locator);
}

bool CWalletDB::WriteOrderPosNext(int64_t nOrderPosNext)
{
    nWalletDBUpdateCounter++;
    return Write(std::string("orderposnext"), nOrderPosNext);
}

bool CWalletDB::WriteDefaultKey(const CPubKey& vchPubKey)
{
    nWalletDBUpdateCounter++;
    return Write(std::string("defaultkey"), vchPubKey);
}

bool CWalletDB::ReadPool(int64_t nPool, CKeyPool& keypool)
{
    return Read(std::make_pair(std::string("pool"), nPool), keypool);
}

bool CWalletDB::WritePool(int64_t nPool, const CKeyPool& keypool)
{
    nWalletDBUpdateCounter++;
    return Write(std::make_pair(std::string("pool"), nPool), keypool);
}

bool CWalletDB::ErasePool(int64_t nPool)
{
    nWalletDBUpdateCounter++;
    return Erase(std::make_pair(std::string("pool"), nPool));
}

bool CWalletDB::WriteMinVersion(int nVersion)
{
    return Write(std::string("minversion"), nVersion);
}

bool CWalletDB::ReadAccount(const std::string& strAccount, CAccount& account)
{
    account.SetNull();
    return Read(std::make_pair(std::string("acc"), strAccount), account);
}

bool CWalletDB::WriteAccount(const std::string& strAccount, const CAccount& account)
{
    return Write(std::make_pair(std::string("acc"), strAccount), account);
}

bool CWalletDB::WriteAccountingEntry(const uint64_t nAccEntryNum, const CAccountingEntry& acentry)
{
    return Write(std::make_pair(std::string("acentry"), std::make_pair(acentry.strAccount, nAccEntryNum)), acentry);
}

bool CWalletDB::WriteAccountingEntry_Backend(const CAccountingEntry& acentry)
{
    return WriteAccountingEntry(++nAccountingEntryNumber, acentry);
}

CAmount CWalletDB::GetAccountCreditDebit(const std::string& strAccount)
{
    std::list<CAccountingEntry> entries;
    ListAccountCreditDebit(strAccount, entries);

    CAmount nCreditDebit = 0;
    BOOST_FOREACH (const CAccountingEntry& entry, entries)
        nCreditDebit += entry.nCreditDebit;

    return nCreditDebit;
}

void CWalletDB::ListAccountCreditDebit(const std::string& strAccount, std::list<CAccountingEntry>& entries)
{
    bool fAllAccounts = (strAccount == "*");

    Dbc* pcursor = GetCursor();
    if (!pcursor)
        throw std::runtime_error(std::string(__func__) + ": cannot create DB cursor");
    bool setRange = true;
    while (true)
    {
        // Read next record
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        if (setRange)
            ssKey << std::make_pair(std::string("acentry"), std::make_pair((fAllAccounts ? std::string("") : strAccount), uint64_t(0)));
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        int ret = ReadAtCursor(pcursor, ssKey, ssValue, setRange);
        setRange = false;
        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0)
        {
            pcursor->close();
            throw std::runtime_error(std::string(__func__) + ": error scanning DB");
        }

        // Unserialize
        std::string strType;
        ssKey >> strType;
        if (strType != "acentry")
            break;
        CAccountingEntry acentry;
        ssKey >> acentry.strAccount;
        if (!fAllAccounts && acentry.strAccount != strAccount)
            break;

        ssValue >> acentry;
        ssKey >> acentry.nEntryNo;
        entries.push_back(acentry);
    }

    pcursor->close();
}

bool CWalletDB::WriteCoinSpendSerialEntry(const CSigmaSpendEntry &sigmaSpend) {
    return Write(std::make_pair(std::string("sigma_spend"), sigmaSpend.coinSerial), sigmaSpend, true);
}

bool CWalletDB::WriteLelantusSpendSerialEntry(const CLelantusSpendEntry& lelantusSpend) {
    return Write(std::make_pair(std::string("lelantus_spend"), lelantusSpend.coinSerial), lelantusSpend, true);
}

bool CWalletDB::HasCoinSpendSerialEntry(const secp_primitives::Scalar& serial) {
    return Exists(std::make_pair(std::string("sigma_spend"), serial));
}

bool CWalletDB::HasLelantusSpendSerialEntry(const secp_primitives::Scalar& serial) {
    return Exists(std::make_pair(std::string("lelantus_spend"), serial));
}

bool CWalletDB::EraseCoinSpendSerialEntry(const CSigmaSpendEntry &sigmaSpend) {
    return Erase(std::make_pair(std::string("sigma_spend"), sigmaSpend.coinSerial));
}

bool CWalletDB::EraseLelantusSpendSerialEntry(const CLelantusSpendEntry& lelantusSpend) {
    return Erase(std::make_pair(std::string("lelantus_spend"), lelantusSpend.coinSerial));
}

bool CWalletDB::ReadLelantusSpendSerialEntry(const secp_primitives::Scalar& serial, CLelantusSpendEntry& lelantusSpend) {
    return Read(std::make_pair(std::string("lelantus_spend"), serial), lelantusSpend);
}

bool CWalletDB::WriteSigmaEntry(const CSigmaEntry &sigma) {
    return Write(std::make_pair(std::string("sigma_mint"), sigma.value), sigma, true);
}

bool CWalletDB::ReadSigmaEntry(const secp_primitives::GroupElement& pub, CSigmaEntry& entry) {
    return Read(std::make_pair(std::string("sigma_mint"), pub), entry);
}

bool CWalletDB::HasSigmaEntry(const secp_primitives::GroupElement& pub) {
    return Exists(std::make_pair(std::string("sigma_mint"), pub));
}

bool CWalletDB::EraseSigmaEntry(const CSigmaEntry &sigma) {
    return Erase(std::make_pair(std::string("sigma_mint"), sigma.value));
}

bool CWalletDB::WriteCalculatedZCBlock(int height) {
    return Write(std::string("calculatedzcblock"), height);
}

void CWalletDB::ListSigmaPubCoin(std::list <CSigmaEntry> &listPubCoin) {
    Dbc *pcursor = GetCursor();
    if (!pcursor)
        throw std::runtime_error("CWalletDB::ListSigmaPubCoin() : cannot create DB cursor");
    bool setRange = true;
    while (true) {
        // Read next record
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        if (setRange)
            ssKey << std::make_pair(std::string("sigma_mint"), secp_primitives::GroupElement());
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        int ret = ReadAtCursor(pcursor, ssKey, ssValue, setRange);
        setRange = false;
        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0) {
            pcursor->close();
            throw std::runtime_error("CWalletDB::ListSigmaPubCoin() : error scanning DB");
        }
        // Unserialize
        std::string strType;
        ssKey >> strType;
        if (strType != "sigma_mint")
            break;
        GroupElement value;
        ssKey >> value;
        CSigmaEntry sigmaItem;
        ssValue >> sigmaItem;
        listPubCoin.push_back(sigmaItem);
    }
    pcursor->close();
}

void CWalletDB::ListCoinSpendSerial(std::list <CSigmaSpendEntry> &listCoinSpendSerial) {
    Dbc *pcursor = GetCursor();
    if (!pcursor)
        throw std::runtime_error("CWalletDB::ListCoinSpendSerial() : cannot create DB cursor");
    bool setRange = true;
    while (true) {
        // Read next record
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        if (setRange)
            ssKey << std::make_pair(std::string("sigma_spend"), secp_primitives::GroupElement());
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        int ret = ReadAtCursor(pcursor, ssKey, ssValue, setRange);
        setRange = false;
        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0) {
            pcursor->close();
            throw std::runtime_error("CWalletDB::ListCoinSpendSerial() : error scanning DB");
        }

        // Unserialize
        std::string strType;
        ssKey >> strType;
        if (strType != "sigma_spend")
            break;
        Scalar value;
        ssKey >> value;
        CSigmaSpendEntry sigmaSpendItem;
        ssValue >> sigmaSpendItem;
        listCoinSpendSerial.push_back(sigmaSpendItem);
    }

    pcursor->close();
}

void CWalletDB::ListLelantusSpendSerial(std::list <CLelantusSpendEntry>& listLelantusSpendSerial) {
    Dbc *pcursor = GetCursor();
    if (!pcursor)
        throw std::runtime_error("CWalletDB::ListLelantusSpendSerial() : cannot create DB cursor");
    bool setRange = true;
    while (true) {
        // Read next record
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        if (setRange)
            ssKey << std::make_pair(std::string("lelantus_spend"), secp_primitives::Scalar());
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        int ret = ReadAtCursor(pcursor, ssKey, ssValue, setRange);
        setRange = false;
        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0) {
            pcursor->close();
            throw std::runtime_error("CWalletDB::ListLelantusSpendSerial() : error scanning DB");
        }

        // Unserialize
        std::string strType;
        ssKey >> strType;
        if (strType != "lelantus_spend")
            break;
        Scalar value;
        ssKey >> value;
        CLelantusSpendEntry lelantusSpendItem;
        ssValue >> lelantusSpendItem;
        listLelantusSpendSerial.push_back(lelantusSpendItem);
    }

    pcursor->close();
}

DBErrors CWalletDB::ReorderTransactions(CWallet* pwallet)
{
    LOCK(pwallet->cs_wallet);
    // Old wallets didn't have any defined order for transactions
    // Probably a bad idea to change the output of this

    // First: get all CWalletTx and CAccountingEntry into a sorted-by-time multimap.
    typedef std::pair<CWalletTx*, CAccountingEntry*> TxPair;
    typedef std::multimap<int64_t, TxPair > TxItems;
    TxItems txByTime;

    for (std::map<uint256, CWalletTx>::iterator it = pwallet->mapWallet.begin(); it != pwallet->mapWallet.end(); ++it)
    {
        CWalletTx* wtx = &((*it).second);
        txByTime.insert(std::make_pair(wtx->nTimeReceived, TxPair(wtx, (CAccountingEntry*)0)));
    }
    std::list<CAccountingEntry> acentries;
    ListAccountCreditDebit("", acentries);
    BOOST_FOREACH(CAccountingEntry& entry, acentries)
    {
        txByTime.insert(std::make_pair(entry.nTime, TxPair((CWalletTx*)0, &entry)));
    }

    int64_t& nOrderPosNext = pwallet->nOrderPosNext;
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
                if (!WriteTx(*pwtx))
                    return DB_LOAD_FAIL;
            }
            else
                if (!WriteAccountingEntry(pacentry->nEntryNo, *pacentry))
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
                if (!WriteTx(*pwtx))
                    return DB_LOAD_FAIL;
            }
            else
                if (!WriteAccountingEntry(pacentry->nEntryNo, *pacentry))
                    return DB_LOAD_FAIL;
        }
    }
    WriteOrderPosNext(nOrderPosNext);

    return DB_LOAD_OK;
}

bool CWalletDB::WriteHDMint(const uint256& hashPubcoin, const CHDMint& dMint, bool isLelantus)
{
    std::string name;
    if(!isLelantus)
        name = "hdmint";
    else
        name = "hdmint_lelantus";
    return Write(std::make_pair(name, hashPubcoin), dMint, true);
}

bool CWalletDB::ReadHDMint(const uint256& hashPubcoin, bool isLelantus, CHDMint& dMint)
{
    std::string name;
    if(!isLelantus)
        name = "hdmint";
    else
        name = "hdmint_lelantus";
    return Read(std::make_pair(name, hashPubcoin), dMint);
}

bool CWalletDB::EraseHDMint(const CHDMint& dMint) {
    nWalletDBUpdateCounter++;
    uint256 hash = dMint.GetPubCoinHash();
    return Erase(std::make_pair(std::string("hdmint"), hash)) || Erase(std::make_pair(std::string("hdmint_lelantus"), hash));
}

bool CWalletDB::HasHDMint(const secp_primitives::GroupElement& pub) {
    return Exists(std::make_pair(std::string("hdmint"), primitives::GetPubCoinValueHash(pub))) || Exists(std::make_pair(std::string("hdmint_lelantus"), primitives::GetPubCoinValueHash(pub)));
}

bool CWalletDB::WritePubcoinHashes(const uint256& fullHash, const uint256& reducedHash) {
    return Write(std::make_pair(std::string("pubhash"), fullHash), reducedHash, true);
}

bool CWalletDB::ReadPubcoinHashes(const uint256& fullHash, uint256& reducedHash) {
    return Read(std::make_pair(std::string("pubhash"), fullHash), reducedHash);
}

bool CWalletDB::ErasePubcoinHashes(const uint256& fullHash) {
    return Erase(std::make_pair(std::string("pubhash"), fullHash));
}

class CWalletScanState {
public:
    unsigned int nKeys;
    unsigned int nCKeys;
    unsigned int nWatchKeys;
    unsigned int nKeyMeta;
    bool fIsEncrypted;
    bool fAnyUnordered;
    bool fUpgradeHDChain;
    int nFileVersion;
    std::vector<uint256> vWalletUpgrade;

    CWalletScanState() {
        nKeys = nCKeys = nWatchKeys = nKeyMeta = 0;
        fIsEncrypted = false;
        fAnyUnordered = false;
        fUpgradeHDChain = false;
        nFileVersion = 0;
    }
};

bool
ReadKeyValue(CWallet* pwallet, CDataStream& ssKey, CDataStream& ssValue,
             CWalletScanState &wss, std::string& strType, std::string& strErr)
{
    try {
        // Unserialize
        // Taking advantage of the fact that pair serialization
        // is just the two items serialized one after the other
        ssKey >> strType;
        if (strType == "kv")
        {
            std::string key, value;
            ssKey >> key;
            ssValue >> value;
            pwallet->mapCustomKeyValues.insert(std::make_pair(key, value));
        }
        else if (strType == "name")
        {
            std::string strAddress;
            ssKey >> strAddress;
            ssValue >> pwallet->mapAddressBook[CBitcoinAddress(strAddress).Get()].name;
        }
        else if (strType == "purpose")
        {
            std::string strAddress;
            ssKey >> strAddress;
            ssValue >> pwallet->mapAddressBook[CBitcoinAddress(strAddress).Get()].purpose;
        }
        else if (strType == "tx")
        {
            uint256 hash;
            ssKey >> hash;
            CWalletTx wtx;
            ssValue >> wtx;
            CValidationState state;
            if (!(CheckTransaction(wtx, state, true, wtx.GetHash(), true, INT_MAX, false, false) && (wtx.GetHash() == hash) && state.IsValid()))
                return false;

            // Undo serialize changes in 31600
            if (31404 <= wtx.fTimeReceivedIsTxTime && wtx.fTimeReceivedIsTxTime <= 31703)
            {
                if (!ssValue.empty())
                {
                    char fTmp;
                    char fUnused;
                    ssValue >> fTmp >> fUnused >> wtx.strFromAccount;
                    strErr = strprintf("LoadWallet() upgrading tx ver=%d %d '%s' %s",
                                       wtx.fTimeReceivedIsTxTime, fTmp, wtx.strFromAccount, hash.ToString());
                    wtx.fTimeReceivedIsTxTime = fTmp;
                }
                else
                {
                    strErr = strprintf("LoadWallet() repairing tx ver=%d %s", wtx.fTimeReceivedIsTxTime, hash.ToString());
                    wtx.fTimeReceivedIsTxTime = 0;
                }
                wss.vWalletUpgrade.push_back(hash);
            }

            if (wtx.nOrderPos == -1)
                wss.fAnyUnordered = true;

            pwallet->LoadToWallet(wtx);
        }
        else if (strType == "acentry")
        {
            std::string strAccount;
            ssKey >> strAccount;
            uint64_t nNumber;
            ssKey >> nNumber;
            if (nNumber > nAccountingEntryNumber)
                nAccountingEntryNumber = nNumber;

            if (!wss.fAnyUnordered)
            {
                CAccountingEntry acentry;
                ssValue >> acentry;
                if (acentry.nOrderPos == -1)
                    wss.fAnyUnordered = true;
            }
        }
        else if (strType == "watchs")
        {
            wss.nWatchKeys++;
            CScript script;
            ssKey >> *(CScriptBase*)(&script);
            char fYes;
            ssValue >> fYes;
            if (fYes == '1')
                pwallet->LoadWatchOnly(script);
        }
        else if (strType == "key" || strType == "wkey")
        {
            CPubKey vchPubKey;
            ssKey >> vchPubKey;
            if (!vchPubKey.IsValid())
            {
                strErr = "Error reading wallet database: CPubKey corrupt";
                return false;
            }
            CKey key;
            CPrivKey pkey;
            uint256 hash;

            if (strType == "key")
            {
                wss.nKeys++;
                ssValue >> pkey;
            } else {
                CWalletKey wkey;
                ssValue >> wkey;
                pkey = wkey.vchPrivKey;
            }

            // Old wallets store keys as "key" [pubkey] => [privkey]
            // ... which was slow for wallets with lots of keys, because the public key is re-derived from the private key
            // using EC operations as a checksum.
            // Newer wallets store keys as "key"[pubkey] => [privkey][hash(pubkey,privkey)], which is much faster while
            // remaining backwards-compatible.
            try
            {
                ssValue >> hash;
            }
            catch (...) {}

            bool fSkipCheck = false;

            if (!hash.IsNull())
            {
                // hash pubkey/privkey to accelerate wallet load
                std::vector<unsigned char> vchKey;
                vchKey.reserve(vchPubKey.size() + pkey.size());
                vchKey.insert(vchKey.end(), vchPubKey.begin(), vchPubKey.end());
                vchKey.insert(vchKey.end(), pkey.begin(), pkey.end());

                if (Hash(vchKey.begin(), vchKey.end()) != hash)
                {
                    strErr = "Error reading wallet database: CPubKey/CPrivKey corrupt";
                    return false;
                }

                fSkipCheck = true;
            }

            if (!key.Load(pkey, vchPubKey, fSkipCheck))
            {
                strErr = "Error reading wallet database: CPrivKey corrupt";
                return false;
            }
            if (!pwallet->LoadKey(key, vchPubKey))
            {
                strErr = "Error reading wallet database: LoadKey failed";
                return false;
            }
        }
        else if (strType == "mkey")
        {
            unsigned int nID;
            ssKey >> nID;
            CMasterKey kMasterKey;
            ssValue >> kMasterKey;
            if(pwallet->mapMasterKeys.count(nID) != 0)
            {
                strErr = strprintf("Error reading wallet database: duplicate CMasterKey id %u", nID);
                return false;
            }
            pwallet->mapMasterKeys[nID] = kMasterKey;
            if (pwallet->nMasterKeyMaxID < nID)
                pwallet->nMasterKeyMaxID = nID;
        }
        else if (strType == "ckey")
        {
            CPubKey vchPubKey;
            ssKey >> vchPubKey;
            if (!vchPubKey.IsValid())
            {
                strErr = "Error reading wallet database: CPubKey corrupt";
                return false;
            }
            std::vector<unsigned char> vchPrivKey;
            ssValue >> vchPrivKey;
            wss.nCKeys++;

            if (!pwallet->LoadCryptedKey(vchPubKey, vchPrivKey))
            {
                strErr = "Error reading wallet database: LoadCryptedKey failed";
                return false;
            }
            wss.fIsEncrypted = true;
        }
        else if (strType == "keymeta" || strType == "watchmeta")
        {
            CTxDestination keyID;
            if (strType == "keymeta")
            {
              CPubKey vchPubKey;
              ssKey >> vchPubKey;
              keyID = vchPubKey.GetID();
            }
            else if (strType == "watchmeta")
            {
              CScript script;
              ssKey >> *(CScriptBase*)(&script);
              keyID = CScriptID(script);
            }

            CKeyMetadata keyMeta;
            ssValue >> keyMeta;
            wss.nKeyMeta++;

            pwallet->LoadKeyMetadata(keyID, keyMeta);
        }
        else if (strType == "defaultkey")
        {
            ssValue >> pwallet->vchDefaultKey;
        }
        else if (strType == "pool")
        {
            int64_t nIndex;
            ssKey >> nIndex;
            CKeyPool keypool;
            ssValue >> keypool;

            pwallet->LoadKeyPool(nIndex, keypool);
        }
        else if (strType == "version")
        {
            ssValue >> wss.nFileVersion;
            if (wss.nFileVersion == 10300)
                wss.nFileVersion = 300;
        }
        else if (strType == "cscript")
        {
            uint160 hash;
            ssKey >> hash;
            CScript script;
            ssValue >> *(CScriptBase*)(&script);
            if (!pwallet->LoadCScript(script))
            {
                strErr = "Error reading wallet database: LoadCScript failed";
                return false;
            }
        }
        else if (strType == "orderposnext")
        {
            ssValue >> pwallet->nOrderPosNext;
        }
        else if (strType == "destdata")
        {
            std::string strAddress, strKey, strValue;
            ssKey >> strAddress;
            ssKey >> strKey;
            ssValue >> strValue;
            if (!pwallet->LoadDestData(CBitcoinAddress(strAddress).Get(), strKey, strValue))
            {
                strErr = "Error reading wallet database: LoadDestData failed";
                return false;
            }
        }
        else if (strType == "hdchain")
        {
            CHDChain chain;
            ssValue >> chain;
            if (!pwallet->SetHDChain(chain, true, wss.fUpgradeHDChain, false))
            {
                strErr = "Error reading wallet database: SetHDChain failed";
                return false;
            }
        }
        else if (strType == "mnemonic") {
            MnemonicContainer mnContainer;
            ssValue >> mnContainer;
            if (!pwallet->SetMnemonicContainer(mnContainer, true)) {
                strErr = "Error reading wallet database: SetMnemonicContainer failed";
                return false;
            }
        }
    } catch (...)
    {
        return false;
    }
    return true;
}

static bool IsKeyType(std::string strType)
{
    return (strType== "key" || strType == "wkey" ||
            strType == "mkey" || strType == "ckey");
}

DBErrors CWalletDB::LoadWallet(CWallet* pwallet)
{
    pwallet->vchDefaultKey = CPubKey();
    CWalletScanState wss;
    bool fNoncriticalErrors = false;
    DBErrors result = DB_LOAD_OK;

    LOCK2(cs_main, pwallet->cs_wallet);
    try {
        int nMinVersion = 0;
        if (Read((std::string)"minversion", nMinVersion))
        {
            if (nMinVersion > CLIENT_VERSION)
                return DB_TOO_NEW;
            pwallet->LoadMinVersion(nMinVersion);
        }

        // Get cursor
        Dbc* pcursor = GetCursor();
        if (!pcursor)
        {
            LogPrintf("Error getting wallet database cursor\n");
            return DB_CORRUPT;
        }

        while (true)
        {
            // Read next record
            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
            CDataStream ssValue(SER_DISK, CLIENT_VERSION);
            int ret = ReadAtCursor(pcursor, ssKey, ssValue);
            if (ret == DB_NOTFOUND)
                break;
            else if (ret != 0)
            {
                LogPrintf("Error reading next record from wallet database\n");
                return DB_CORRUPT;
            }

            // Try to be tolerant of single corrupt records:
            std::string strType, strErr;
            if (!ReadKeyValue(pwallet, ssKey, ssValue, wss, strType, strErr))
            {
                // losing keys is considered a catastrophic error, anything else
                // we assume the user can live with:
                if (IsKeyType(strType))
                    result = DB_CORRUPT;
                else
                {
                    // Leave other errors alone, if we try to fix them we might make things worse.
                    fNoncriticalErrors = true; // ... but do warn the user there is something wrong.
                    if (strType == "tx")
                        // Rescan if there is a bad transaction record:
                        SoftSetBoolArg("-rescan", true);
                }
            }
            if (!strErr.empty())
                LogPrintf("%s\n", strErr);
        }
        pcursor->close();
    }
    catch (const boost::thread_interrupted&) {
        throw;
    }
    catch (...) {
        result = DB_CORRUPT;
    }

    if (fNoncriticalErrors && result == DB_LOAD_OK)
        result = DB_NONCRITICAL_ERROR;

    // Any wallet corruption at all: skip any rewriting or
    // upgrading, we don't want to make it worse.
    if (result != DB_LOAD_OK)
        return result;

    LogPrintf("nFileVersion = %d\n", wss.nFileVersion);

    LogPrintf("Keys: %u plaintext, %u encrypted, %u w/ metadata, %u total\n",
           wss.nKeys, wss.nCKeys, wss.nKeyMeta, wss.nKeys + wss.nCKeys);

    // nTimeFirstKey is only reliable if all keys have metadata
    if ((wss.nKeys + wss.nCKeys + wss.nWatchKeys) != wss.nKeyMeta)
        pwallet->UpdateTimeFirstKey(1);

    BOOST_FOREACH(uint256 hash, wss.vWalletUpgrade)
        WriteTx(pwallet->mapWallet[hash]);

    // Rewrite encrypted wallets of versions 0.4.0 and 0.5.0rc:
    if (wss.fIsEncrypted && (wss.nFileVersion == 40000 || wss.nFileVersion == 50000))
        return DB_NEED_REWRITE;

    if (wss.nFileVersion < CLIENT_VERSION) // Update
        WriteVersion(CLIENT_VERSION);

    if (wss.fAnyUnordered)
        result = pwallet->ReorderTransactions();

    pwallet->laccentries.clear();
    ListAccountCreditDebit("*", pwallet->laccentries);
    BOOST_FOREACH(CAccountingEntry& entry, pwallet->laccentries) {
        pwallet->wtxOrdered.insert(std::make_pair(entry.nOrderPos, CWallet::TxPair((CWalletTx*)0, &entry)));
    }

    // unencrypted wallets upgrading the wallet version get a new keypool here
    if (wss.fUpgradeHDChain && !pwallet->IsLocked())
        pwallet->NewKeyPool();

    return result;
}

DBErrors CWalletDB::FindWalletTx(CWallet* pwallet, std::vector<uint256>& vTxHash, std::vector<CWalletTx>& vWtx)
{
    pwallet->vchDefaultKey = CPubKey();
    bool fNoncriticalErrors = false;
    DBErrors result = DB_LOAD_OK;

    try {
        LOCK(pwallet->cs_wallet);
        int nMinVersion = 0;
        if (Read((std::string)"minversion", nMinVersion))
        {
            if (nMinVersion > CLIENT_VERSION)
                return DB_TOO_NEW;
            pwallet->LoadMinVersion(nMinVersion);
        }

        // Get cursor
        Dbc* pcursor = GetCursor();
        if (!pcursor)
        {
            LogPrintf("Error getting wallet database cursor\n");
            return DB_CORRUPT;
        }

        while (true)
        {
            // Read next record
            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
            CDataStream ssValue(SER_DISK, CLIENT_VERSION);
            int ret = ReadAtCursor(pcursor, ssKey, ssValue);
            if (ret == DB_NOTFOUND)
                break;
            else if (ret != 0)
            {
                LogPrintf("Error reading next record from wallet database\n");
                return DB_CORRUPT;
            }

            std::string strType;
            ssKey >> strType;
            if (strType == "tx") {
                uint256 hash;
                ssKey >> hash;

                CWalletTx wtx;
                ssValue >> wtx;

                vTxHash.push_back(hash);
                vWtx.push_back(wtx);
            }
        }
        pcursor->close();
    }
    catch (const boost::thread_interrupted&) {
        throw;
    }
    catch (...) {
        result = DB_CORRUPT;
    }

    if (fNoncriticalErrors && result == DB_LOAD_OK)
        result = DB_NONCRITICAL_ERROR;

    return result;
}

DBErrors CWalletDB::ZapSelectTx(CWallet* pwallet, std::vector<uint256>& vTxHashIn, std::vector<uint256>& vTxHashOut)
{
    // build list of wallet TXs and hashes
    std::vector<uint256> vTxHash;
    std::vector<CWalletTx> vWtx;
    DBErrors err = FindWalletTx(pwallet, vTxHash, vWtx);
    if (err != DB_LOAD_OK) {
        return err;
    }

    std::sort(vTxHash.begin(), vTxHash.end());
    std::sort(vTxHashIn.begin(), vTxHashIn.end());

    // erase each matching wallet TX
    bool delerror = false;
    std::vector<uint256>::iterator it = vTxHashIn.begin();
    BOOST_FOREACH (uint256 hash, vTxHash) {
        while (it < vTxHashIn.end() && (*it) < hash) {
            it++;
        }
        if (it == vTxHashIn.end()) {
            break;
        }
        else if ((*it) == hash) {
            pwallet->mapWallet.erase(hash);
            if(!EraseTx(hash)) {
                LogPrint("db", "Transaction was found for deletion but returned database error: %s\n", hash.GetHex());
                delerror = true;
            }
            vTxHashOut.push_back(hash);
        }
    }

    if (delerror) {
        return DB_CORRUPT;
    }
    return DB_LOAD_OK;
}

DBErrors CWalletDB::ZapSigmaMints(CWallet *pwallet) {
    // get list of HD Mints
    std::list<CHDMint> vHDMints = ListHDMints(false);

    // get list of non HD Mints
    std::list <CSigmaEntry> sigmaEntries;
    ListSigmaPubCoin(sigmaEntries);

    // erase each HD Mint
    BOOST_FOREACH(CHDMint & hdMint, vHDMints)
    {
        if (!EraseHDMint(hdMint))
            return DB_CORRUPT;
    }

    // erase each non HD Mint
    BOOST_FOREACH(CSigmaEntry & sigmaEntry, sigmaEntries)
    {
        if (!EraseSigmaEntry(sigmaEntry))
            return DB_CORRUPT;
    }

    return DB_LOAD_OK;
}

DBErrors CWalletDB::ZapLelantusMints(CWallet *pwallet) {
    // get list of HD Mints
    std::list<CHDMint> lelantusHDMints = ListHDMints(true);

    // erase each HD Mint
    BOOST_FOREACH(CHDMint & hdMint, lelantusHDMints)
    {
        if (!EraseHDMint(hdMint))
            return DB_CORRUPT;
    }

    return DB_LOAD_OK;
}

DBErrors CWalletDB::ZapWalletTx(CWallet* pwallet, std::vector<CWalletTx>& vWtx)
{
    // build list of wallet TXs
    std::vector<uint256> vTxHash;
    DBErrors err = FindWalletTx(pwallet, vTxHash, vWtx);
    if (err != DB_LOAD_OK)
        return err;

    // erase each wallet TX
    BOOST_FOREACH (uint256& hash, vTxHash) {
        if (!EraseTx(hash))
            return DB_CORRUPT;
    }

    return DB_LOAD_OK;
}

void ThreadFlushWalletDB()
{
    // Make this thread recognisable as the wallet flushing thread
    RenameThread("firo-wallet");

    static bool fOneThread;
    if (fOneThread)
        return;
    fOneThread = true;
    if (!GetBoolArg("-flushwallet", DEFAULT_FLUSHWALLET))
        return;

    unsigned int nLastSeen = CWalletDB::GetUpdateCounter();
    unsigned int nLastFlushed = CWalletDB::GetUpdateCounter();
    int64_t nLastWalletUpdate = GetTime();
    while (true)
    {
        MilliSleep(500);

        if (nLastSeen != CWalletDB::GetUpdateCounter())
        {
            nLastSeen = CWalletDB::GetUpdateCounter();
            nLastWalletUpdate = GetTime();
        }

        if (nLastFlushed != CWalletDB::GetUpdateCounter() && GetTime() - nLastWalletUpdate >= 2)
        {
            TRY_LOCK(bitdb.cs_db,lockDb);
            if (lockDb)
            {
                // Don't do this if any databases are in use
                int nRefCount = 0;
                std::map<std::string, int>::iterator mi = bitdb.mapFileUseCount.begin();
                while (mi != bitdb.mapFileUseCount.end())
                {
                    nRefCount += (*mi).second;
                    mi++;
                }

                if (nRefCount == 0)
                {
                    boost::this_thread::interruption_point();
                    const std::string& strFile = pwalletMain->strWalletFile;
                    std::map<std::string, int>::iterator _mi = bitdb.mapFileUseCount.find(strFile);
                    if (_mi != bitdb.mapFileUseCount.end())
                    {
                        LogPrint("db", "Flushing %s\n", strFile);
                        nLastFlushed = CWalletDB::GetUpdateCounter();
                        int64_t nStart = GetTimeMillis();

                        // Flush wallet file so it's self contained
                        bitdb.CloseDb(strFile);
                        bitdb.CheckpointLSN(strFile);

                        bitdb.mapFileUseCount.erase(_mi++);
                        LogPrint("db", "Flushed %s %dms\n", strFile, GetTimeMillis() - nStart);
                    }
                }
            }
        }
    }
}

// This should be called carefully:
// either supply "wallet" (if already loaded) or "strWalletFile" (if wallet wasn't loaded yet)
bool AutoBackupWallet (CWallet* wallet, std::string strWalletFile, std::string& strBackupWarning, std::string& strBackupError)
{
    namespace fs = boost::filesystem;

    strBackupWarning = strBackupError = "";

    if(nWalletBackups > 0)
    {
        fs::path backupsDir = GetBackupsDir();

        if (!fs::exists(backupsDir))
        {
            // Always create backup folder to not confuse the operating system's file browser
            LogPrintf("Creating backup folder %s\n", backupsDir.string());
            if(!fs::create_directories(backupsDir)) {
                // smth is wrong, we shouldn't continue until it's resolved
                strBackupError = strprintf(_("Wasn't able to create wallet backup folder %s!"), backupsDir.string());
                LogPrintf("%s\n", strBackupError);
                nWalletBackups = -1;
                return false;
            }
        }

        // Create backup of the ...
        std::string dateTimeStr = DateTimeStrFormat(".%Y-%m-%d-%H-%M", GetTime());
        if (wallet)
        {
            // ... opened wallet
            LOCK2(cs_main, wallet->cs_wallet);
            strWalletFile = wallet->strWalletFile;
            fs::path backupFile = backupsDir / (strWalletFile + dateTimeStr);
//            if(!BackupWallet(*wallet, backupFile.std::string())) {
//                strBackupWarning = strprintf(_("Failed to create backup %s!"), backupFile.std::string());
//                LogPrintf("%s\n", strBackupWarning);
//                nWalletBackups = -1;
//                return false;
//            }
            // Update nKeysLeftSinceAutoBackup using current pool size
            wallet->nKeysLeftSinceAutoBackup = wallet->GetKeyPoolSize();
            LogPrintf("nKeysLeftSinceAutoBackup: %d\n", wallet->nKeysLeftSinceAutoBackup);
            if(wallet->IsLocked()) {
                strBackupWarning = _("Wallet is locked, can't replenish keypool! Automatic backups and mixing are disabled, please unlock your wallet to replenish keypool.");
                LogPrintf("%s\n", strBackupWarning);
                nWalletBackups = -2;
                return false;
            }
        } else {
            // ... strWalletFile file
            fs::path sourceFile = GetDataDir() / strWalletFile;
            fs::path backupFile = backupsDir / (strWalletFile + dateTimeStr);
            sourceFile.make_preferred();
            backupFile.make_preferred();
            if (fs::exists(backupFile))
            {
                strBackupWarning = _("Failed to create backup, file already exists! This could happen if you restarted wallet in less than 60 seconds. You can continue if you are ok with this.");
                LogPrintf("%s\n", strBackupWarning);
                return false;
            }
            if(fs::exists(sourceFile)) {
                try {
                    fs::copy_file(sourceFile, backupFile);
                    LogPrintf("Creating backup of %s -> %s\n", sourceFile.string(), backupFile.string());
                } catch(fs::filesystem_error &error) {
                    strBackupWarning = strprintf(_("Failed to create backup, error: %s"), error.what());
                    LogPrintf("%s\n", strBackupWarning);
                    nWalletBackups = -1;
                    return false;
                }
            }
        }

        // Keep only the last 10 backups, including the new one of course
        typedef std::multimap<std::time_t, fs::path> folder_set_t;
        folder_set_t folder_set;
        fs::directory_iterator end_iter;
        backupsDir.make_preferred();
        // Build map of backup files for current(!) wallet sorted by last write time
        fs::path currentFile;
        for (fs::directory_iterator dir_iter(backupsDir); dir_iter != end_iter; ++dir_iter)
        {
            // Only check regular files
            if ( fs::is_regular_file(dir_iter->status()))
            {
                currentFile = dir_iter->path().filename();
                // Only add the backups for the current wallet, e.g. wallet.dat.*
                if(dir_iter->path().stem().string() == strWalletFile)
                {
                    folder_set.insert(folder_set_t::value_type(fs::last_write_time(dir_iter->path()), *dir_iter));
                }
            }
        }

        // Loop backward through backup files and keep the N newest ones (1 <= N <= 10)
        int counter = 0;
        BOOST_REVERSE_FOREACH(PAIRTYPE(const std::time_t, fs::path) file, folder_set)
        {
            counter++;
            if (counter > nWalletBackups)
            {
                // More than nWalletBackups backups: delete oldest one(s)
                try {
                    fs::remove(file.second);
                    LogPrintf("Old backup deleted: %s\n", file.second);
                } catch(fs::filesystem_error &error) {
                    strBackupWarning = strprintf(_("Failed to delete backup, error: %s"), error.what());
                    LogPrintf("%s\n", strBackupWarning);
                    return false;
                }
            }
        }
        return true;
    }

    LogPrintf("Automatic wallet backups are disabled!\n");
    return false;
}

//
// Try to (very carefully!) recover wallet file if there is a problem.
//
bool CWalletDB::Recover(CDBEnv& dbenv, const std::string& filename, bool fOnlyKeys)
{
    // Recovery procedure:
    // move wallet file to wallet.timestamp.bak
    // Call Salvage with fAggressive=true to
    // get as much data as possible.
    // Rewrite salvaged data to fresh wallet file
    // Set -rescan so any missing transactions will be
    // found.
    int64_t now = GetTime();
    std::string newFilename = strprintf("wallet.%d.bak", now);

    int result = dbenv.dbenv->dbrename(NULL, filename.c_str(), NULL,
                                       newFilename.c_str(), DB_AUTO_COMMIT);
    if (result == 0)
        LogPrintf("Renamed %s to %s\n", filename, newFilename);
    else
    {
        LogPrintf("Failed to rename %s to %s\n", filename, newFilename);
        return false;
    }

    std::vector<CDBEnv::KeyValPair> salvagedData;
    bool fSuccess = dbenv.Salvage(newFilename, true, salvagedData);
    if (salvagedData.empty())
    {
        LogPrintf("Salvage(aggressive) found no records in %s.\n", newFilename);
        return false;
    }
    LogPrintf("Salvage(aggressive) found %u records\n", salvagedData.size());

    std::unique_ptr<Db> pdbCopy(new Db(dbenv.dbenv, 0));
    int ret = pdbCopy->open(NULL,               // Txn pointer
                            filename.c_str(),   // Filename
                            "main",             // Logical db name
                            DB_BTREE,           // Database type
                            DB_CREATE,          // Flags
                            0);
    if (ret > 0)
    {
        LogPrintf("Cannot create database file %s\n", filename);
        return false;
    }
    CWallet dummyWallet;
    CWalletScanState wss;

    DbTxn* ptxn = dbenv.TxnBegin();
    BOOST_FOREACH(CDBEnv::KeyValPair& row, salvagedData)
    {
        if (fOnlyKeys)
        {
            CDataStream ssKey(row.first, SER_DISK, CLIENT_VERSION);
            CDataStream ssValue(row.second, SER_DISK, CLIENT_VERSION);
            std::string strType, strErr;
            bool fReadOK;
            {
                // Required in LoadKeyMetadata():
                LOCK(dummyWallet.cs_wallet);
                fReadOK = ReadKeyValue(&dummyWallet, ssKey, ssValue,
                                        wss, strType, strErr);
            }
            if (!IsKeyType(strType) && strType != "hdchain")
                continue;
            if (!fReadOK)
            {
                LogPrintf("WARNING: CWalletDB::Recover skipping %s: %s\n", strType, strErr);
                continue;
            }
        }
        Dbt datKey(&row.first[0], row.first.size());
        Dbt datValue(&row.second[0], row.second.size());
        int ret2 = pdbCopy->put(ptxn, &datKey, &datValue, DB_NOOVERWRITE);
        if (ret2 > 0)
            fSuccess = false;
    }
    ptxn->commit(0);
    pdbCopy->close(0);

    return fSuccess;
}

bool CWalletDB::Recover(CDBEnv& dbenv, const std::string& filename)
{
    return CWalletDB::Recover(dbenv, filename, false);
}

bool CWalletDB::WriteDestData(const std::string &address, const std::string &key, const std::string &value)
{
    nWalletDBUpdateCounter++;
    return Write(std::make_pair(std::string("destdata"), std::make_pair(address, key)), value);
}

bool CWalletDB::EraseDestData(const std::string &address, const std::string &key)
{
    nWalletDBUpdateCounter++;
    return Erase(std::make_pair(std::string("destdata"), std::make_pair(address, key)));
}


bool CWalletDB::WriteHDChain(const CHDChain& chain)
{
    nWalletDBUpdateCounter++;
    return Write(std::string("hdchain"), chain);
}
/******************************************************************************/
// Mnemonic
/******************************************************************************/

bool CWalletDB::WriteMnemonic(const MnemonicContainer& mnContainer) {
    nWalletDBUpdateCounter++;
    return Write(std::string("mnemonic"), mnContainer);
}

bool CWalletDB::ReadMintCount(int32_t& nCount)
{
    return Read(std::string("dzc"), nCount);
}

bool CWalletDB::WriteMintCount(const int32_t& nCount)
{
    return Write(std::string("dzc"), nCount);
}

bool CWalletDB::ReadMintSeedCount(int32_t& nCount)
{
    return Read(std::string("dzsc"), nCount);
}

bool CWalletDB::WriteMintSeedCount(const int32_t& nCount)
{
    return Write(std::string("dzsc"), nCount);
}

bool CWalletDB::WritePubcoin(const uint256& hashSerial, const GroupElement& pubcoin)
{
    return Write(std::make_pair(std::string("pubcoin"), hashSerial), pubcoin);
}

bool CWalletDB::ReadPubcoin(const uint256& hashSerial, GroupElement& pubcoin)
{
    return Read(std::make_pair(std::string("pubcoin"), hashSerial), pubcoin);
}

bool CWalletDB::ErasePubcoin(const uint256& hashSerial)
{
    return Erase(std::make_pair(std::string("pubcoin"), hashSerial));
}

std::vector<std::pair<uint256, GroupElement>> CWalletDB::ListSerialPubcoinPairs()
{
    std::vector<std::pair<uint256, GroupElement>> listSerialPubcoin;
    Dbc* pcursor = GetCursor();
    if (!pcursor)
        throw std::runtime_error(std::string(__func__)+" : cannot create DB cursor");
    bool setRange = true;
    for (;;)
    {
        // Read next record
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        if (setRange)
            ssKey << std::make_pair(std::string("pubcoin"), ArithToUint256(arith_uint256(0)));
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        int ret = ReadAtCursor(pcursor, ssKey, ssValue, setRange);
        setRange = false;
        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0)
        {
            pcursor->close();
            throw std::runtime_error(std::string(__func__)+" : error scanning DB");
        }

        // Unserialize
        std::string strType;
        ssKey >> strType;
        if (strType != "pubcoin")
            break;

        uint256 hashSerial;
        ssKey >> hashSerial;

        GroupElement pubcoin;
        ssValue >> pubcoin;

        listSerialPubcoin.push_back(std::make_pair(hashSerial, pubcoin));
    }

    pcursor->close();

    return listSerialPubcoin;

}

bool CWalletDB::EraseMintPoolPair(const uint256& hashPubcoin)
{
    return Erase(std::make_pair(std::string("mintpool"), hashPubcoin));
}

bool CWalletDB::WriteMintPoolPair(const uint256& hashPubcoin, const std::tuple<uint160, CKeyID, int32_t>& hashSeedMintPool)
{
    return Write(std::make_pair(std::string("mintpool"), hashPubcoin), hashSeedMintPool);
}

bool CWalletDB::ReadMintPoolPair(const uint256& hashPubcoin, uint160& hashSeedMaster, CKeyID& seedId, int32_t& nCount)
{
    std::tuple<uint160, CKeyID, int32_t> hashSeedMintPool;
    if(!Read(std::make_pair(std::string("mintpool"), hashPubcoin), hashSeedMintPool))
        return false;
    hashSeedMaster = std::get<0>(hashSeedMintPool);
    seedId = std::get<1>(hashSeedMintPool);
    nCount = std::get<2>(hashSeedMintPool);
    return true;
}

//! list of MintPoolEntry objects mapped with pubCoin hash, returned as pairs
std::vector<std::pair<uint256, MintPoolEntry>> CWalletDB::ListMintPool()
{
    std::vector<std::pair<uint256, MintPoolEntry>> listPool;
    Dbc* pcursor = GetCursor();
    if (!pcursor)
        throw std::runtime_error(std::string(__func__)+" : cannot create DB cursor");
    bool setRange = true;
    for (;;)
    {
        // Read next record
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        if (setRange)
            ssKey << std::make_pair(std::string("mintpool"), ArithToUint256(arith_uint256(0)));
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        int ret = ReadAtCursor(pcursor, ssKey, ssValue, setRange);
        setRange = false;
        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0)
        {
            pcursor->close();
            throw std::runtime_error(std::string(__func__)+" : error scanning DB");
        }

        // Unserialize

        try {
            std::string strType;
            ssKey >> strType;
            if (strType != "mintpool")
                break;

            uint256 hashPubcoin;
            ssKey >> hashPubcoin;

            uint160 hashSeedMaster;
            ssValue >> hashSeedMaster;

            CKeyID seedId;
            ssValue >> seedId;

            int32_t nCount;
            ssValue >> nCount;

            MintPoolEntry mintPoolEntry(hashSeedMaster, seedId, nCount);

            listPool.push_back(std::make_pair(hashPubcoin, mintPoolEntry));
        } catch (std::ios_base::failure const &) {
            // There maybe some old entries that don't conform to the latest version. Just skipping those.
        }
    }

    pcursor->close();

    return listPool;
}

std::list<CHDMint> CWalletDB::ListHDMints(bool isLelantus)
{
    std::list<CHDMint> listMints;
    Dbc* pcursor = GetCursor();
    if (!pcursor)
        throw std::runtime_error(std::string(__func__)+" : cannot create DB cursor");

    std::string mintName;

    if(isLelantus)
        mintName = "hdmint_lelantus";
    else
        mintName = "hdmint";

    bool setRange = true;
    for (;;)
    {
        // Read next record
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        if (setRange)
            ssKey << std::make_pair(mintName, ArithToUint256(arith_uint256(0)));
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        int ret = ReadAtCursor(pcursor, ssKey, ssValue, setRange);
        setRange = false;
        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0)
        {
            pcursor->close();
            throw std::runtime_error(std::string(__func__)+" : error scanning DB");
        }

        // Unserialize
        std::string strType;
        ssKey >> strType;
        if (strType != mintName)
            break;

        uint256 hashPubcoin;
        ssKey >> hashPubcoin;

        CHDMint mint;
        ssValue >> mint;

        listMints.emplace_back(mint);
    }

    pcursor->close();
    return listMints;
}

bool CWalletDB::ArchiveDeterministicOrphan(const CHDMint& dMint)
{
    if (!Write(std::make_pair(std::string("dzco"), dMint.GetPubCoinHash()), dMint))
        return error("%s: write failed", __func__);

    if (!Erase(std::make_pair(std::string("hdmint"), dMint.GetPubCoinHash())))
        return error("%s: failed to erase", __func__);

    if (!Erase(std::make_pair(std::string("hdmint_lelantus"), dMint.GetPubCoinHash())))
        return error("%s: failed to erase lelantus", __func__);

    return true;
}

bool CWalletDB::UnarchiveHDMint(const uint256& hashPubcoin, bool isLelantus, CHDMint& dMint)
{
    if (!Read(std::make_pair(std::string("dzco"), hashPubcoin), dMint))
        return error("%s: failed to retrieve deterministic mint from archive", __func__);

    if (!WriteHDMint(hashPubcoin, dMint, isLelantus))
        return error("%s: failed to write deterministic mint", __func__);

    if (!Erase(std::make_pair(std::string("dzco"), dMint.GetPubCoinHash())))
        return error("%s : failed to erase archived deterministic mint", __func__);

    return true;
}

bool CWalletDB::UnarchiveSigmaMint(const uint256& hashPubcoin, CSigmaEntry& sigma)
{
    if (!Read(std::make_pair(std::string("zco"), hashPubcoin), sigma))
        return error("%s: failed to retrieve sigmamint from archive", __func__);

    if (!WriteSigmaEntry(sigma))
        return error("%s: failed to write sigmamint", __func__);

    uint256 hash = primitives::GetPubCoinValueHash(sigma.value);
    if (!Erase(std::make_pair(std::string("zco"), hash)))
        return error("%s : failed to erase archived sigma mint", __func__);

    return true;
}

void CWalletDB::IncrementUpdateCounter()
{
    nWalletDBUpdateCounter++;
}

unsigned int CWalletDB::GetUpdateCounter()
{
    return nWalletDBUpdateCounter;
}


/******************************************************************************/
// BIP47
/******************************************************************************/

bool CWalletDB::WriteBip47Account(bip47::CAccountReceiver const & account)
{
    return Write(std::make_pair(std::string("bip47rcv"), uint32_t(account.getAccountNum())), account, true);
}

bool CWalletDB::WriteBip47Account(bip47::CAccountSender const & account)
{
    return Write(std::make_pair(std::string("bip47snd"), uint32_t(account.getAccountNum())), account, true);
}

void CWalletDB::LoadBip47Accounts(bip47::CWallet & wallet)
{
    ListEntries<uint32_t, bip47::CAccountReceiver>("bip47rcv",
            [&wallet](char, bip47::CAccountReceiver & receiver)
            {
                wallet.readReceiver(std::move(receiver));
            }
        );

    ListEntries<uint32_t, bip47::CAccountSender>("bip47snd",
            [&wallet](char, bip47::CAccountSender & sender)
            {
                wallet.readSender(std::move(sender));
            }
        );
}
