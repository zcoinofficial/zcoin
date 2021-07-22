// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_WALLETDB_H
#define BITCOIN_WALLET_WALLETDB_H

#include "amount.h"
#include "primitives/transaction.h"
#include "primitives/mint_spend.h"
#include "wallet/db.h"
#include "mnemoniccontainer.h"
#include "streams.h"
#include "key.h"

#include "hdmint/hdmint.h"
#include "hdmint/mintpool.h"
#include "../secp256k1/include/GroupElement.h"
#include "../secp256k1/include/Scalar.h"

#include <list>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/erase.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/lexical_cast.hpp>

static const bool DEFAULT_FLUSHWALLET = true;
static const uint32_t ORIGINAL_KEYPATH_SIZE = 0x4; // m/0'/0'/<n> is the original keypath
static const uint32_t BIP44_KEYPATH_SIZE = 0x6;    // m/44'/<1/136>'/0'/<c>/<n> is the BIP44 keypath

class CAccount;
class CAccountingEntry;
struct CBlockLocator;
class CKeyPool;
class CMasterKey;
class CScript;
class CWallet;
class CWalletTx;
class uint160;
class uint256;
class CSigmaEntry;
class CSigmaSpendEntry;

namespace bip47 {
class CAccountReceiver;
class CAccountSender;
class CWallet;
}

/** Error statuses for the wallet database */
enum DBErrors
{
    DB_LOAD_OK,
    DB_CORRUPT,
    DB_NONCRITICAL_ERROR,
    DB_TOO_NEW,
    DB_LOAD_FAIL,
    DB_NEED_REWRITE
};

// {value, isHardened}
typedef std::pair<uint32_t,bool> Component;

/* simple HD chain data model */
class CHDChain
{
public:
    uint32_t nExternalChainCounter; // VERSION_BASIC
    std::vector<uint32_t> nExternalChainCounters; // VERSION_WITH_BIP44: vector index corresponds to account value
    CKeyID masterKeyID; //!< master key hash160

    static const int VERSION_BASIC = 1;
    static const int VERSION_WITH_BIP44 = 10;
    static const int VERSION_WITH_BIP39 = 11;
    static const int CURRENT_VERSION = VERSION_WITH_BIP39;
    static const int N_CHANGES = 5; // standard = 0/1, mint = 2, elysium = 3, elysiumv1 = 4
    int nVersion;

    CHDChain() { SetNull(); }
    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {

        READWRITE(this->nVersion);
        READWRITE(nExternalChainCounter);
        READWRITE(masterKeyID);
        if (this->nVersion >= VERSION_WITH_BIP44) {
            READWRITE(nExternalChainCounters);
            nExternalChainCounters.resize(N_CHANGES);
        }
    }

    void SetNull()
    {
        nVersion = CHDChain::CURRENT_VERSION;
        masterKeyID.SetNull();
        nExternalChainCounter = 0;
        for(int index=0;index<N_CHANGES;index++){
            nExternalChainCounters.push_back(0);
        }
    }
};

class CKeyMetadata
{
public:
    static const int VERSION_BASIC=1;
    static const int VERSION_WITH_HDDATA=10;
    static const int CURRENT_VERSION=VERSION_WITH_HDDATA;
    int nVersion;
    int64_t nCreateTime; // 0 means unknown
    std::string hdKeypath; //optional HD/bip32 keypath
    Component nChange; // HD/bip32 keypath change counter
    Component nChild; // HD/bip32 keypath child counter
    CKeyID hdMasterKeyID; //id of the HD masterkey used to derive this key

    CKeyMetadata()
    {
        SetNull();
    }
    CKeyMetadata(int64_t nCreateTime_)
    {
        SetNull();
        nCreateTime = nCreateTime_;
    }

    bool ParseComponents(){
        std::vector<std::string> nComponents;
        if(hdKeypath.empty())
            return false;
        if(hdKeypath=="m")
            return true;

        boost::split(nComponents, hdKeypath, boost::is_any_of("/"), boost::token_compress_on);
        if(nComponents.size()!=ORIGINAL_KEYPATH_SIZE &&
           nComponents.size()!=BIP44_KEYPATH_SIZE)
            return false;

        std::string nChangeStr = nComponents[nComponents.size()-2];
        std::string nChildStr  = nComponents[nComponents.size()-1];

        nChange.second = (nChangeStr.find("'") != std::string::npos);
        boost::erase_all(nChangeStr, "'");
        nChange.first = boost::lexical_cast<uint32_t>(nChangeStr);

        nChild.second = (nChildStr.find("'") != std::string::npos);
        boost::erase_all(nChildStr, "'");
        nChild.first = boost::lexical_cast<uint32_t>(nChildStr);

        return true;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->nVersion);
        READWRITE(nCreateTime);
        if (this->nVersion >= VERSION_WITH_HDDATA)
        {
            READWRITE(hdKeypath);
            READWRITE(hdMasterKeyID);
        }
    }

    void SetNull()
    {
        nVersion = CKeyMetadata::CURRENT_VERSION;
        nCreateTime = 0;
        hdKeypath.clear();
        nChild = Component(0, false);
        nChange = Component(0, false);
        hdMasterKeyID.SetNull();
    }
};

/** Access to the wallet database */
class CWalletDB : public CDB
{
public:
    CWalletDB(const std::string& strFilename, const char* pszMode = "r+", bool fFlushOnClose = true) : CDB(strFilename, pszMode, fFlushOnClose)
    {
    }

    bool WriteKV(const std::string& key, const std::string& value);
    bool EraseKV(const std::string& key);

    bool WriteName(const std::string& strAddress, const std::string& strName);
    bool EraseName(const std::string& strAddress);

    bool WritePurpose(const std::string& strAddress, const std::string& purpose);
    bool ErasePurpose(const std::string& strAddress);

    bool WriteTx(const CWalletTx& wtx);
    bool EraseTx(uint256 hash);

    bool WriteKey(const CPubKey& vchPubKey, const CPrivKey& vchPrivKey, const CKeyMetadata &keyMeta);
    bool WriteCryptedKey(const CPubKey& vchPubKey, const std::vector<unsigned char>& vchCryptedSecret, const CKeyMetadata &keyMeta);
    bool WriteMasterKey(unsigned int nID, const CMasterKey& kMasterKey);

    bool WriteCScript(const uint160& hash, const CScript& redeemScript);

    bool WriteWatchOnly(const CScript &script, const CKeyMetadata &keymeta);
    bool EraseWatchOnly(const CScript &script);

    bool WriteBestBlock(const CBlockLocator& locator);
    bool ReadBestBlock(CBlockLocator& locator);

    bool WriteOrderPosNext(int64_t nOrderPosNext);

    bool WriteDefaultKey(const CPubKey& vchPubKey);

    bool ReadPool(int64_t nPool, CKeyPool& keypool);
    bool WritePool(int64_t nPool, const CKeyPool& keypool);
    bool ErasePool(int64_t nPool);

    bool WriteMinVersion(int nVersion);

    /// This writes directly to the database, and will not update the CWallet's cached accounting entries!
    /// Use wallet.AddAccountingEntry instead, to write *and* update its caches.
    bool WriteAccountingEntry(const uint64_t nAccEntryNum, const CAccountingEntry& acentry);
    bool WriteAccountingEntry_Backend(const CAccountingEntry& acentry);
    bool ReadAccount(const std::string& strAccount, CAccount& account);
    bool WriteAccount(const std::string& strAccount, const CAccount& account);

    /// Write destination data key,value tuple to database
    bool WriteDestData(const std::string &address, const std::string &key, const std::string &value);
    /// Erase destination data tuple from wallet database
    bool EraseDestData(const std::string &address, const std::string &key);

    CAmount GetAccountCreditDebit(const std::string& strAccount);
    void ListAccountCreditDebit(const std::string& strAccount, std::list<CAccountingEntry>& acentries);

    bool WriteSigmaEntry(const CSigmaEntry& sigma);
    bool ReadSigmaEntry(const secp_primitives::GroupElement& pub, CSigmaEntry& entry);
    bool HasSigmaEntry(const secp_primitives::GroupElement& pub);
    bool EraseSigmaEntry(const CSigmaEntry& sigma);
    void ListSigmaPubCoin(std::list<CSigmaEntry>& listPubCoin);
    void ListCoinSpendSerial(std::list<CSigmaSpendEntry>& listCoinSpendSerial);
    void ListLelantusSpendSerial(std::list<CLelantusSpendEntry>& listLelantusSpendSerial);
    bool WriteCoinSpendSerialEntry(const CSigmaSpendEntry& sigmaSpend);
    bool WriteLelantusSpendSerialEntry(const CLelantusSpendEntry& lelantusSpend);
    bool ReadLelantusSpendSerialEntry(const secp_primitives::Scalar& serial, CLelantusSpendEntry& lelantusSpend);
    bool HasCoinSpendSerialEntry(const secp_primitives::Scalar& serial);
    bool HasLelantusSpendSerialEntry(const secp_primitives::Scalar& serial);
    bool EraseCoinSpendSerialEntry(const CSigmaSpendEntry& sigmaSpend);
    bool EraseLelantusSpendSerialEntry(const CLelantusSpendEntry& lelantusSpend);

    bool ReadCalculatedZCBlock(int& height);
    bool WriteCalculatedZCBlock(int height);

    DBErrors ReorderTransactions(CWallet* pwallet);
    DBErrors LoadWallet(CWallet* pwallet);
    DBErrors FindWalletTx(CWallet* pwallet, std::vector<uint256>& vTxHash, std::vector<CWalletTx>& vWtx);
    DBErrors ZapWalletTx(CWallet* pwallet, std::vector<CWalletTx>& vWtx);
    DBErrors ZapSelectTx(CWallet* pwallet, std::vector<uint256>& vHashIn, std::vector<uint256>& vHashOut);
    DBErrors ZapSigmaMints(CWallet* pwallet);
    DBErrors ZapLelantusMints(CWallet *pwallet);
    static bool Recover(CDBEnv& dbenv, const std::string& filename, bool fOnlyKeys);
    static bool Recover(CDBEnv& dbenv, const std::string& filename);

    bool ReadMintCount(int32_t& nCount);
    bool WriteMintCount(const int32_t& nCount);

    bool ReadMintSeedCount(int32_t& nCount);
    bool WriteMintSeedCount(const int32_t& nCount);

    bool ArchiveDeterministicOrphan(const CHDMint& dMint);
    bool UnarchiveSigmaMint(const uint256& hashPubcoin, CSigmaEntry& sigma);
    bool UnarchiveHDMint(const uint256& hashPubcoin, bool isLelantus, CHDMint& dMint);

    bool WriteHDMint(const uint256& hashPubcoin, const CHDMint& dMint, bool isLelantus);
    bool ReadHDMint(const uint256& hashPubcoin, bool isLelantus, CHDMint& dMint);
    bool EraseHDMint(const CHDMint& dMint);
    bool HasHDMint(const secp_primitives::GroupElement& pub);

    bool WritePubcoinHashes(const uint256& fullHash, const uint256& reducedHash);
    bool ReadPubcoinHashes(const uint256& fullHash, uint256& reducedHash);
    bool ErasePubcoinHashes(const uint256& fullHash);

    std::list<CHDMint> ListHDMints(bool isLelantus);
    bool WritePubcoin(const uint256& hashSerial, const GroupElement& hashPubcoin);
    bool ReadPubcoin(const uint256& hashSerial, GroupElement& hashPubcoin);
    bool ErasePubcoin(const uint256& hashSerial);
    std::vector<std::pair<uint256, GroupElement>> ListSerialPubcoinPairs();
    bool EraseMintPoolPair(const uint256& hashPubcoin);
    bool WriteMintPoolPair(const uint256& hashPubcoin, const std::tuple<uint160, CKeyID, int32_t>& hashSeedMintPool);
    bool ReadMintPoolPair(const uint256& hashPubcoin, uint160& hashSeedMaster, CKeyID& seedId, int32_t& nCount);
    std::vector<std::pair<uint256, MintPoolEntry>> ListMintPool();

    //! write the hdchain model (external chain child index counter)
    bool WriteHDChain(const CHDChain& chain);
    bool WriteMnemonic(const MnemonicContainer& mnContainer);

    static void IncrementUpdateCounter();
    static unsigned int GetUpdateCounter();

#ifdef ENABLE_ELYSIUM

public:
    template<class MintPool>
    bool ReadElysiumMintPoolV0(MintPool &mintPool)
    {
        return Read(std::string("exodus_mint_pool"), mintPool);
    }

    template<class MintPool>
    bool WriteElysiumMintPoolV0(MintPool const &mintPool)
    {
        return Write(std::string("exodus_mint_pool"), mintPool, true);
    }

    bool HasElysiumMintPoolV0()
    {
        return Exists(std::string("exodus_mint_pool"));
    }

    template<class Key, class MintID>
    bool ReadElysiumMintIdV0(const Key& k, MintID &id)
    {
        return Read(std::make_pair(std::string("exodus_mint_id"), k), id);
    }

    template<class Key, class MintID>
    bool WriteElysiumMintIdV0(const Key& k, const MintID &id)
    {
        return Write(std::make_pair(std::string("exodus_mint_id"), k), id);
    }

    template<class Key>
    bool HasElysiumMintIdV0(const Key& k)
    {
        return Exists(std::make_pair(std::string("exodus_mint_id"), k));
    }

    template<class Key>
    bool EraseElysiumMintIdV0(const Key& k)
    {
        return Erase(std::make_pair(std::string("exodus_mint_id"), k));
    }

    template<class K, class V>
    bool ReadElysiumMintV0(const K& k, V& v)
    {
        return Read(std::make_pair(std::string("exodus_mint"), k), v);
    }

    template<class K>
    bool HasElysiumMintV0(const K& k)
    {
        return Exists(std::make_pair(std::string("exodus_mint"), k));
    }

    template<class K, class V>
    bool WriteElysiumMintV0(const K &k, const V &v)
    {
        return Write(std::make_pair(std::string("exodus_mint"), k), v, true);
    }

    template<class K>
    bool EraseElysiumMintV0(const K& k)
    {
        return Erase(std::make_pair(std::string("exodus_mint"), k));
    }

    template<typename K, typename V, typename InsertF>
    void ListElysiumMintsV0(InsertF insertF)
    {
        ListEntries<K, V, InsertF>(std::string("exodus_mint"), insertF);
    }

    // version 1
    template<class MintPool>
    bool ReadElysiumMintPoolV1(MintPool &mintPool)
    {
        return Read(std::string("exodus_mint_pool_v1"), mintPool);
    }

    template<class MintPool>
    bool WriteElysiumMintPoolV1(MintPool const &mintPool)
    {
        return Write(std::string("exodus_mint_pool_v1"), mintPool, true);
    }

    bool HasElysiumMintPoolV1()
    {
        return Exists(std::string("exodus_mint_pool_v1"));
    }

    template<class Key, class MintID>
    bool ReadElysiumMintIdV1(const Key& k, MintID &id)
    {
        return Read(std::make_pair(std::string("exodus_mint_id_v1"), k), id);
    }

    template<class Key, class MintID>
    bool WriteElysiumMintIdV1(const Key& k, const MintID &id)
    {
        return Write(std::make_pair(std::string("exodus_mint_id_v1"), k), id);
    }

    template<class Key>
    bool HasElysiumMintIdV1(const Key& k)
    {
        return Exists(std::make_pair(std::string("exodus_mint_id_v1"), k));
    }

    template<class Key>
    bool EraseElysiumMintIdV1(const Key& k)
    {
        return Erase(std::make_pair(std::string("exodus_mint_id_v1"), k));
    }

    template<class K, class V>
    bool ReadElysiumMintV1(const K& k, V& v)
    {
        return Read(std::make_pair(std::string("exodus_mint_v1"), k), v);
    }

    template<class K>
    bool HasElysiumMintV1(const K& k)
    {
        return Exists(std::make_pair(std::string("exodus_mint_v1"), k));
    }

    template<class K, class V>
    bool WriteElysiumMintV1(const K &k, const V &v)
    {
        return Write(std::make_pair(std::string("exodus_mint_v1"), k), v, true);
    }

    template<class K>
    bool EraseElysiumMintV1(const K& k)
    {
        return Erase(std::make_pair(std::string("exodus_mint_v1"), k));
    }

    template<typename K, typename V, typename InsertF>
    void ListElysiumMintsV1(InsertF insertF)
    {
        ListEntries<K, V, InsertF>(std::string("exodus_mint_v1"), insertF);
    }

    template<class MintPool>
    bool ReadElysiumLelantusMintPool(MintPool &mintPool)
    {
        return Read(std::string("elysium_lelantusmint_pool"), mintPool);
    }

    template<class MintPool>
    bool WriteElysiumLelantusMintPool(MintPool const &mintPool)
    {
        return Write(std::string("elysium_lelantusmint_pool"), mintPool, true);
    }

    bool HasElysiumLelantusMintPool()
    {
        return Exists(std::string("elysium_lelantusmint_pool"));
    }

    template<class Key, class MintID>
    bool ReadElysiumLelantusMintId(const Key& k, MintID &id)
    {
        return Read(std::make_pair(std::string("elysium_lelantusmint_id"), k), id);
    }

    template<class Key, class MintID>
    bool WriteElysiumLelantusMintId(const Key& k, const MintID &id)
    {
        return Write(std::make_pair(std::string("elysium_lelantusmint_id"), k), id);
    }

    template<class Key>
    bool HasElysiumLelantusMintId(const Key& k)
    {
        return Exists(std::make_pair(std::string("elysium_lelantusmint_id"), k));
    }

    template<class Key>
    bool EraseElysiumLelantusMintId(const Key& k)
    {
        return Erase(std::make_pair(std::string("elysium_lelantusmint_id"), k));
    }

    template<class K, class V>
    bool ReadElysiumLelantusMint(const K& k, V& v)
    {
        return Read(std::make_pair(std::string("elysium_lelantusmintmint"), k), v);
    }

    template<class K>
    bool HasElysiumLelantusMint(const K& k)
    {
        return Exists(std::make_pair(std::string("elysium_lelantusmintmint"), k));
    }

    template<class K, class V>
    bool WriteElysiumLelantusMint(const K &k, const V &v)
    {
        return Write(std::make_pair(std::string("elysium_lelantusmintmint"), k), v, true);
    }

    template<class K>
    bool EraseElysiumLelantusMint(const K& k)
    {
        return Erase(std::make_pair(std::string("elysium_lelantusmintmint"), k));
    }

    template<typename K, typename V, typename InsertF>
    void ListElysiumLelantusMints(InsertF insertF)
    {
        ListEntries<K, V, InsertF>(std::string("elysium_lelantusmintmint"), insertF);
    }

#endif

    //bip47 data
    bool WriteBip47Account(bip47::CAccountReceiver const & account);
    bool WriteBip47Account(bip47::CAccountSender const & account);
    void LoadBip47Accounts(bip47::CWallet & wallet);
private:
    CWalletDB(const CWalletDB&);
    void operator=(const CWalletDB&);

    template<typename K, typename V, typename InsertF>
    void ListEntries(std::string const &prefix, InsertF insertF)
    {
        auto cursor = GetCursor();
        if (!cursor) {
            throw std::runtime_error(std::string(__func__) + " : cannot create DB cursor");
        }

        bool setRange = true;
        while (true) {

            // Read next record
            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
            if (setRange) {
                ssKey << std::make_pair(prefix, K());
            }

            CDataStream ssValue(SER_DISK, CLIENT_VERSION);
            int ret = ReadAtCursor(cursor, ssKey, ssValue, setRange);

            setRange = false;
            if (ret == DB_NOTFOUND) {
                break;
            } else if (ret != 0) {
                cursor->close();
                throw std::runtime_error(std::string(__func__)+" : error scanning DB");
            }

            // Unserialize
            std::string itemType;
            ssKey >> itemType;
            if (itemType != prefix) {
                break;
            }

            K key;
            ssKey >> key;

            V value;
            ssValue >> value;

            insertF(key, value);
        }

        cursor->close();
    }
};

void ThreadFlushWalletDB();
bool AutoBackupWallet (CWallet* wallet, std::string strWalletFile, std::string& strBackupWarning, std::string& strBackupError);

#endif // BITCOIN_WALLET_WALLETDB_H
