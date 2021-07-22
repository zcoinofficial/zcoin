// Copyright (c) 2020 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FIRO_ELYSIUM_LELANTUSWALLET_H
#define FIRO_ELYSIUM_LELANTUSWALLET_H

#include "ecdsa_context.h"
#include "property.h"
#include "lelantusprimitives.h"
#include "lelantuswalletmodels.h"

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/optional.hpp>

#include "../crypto/hmac_sha256.h"
#include "../crypto/hmac_sha512.h"
#include "../uint256.h"
#include "../wallet/wallet.h"
#include "../wallet/walletdb.h"
#include "../wallet/walletexcept.h"

#include <memory>
#include <utility>

namespace elysium {

class LelantusWallet
{
public:
    struct MintPoolEntry {
        MintEntryId id;
        CKeyID seedId;
        LelantusIndex index;

        MintPoolEntry();
        MintPoolEntry(MintEntryId const &id, CKeyID const &seedId, uint32_t index);

        bool operator==(MintPoolEntry const &another) const;
        bool operator!=(MintPoolEntry const &another) const;

        ADD_SERIALIZE_METHODS;

        template<typename Stream, typename Operation>
        void SerializationOp(Stream& s, Operation ser_action)
        {
            READWRITE(id);
            READWRITE(seedId);
            READWRITE(index);
        }
    };

    struct MintReservation {
        MintEntryId id;
        lelantus::PrivateCoin coin;

        MintReservation(LelantusWallet *_wallet, MintEntryId const &_id, lelantus::PrivateCoin const &_coin, LelantusMint const &_mint);
        ~MintReservation();
        void Commit();

    public:
        MintPoolEntry GetMintPoolEntry() const { return mintpoolEntry; }

    private:
        LelantusWallet *wallet;
        LelantusMint mint;
        MintPoolEntry mintpoolEntry;

        bool commited;
    };

    typedef boost::multi_index_container<
        MintPoolEntry,
        boost::multi_index::indexed_by<
            // Sequence
            boost::multi_index::ordered_unique<
                boost::multi_index::member<MintPoolEntry, LelantusIndex, &MintPoolEntry::index>
            >,
            // Mint entry id index
            boost::multi_index::hashed_unique<
                boost::multi_index::member<MintPoolEntry, MintEntryId, &MintPoolEntry::id>,
                std::hash<MintEntryId>
            >
        >
    > MintPool;

protected:
    class Database {
    public:
        Database();

    public:
        bool WriteMint(MintEntryId const &id, LelantusMint const &mint, CWalletDB *db = nullptr);
        bool ReadMint(MintEntryId const &id, LelantusMint &mint, CWalletDB *db = nullptr) const;
        bool EraseMint(MintEntryId const &id, CWalletDB *db = nullptr);
        bool HasMint(MintEntryId const &id, CWalletDB *db = nullptr) const;

        bool WriteMintId(uint160 const &hash, MintEntryId const &mintId, CWalletDB *db = nullptr);
        bool ReadMintId(uint160 const &hash, MintEntryId &mintId, CWalletDB *db = nullptr) const;
        bool EraseMintId(uint160 const &hash, CWalletDB *db = nullptr);
        bool HasMintId(uint160 const &hash, CWalletDB *db = nullptr) const;

        bool WriteMintPool(std::vector<MintPoolEntry> const &mints, CWalletDB *db = nullptr);
        bool ReadMintPool(std::vector<MintPoolEntry> &mints, CWalletDB *db = nullptr);

        void ListMints(std::function<void(MintEntryId&, LelantusMint&)> const&, CWalletDB *db = nullptr) ;

    protected:
        // Helper
        class Connection
        {
        public:
            Connection(CWalletDB *db);
            ~Connection();

        public:
            CWalletDB* operator->() noexcept;

        private:
            bool local;
            union {
                CWalletDB *db;
                unsigned char local[sizeof(CWalletDB)];
            } db;
        };
    };

public:
    std::unique_ptr<Database> database;
    std::string walletFile;
    MintPool mintPool;
    uint160 masterId;
    std::atomic<bool> loaded;

    static constexpr unsigned MINTPOOL_CAPACITY = 20;

public:
    LelantusWallet();
    LelantusWallet(Database *database);

public:
    void ReloadMasterKey();

    // Generator
protected:
    uint32_t GenerateNewSeed(CKeyID &seedId, uint512 &seed);
    uint32_t GenerateSeed(CKeyID const &seedId, uint512 &seed);
    uint32_t GetSeedIndex(CKeyID const &seedId, uint32_t &change);

    void EnsureMasterKeyIsLoaded();

protected:
    bool GetPublicKey(ECDSAPrivateKey const &privateKey, secp256k1_pubkey &out);
    secp_primitives::Scalar GenerateSerial(secp256k1_pubkey const &pubkey);

    uint32_t BIP44ChangeIndex() const;
    LelantusPrivateKey GeneratePrivateKey(uint512 const &seed);

    // Mint updating
public:
    LelantusPrivateKey GeneratePrivateKey(CKeyID const &seedId);
    MintReservation GenerateMint(PropertyId property, LelantusAmount amount, boost::optional<CKeyID> seedId = boost::none);

    void ClearMintsChainState();
    bool SyncWithChain();
    bool SyncWithChain(MintEntryId const &id);

    bool TryRecoverMint(MintEntryId const &id, LelantusMintChainState const &chainState, PropertyId property, CAmount amount);
    bool TryRecoverMint(MintEntryId const &id, LelantusMintChainState const &chainState, uint256 const &spendTx, PropertyId property, CAmount amount);

private:
    LelantusMint UpdateMint(MintEntryId const &id, std::function<void(LelantusMint &)> const &modifier);

    void WriteMint(MintEntryId const &id, LelantusMint const &mint);
    MintPoolEntry ReserveMint(MintEntryId const &id);
    void RollbackMint(MintEntryId const &id, MintPoolEntry const &entry);

public:
    void UpdateMintCreatedTx(MintEntryId const &id, uint256 const &tx);
    void UpdateMintChainstate(MintEntryId const &id, LelantusMintChainState const &state);
    void UpdateMintSpendTx(MintEntryId const &id, uint256 const &tx);

    // Mint querying
public:

    bool HasMint(MintEntryId const &id) const;
    bool HasMint(secp_primitives::Scalar const &serial) const;

    LelantusMint GetMint(MintEntryId const &id) const;
    LelantusMint GetMint(secp_primitives::Scalar const &serial) const;
    MintEntryId GetMintId(secp_primitives::Scalar const &serial) const;

    template<class Output>
    Output ListMints(Output output, CWalletDB *db = nullptr)
    {
        database->ListMints([&](const MintEntryId& id, const LelantusMint &m) {
            *output++ = std::make_pair(id, m);
        }, db);

        return output;
    }

    CAmount GetCoinsToJoinSplit(PropertyId property, LelantusAmount required, std::vector<SpendableCoin> &coins, LelantusAmount &changed, CWalletDB *db = nullptr);

    lelantus::JoinSplit CreateJoinSplit(
        PropertyId property,
        CAmount amountToSpend,
        uint256 const &metadata,
        std::vector<SpendableCoin> &spendables,
        boost::optional<LelantusWallet::MintReservation> &changeMint,
        LelantusAmount &change);

    // MintPool state
public:
    void DeleteUnconfirmedMint(MintEntryId const &id);
    bool IsMintInPool(MintEntryId const &id);

    bool GetMintPoolEntry(MintEntryId const &id, MintPoolEntry &entry);

protected:
    void RemoveInvalidMintPoolEntries(); // Remove MintPool entries that aren't belong to current masterId.
    size_t FillMintPool();

    void LoadMintPool();
    void SaveMintPool();

    bool RemoveFromMintPool(MintEntryId const &id);

private:
    ECDSAContext context;
};

} // namespace elysium

#endif // FIRO_ELYSIUM_LELANTUSWALLET_H
