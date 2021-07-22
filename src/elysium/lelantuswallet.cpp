// Copyright (c) 2020 - 2021 The Firo Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ecdsa_context.h"
#include "lelantusdb.h"
#include "lelantusutils.h"
#include "lelantuswallet.h"
//#include "walletmodels.h"

#include "../liblelantus/coin.h"
#include "../uint256.h"
#include "../validation.h"

#include "../crypto/hmac_sha256.h"
#include "../crypto/hmac_sha512.h"

#include "../wallet/wallet.h"
#include "../wallet/walletdb.h"
#include "../wallet/walletexcept.h"

#include <boost/optional.hpp>

#include <iterator>
#include <stdexcept>
#include <utility>
#include <vector>

namespace elysium {

LelantusWallet::MintPoolEntry::MintPoolEntry()
{
}

LelantusWallet::MintPoolEntry::MintPoolEntry(MintEntryId const &id, CKeyID const &seedId, uint32_t index)
    : id(id), seedId(seedId), index(index)
{
}

bool LelantusWallet::MintPoolEntry::operator==(MintPoolEntry const &another) const
{
    return id == another.id &&
        seedId == another.seedId &&
        index == another.index;
}

bool LelantusWallet::MintPoolEntry::operator!=(MintPoolEntry const &another) const
{
    return !(*this == another);
}

LelantusWallet::MintReservation::MintReservation(
    LelantusWallet *_wallet, MintEntryId const &_id, lelantus::PrivateCoin const &_coin, LelantusMint const &_mint) :
    id(_id),
    coin(_coin),
    wallet(_wallet),
    mint(_mint),
    mintpoolEntry(wallet->ReserveMint(_id)),
    commited(false)
{
    if (mint.amount > INT64_MAX) {
        throw std::runtime_error("mint amount would violate consensus limits");
    }
}

LelantusWallet::MintReservation::~MintReservation()
{
    if (!commited) {
        wallet->RollbackMint(id, mintpoolEntry);
    }
}

void LelantusWallet::MintReservation::Commit()
{
    if (commited) {
        throw std::runtime_error("The mint is already be commited.");
    }

    wallet->WriteMint(id, mint);
    commited = true;
}

LelantusWallet::LelantusWallet() : LelantusWallet(new Database)
{
}

LelantusWallet::LelantusWallet(Database *database)
    : database(database), walletFile(pwalletMain->strWalletFile), loaded(false), context(ECDSAContext::CreateSignContext())
{
}

void LelantusWallet::ReloadMasterKey()
{
    LOCK(pwalletMain->cs_wallet);

    if (pwalletMain->IsLocked()) {
        throw std::runtime_error("Unable to reload master key because wallet is locked");
    }

    masterId = pwalletMain->GetHDChain().masterKeyID;

    if (masterId.IsNull()) {
        throw std::runtime_error("Master id is null");
    }

    // Load mint pool from DB
    LoadMintPool();

    // Clean up any mint entries that aren't corresponded to current masterId
    RemoveInvalidMintPoolEntries();

    // Refill mint pool
    FillMintPool();

    loaded = true;
}

void LelantusWallet::EnsureMasterKeyIsLoaded()
{
    if (!loaded) {
        ReloadMasterKey();
    }
}

uint32_t LelantusWallet::GenerateNewSeed(CKeyID &seedId, uint512 &seed)
{
    LOCK(pwalletMain->cs_wallet);
    seedId = pwalletMain->GenerateNewKey(BIP44ChangeIndex()).GetID();
    return GenerateSeed(seedId, seed);
}

uint32_t LelantusWallet::GenerateSeed(CKeyID const &seedId, uint512 &seed)
{
    LOCK(pwalletMain->cs_wallet);
    CKey key;
    if (!pwalletMain->GetKey(seedId, key)) {
        throw std::runtime_error(
            "Unable to retrieve generated key for mint seed. Is the wallet locked?");
    }

    // HMAC-SHA512(key, count)
    // `count` is LE unsigned 32 bits integer
    std::array<unsigned char, CSHA512::OUTPUT_SIZE> result;
    uint32_t change;
    auto seedIndex = GetSeedIndex(seedId, change);

    if (change != BIP44ChangeIndex()) {
        throw std::invalid_argument("BIP44 Change of seed id is invalid");
    }

    CHMAC_SHA512(key.begin(), key.size()).
        Write(reinterpret_cast<const unsigned char*>(&seedIndex), sizeof(seedIndex)).
        Finalize(result.data());

    seed = uint512(result);

    return seedIndex;
}

namespace {

uint32_t GetBIP44AddressIndex(std::string const &path, uint32_t &change)
{
    uint32_t index;
    if (sscanf(path.data(), "m/44'/%*u'/%*u'/%u/%u", &change, &index) != 2) {
        throw std::runtime_error("Fail to match BIP44 path");
    }

    return index;
}

}

uint32_t LelantusWallet::GetSeedIndex(CKeyID const &seedId, uint32_t &change)
{
    LOCK(pwalletMain->cs_wallet);
    auto it = pwalletMain->mapKeyMetadata.find(seedId);
    if (it == pwalletMain->mapKeyMetadata.end()) {
        throw std::runtime_error("key not found");
    }

    // parse last index
    try {
        return GetBIP44AddressIndex(it->second.hdKeypath, change);
    } catch (std::runtime_error const &e) {
        LogPrintf("%s : fail to get child from, %s\n", __func__, e.what());
        throw;
    }
}

bool LelantusWallet::GetPublicKey(ECDSAPrivateKey const &priv, secp256k1_pubkey &out)
{
    return 1 == secp256k1_ec_pubkey_create(
        context.Get(),
        &out,
        priv.data());
}

secp_primitives::Scalar LelantusWallet::GenerateSerial(secp256k1_pubkey const &pubkey)
{
    std::array<uint8_t, 33> compressedPub;

    size_t outSize = compressedPub.size();
    secp256k1_ec_pubkey_serialize(
        context.Get(),
        compressedPub.data(),
        &outSize,
        &pubkey,
        SECP256K1_EC_COMPRESSED);

    if (outSize != 33) {
        throw std::runtime_error("Compressed public key size is invalid.");
    }

    std::array<uint8_t, CSHA256::OUTPUT_SIZE> hash;
    CSHA256().Write(compressedPub.data(), compressedPub.size()).Finalize(hash.data());

    secp_primitives::Scalar serial;
    serial.memberFromSeed(hash.data());

    return serial;
}

uint32_t LelantusWallet::BIP44ChangeIndex() const
{
    return BIP44_ELYSIUM_LELANTUSMINT_INDEX;
}

LelantusPrivateKey LelantusWallet::GeneratePrivateKey(uint512 const &seed)
{
    auto params = lelantus::Params::get_elysium();

    ECDSAPrivateKey signatureKey;

    // last 32 bytes as seed of randomness
    std::array<uint8_t, 32> randomnessSeed;
    std::copy(seed.begin() + 32, seed.end(), randomnessSeed.begin());
    secp_primitives::Scalar randomness;
    randomness.memberFromSeed(randomnessSeed.data());

    // first 32 bytes as seed of ecdsa key and serial
    std::copy(seed.begin(), seed.begin() + 32, signatureKey.begin());

    // hash until get valid private key
    secp256k1_pubkey pubkey;
    do {
        CSHA256().Write(signatureKey.data(), signatureKey.size()).Finalize(signatureKey.data());
    } while (!GetPublicKey(signatureKey, pubkey));

    auto serial = lelantus::PrivateCoin::serialNumberFromSerializedPublicKey(
        OpenSSLContext::get_context(), &pubkey);

    return LelantusPrivateKey(params, serial, randomness, signatureKey);
}

// Mint Updating
void LelantusWallet::WriteMint(MintEntryId const &id, LelantusMint const &mint)
{
    if (!database->WriteMint(id, mint)) {
        throw std::runtime_error("fail to write hdmint");
    }

    if (!database->WriteMintId(mint.serialId, id)) {
        throw std::runtime_error("fail to record id");
    }

    RemoveFromMintPool(id);
    FillMintPool();
}

LelantusWallet::MintPoolEntry LelantusWallet::ReserveMint(MintEntryId const &id)
{
    LOCK(pwalletMain->cs_wallet);

    auto &mintIdIndex = mintPool.get<1>();
    auto it = mintIdIndex.find(id);

    if (it == mintIdIndex.end()) {
        throw std::runtime_error("Mint is not in pool");
    }

    MintPoolEntry entry = *it;

    mintIdIndex.erase(it);
    FillMintPool();
    SaveMintPool();

    return entry;
}

void LelantusWallet::RollbackMint(MintEntryId const &id, MintPoolEntry const &entry)
{
    if (HasMint(id)) {
        throw std::runtime_error("Mint is not rollbackable");
    }

    mintPool.insert(entry);
    SaveMintPool();
}

LelantusPrivateKey LelantusWallet::GeneratePrivateKey(CKeyID const &seedId)
{
    uint512 seed;

    GenerateSeed(seedId, seed);
    return GeneratePrivateKey(seed);
}

LelantusWallet::MintReservation LelantusWallet::GenerateMint(PropertyId property, LelantusAmount amount, boost::optional<CKeyID> seedId)
{
    LOCK(pwalletMain->cs_wallet);

    // If not specify seed to use that mean caller want to generate a new mint.
    if (!seedId) {
        if (pwalletMain->IsLocked()) {
            throw WalletLocked();
        }

        if (mintPool.empty()) {

            // Try to recover mint pools
            ReloadMasterKey();

            if (mintPool.empty()) {
                throw std::runtime_error("Mint pool is empty");
            }
        }

        seedId = mintPool.begin()->seedId;
    }

    // Generate private & public key.
    auto priv = GeneratePrivateKey(seedId.get());
    auto id = MintEntryId(priv.serial, priv.randomness, seedId.get());

    // Create a new mint.
    auto serialId = GetSerialId(priv.serial);
    LelantusMint mint(property, amount, seedId.get(), serialId);

    return {this, id, priv.GetPrivateCoin(amount), mint};
}

LelantusMint LelantusWallet::UpdateMint(MintEntryId const &id, std::function<void(LelantusMint &)> const &modifier)
{
    auto m = GetMint(id);
    modifier(m);

    if (!database->WriteMint(id, m)) {
        throw std::runtime_error("fail to update mint");
    }

    return m;
}

void LelantusWallet::ClearMintsChainState()
{
    CWalletDB db(walletFile);
    std::vector<std::pair<MintEntryId, LelantusMint>> mints;

    db.TxnBegin();

    ListMints(std::back_inserter(mints), &db);

    for (auto &m : mints) {
        m.second.chainState = LelantusMintChainState();
        m.second.spendTx = uint256();

        if (!database->WriteMint(m.first, m.second, &db)) {
            throw std::runtime_error("Failed to write " + walletFile);
        }
    }

    db.TxnCommit();
}

bool LelantusWallet::SyncWithChain()
{
    EnsureMasterKeyIsLoaded();
    EnsureWalletIsUnlocked(pwalletMain);

    bool keepFinding = true;

    while (keepFinding) {
        keepFinding = false;

        std::vector<MintEntryId> ids;
        for (auto const &entry: mintPool) {
            ids.push_back(entry.id);
        }
        for (MintEntryId id: ids) {
            // SyncWithChain will remove the mint from mintPool if it is found.
            if (!SyncWithChain(id)) {
                continue;
            }

            // Perform a sanity check to make sure the mint is removed. This should never throw.
            auto &index = mintPool.get<1>();
            if (index.find(id) != index.end()) {
                throw std::runtime_error("Failed to remove recovered mint from mintpool");
            }

            keepFinding = true;
        }

        if (keepFinding) {
            FillMintPool();
        }
    }

    std::vector<MintEntryId> idsToUpdate;
    ListMints(boost::make_function_output_iterator([&] (const std::pair<MintEntryId, LelantusMint>& m) {
        if (m.second.IsSpent() || m.second.IsOnChain()) {
            return;
        }

        idsToUpdate.push_back(m.first);
    }));

    for (auto const &id : idsToUpdate) {
        SyncWithChain(id);
    }

    // Update spent status of our mints.
    std::vector<std::pair<MintEntryId, LelantusMint>> mints;
    ListMints(back_inserter(mints));
    for (std::pair<MintEntryId, LelantusMint> m: mints) {
        if (m.second.IsSpent()) continue;

        uint512 seed;
        GenerateSeed(m.second.seedId, seed);
        LelantusPrivateKey privKey = GeneratePrivateKey(seed);

        uint256 spendTx;
        if (!lelantusDb->HasSerial(m.second.property, privKey.serial, spendTx)) continue;

        m.second.spendTx = spendTx;
        WriteMint(m.first, m.second);
    }

    return true;
}

bool LelantusWallet::SyncWithChain(MintEntryId const &id)
{
    EnsureWalletIsUnlocked(pwalletMain);

    PropertyId property;

    lelantus::PublicCoin publicKey;
    LelantusIndex index;
    LelantusGroup group;
    int block;
    LelantusAmount amount;
    std::vector<unsigned char> additional;

    if (!lelantusDb->HasMint(id, property, publicKey, index, group, block, amount, additional)) {
        return false;
    }

    if (!amount) {
        EncryptedValue enc;
        if (additional.size() != sizeof(enc)) {
            LogPrintf("%s : Addition data size is not correct\n", __func__);
            return false;
        }

        std::copy(additional.begin(), additional.end(), &enc[0]);
        if (!DecryptMintAmount(enc, publicKey.getValue(), amount)) {
            LogPrintf("%s : Fail to decrypted\n", __func__);
            return false;
        }
    }

    LelantusMintChainState state(block, group, index);
    if (HasMint(id)) {
        UpdateMintChainstate(id, state);
    } else {
        if (!TryRecoverMint(id, state, property, amount)) {
            LogPrintf("%s : Fail to recover mint\n", __func__);
            return false;
        }
    }

    return true;
}

bool LelantusWallet::TryRecoverMint(
    MintEntryId const &id,
    LelantusMintChainState const &chainState,
    uint256 const &spendTx,
    PropertyId property,
    CAmount amount)
{
    LOCK(pwalletMain->cs_wallet);

    MintPoolEntry entry;
    if (!GetMintPoolEntry(id, entry)) {
        return false;
    }

    // Regenerate the mint
    auto const &seedId = entry.seedId;

    uint512 seed;
    GenerateSeed(seedId, seed);

    auto privKey = GeneratePrivateKey(seed);

    auto serialId = GetSerialId(privKey.serial);

    // Create mint object
    LelantusMint mint(
        property,
        amount,
        seedId,
        serialId);
    mint.chainState = chainState;
    mint.spendTx = spendTx;

    WriteMint(id, mint);

    return true;
}

bool LelantusWallet::TryRecoverMint(
    MintEntryId const &id,
    LelantusMintChainState const &chainState,
    PropertyId property,
    CAmount amount)
{
    // update tx
    uint256 spendTx;
    MintPoolEntry entry;
    if (GetMintPoolEntry(id, entry)) {
        auto priv = GeneratePrivateKey(entry.seedId);
        if (!lelantusDb->HasSerial(property, priv.serial, spendTx)) {
            spendTx.SetNull();
        }
    } else {
        return false;
    }

    return TryRecoverMint(id, chainState, spendTx, property, amount);
}

void LelantusWallet::UpdateMintCreatedTx(MintEntryId const &id, const uint256& tx)
{
    UpdateMint(id, [&](LelantusMint& m) {
        m.createdTx = tx;
    });
}

void LelantusWallet::UpdateMintChainstate(MintEntryId const &id, LelantusMintChainState const &state)
{
    UpdateMint(id, [&](LelantusMint &m) {
        m.chainState = state;
    });
}

void LelantusWallet::UpdateMintSpendTx(MintEntryId const &id, uint256 const &tx)
{
    UpdateMint(id, [&](LelantusMint &m) {
        m.spendTx = tx;
    });
}

// Mint querying
bool LelantusWallet::HasMint(MintEntryId const &id) const
{
    return database->HasMint(id);
}

bool LelantusWallet::HasMint(secp_primitives::Scalar const &serial) const
{
    auto id = GetSerialId(serial);
    return database->HasMintId(id);
}

LelantusMint LelantusWallet::GetMint(MintEntryId const &id) const
{
    LelantusMint m;
    if (!database->ReadMint(id, m)) {
        throw std::runtime_error("fail to read hdmint");
    }

    return m;
}

LelantusMint LelantusWallet::GetMint(secp_primitives::Scalar const &serial) const
{
    return GetMint(GetMintId(serial));
}

MintEntryId LelantusWallet::GetMintId(secp_primitives::Scalar const &serial) const
{
    MintEntryId id;
    auto serialHash = GetSerialId(serial);
    if (!database->ReadMintId(serialHash, id)) {
        throw std::runtime_error("fail to read id");
    }

    return id;
}

// MintPool state
void LelantusWallet::RemoveInvalidMintPoolEntries() // Remove MintPool entry that isn't belong to current masterId.
{
    LOCK(pwalletMain->cs_wallet);

    bool updated = false;
    for (auto it = mintPool.begin(); it != mintPool.end(); it++) {

        auto metaIt = pwalletMain->mapKeyMetadata.find(it->seedId);
        if (metaIt == pwalletMain->mapKeyMetadata.end() ||
            metaIt->second.hdMasterKeyID != masterId) {

            updated = true;
            mintPool.erase(it);
        }
    }

    if (updated) {
        SaveMintPool();
    }
}

void LelantusWallet::DeleteUnconfirmedMint(MintEntryId const &id)
{
    LelantusMint mint;
    if (!database->ReadMint(id, mint)) {
        throw std::runtime_error("no mint data in wallet");
    }

    if (mint.IsOnChain()) {
        throw std::invalid_argument("try to delete onchain mint");
    }

    auto priv = GeneratePrivateKey(mint.seedId);

    uint32_t change;
    auto index = GetSeedIndex(mint.seedId, change);

    if (change != BIP44ChangeIndex()) {
        throw std::invalid_argument("Try to delete invalid seed id mint");
    }

    mintPool.insert(MintPoolEntry(id, mint.seedId, index));
    SaveMintPool();

    if (!database->EraseMint(id)) {
        throw std::runtime_error("fail to erase mint from wallet");
    }
}

bool LelantusWallet::IsMintInPool(MintEntryId const &id)
{
    LOCK(pwalletMain->cs_wallet);
    return mintPool.get<1>().count(id);
}

bool LelantusWallet::GetMintPoolEntry(MintEntryId const &id, MintPoolEntry &entry)
{
    LOCK(pwalletMain->cs_wallet);

    auto &publicKeyIndex = mintPool.get<1>();
    auto it = publicKeyIndex.find(id);

    if (it == publicKeyIndex.end()) {
        return false;
    }

    entry = *it;
    return true;
}

// Generate coins to mint pool until amount of coins in mint pool touch the expected amount.
size_t LelantusWallet::FillMintPool()
{
    LOCK(pwalletMain->cs_wallet);

    size_t generatedCoins = 0;
    while (mintPool.size() < MINTPOOL_CAPACITY) {

        CKeyID seedId;
        uint512 seed;

        auto index = GenerateNewSeed(seedId, seed);
        auto priv = GeneratePrivateKey(seed);

        MintEntryId id(priv.serial, priv.randomness, seedId);
        mintPool.insert(MintPoolEntry(id, seedId, index));

        generatedCoins++;
    }

    if (generatedCoins)  {
        SaveMintPool();
    }

    return generatedCoins;
}

void LelantusWallet::LoadMintPool()
{
    LOCK(pwalletMain->cs_wallet);

    mintPool.clear();

    std::vector<MintPoolEntry> mintPoolData;
    if (database->ReadMintPool(mintPoolData)) {
        for (auto &entry : mintPoolData) {
            mintPool.insert(std::move(entry));
        }
    }

    LogPrintf("%s : load mint pool size %d\n", __func__, mintPool.size());
}

void LelantusWallet::SaveMintPool()
{
    LOCK(pwalletMain->cs_wallet);

    std::vector<MintPoolEntry> mintPoolData;
    for (auto const &entry : mintPool) {
        mintPoolData.push_back(entry);
    }

    if (!database->WriteMintPool(mintPoolData)) {
        throw std::runtime_error("fail to save mint pool to DB");
    }
}

bool LelantusWallet::RemoveFromMintPool(MintEntryId const &id)
{
    LOCK(pwalletMain->cs_wallet);

    auto &mintIdIndex = mintPool.get<1>();
    auto it = mintIdIndex.find(id);

    if (it != mintIdIndex.end()) {

        mintIdIndex.erase(it);
        SaveMintPool();
        return true;
    }

    // mint is not in the pool
    return false;
}

CAmount LelantusWallet::GetCoinsToJoinSplit(PropertyId property, LelantusAmount required, std::vector<SpendableCoin> &coins, LelantusAmount &change, CWalletDB *db)
{
    coins.clear();

    std::vector<std::pair<MintEntryId, LelantusMint>> mints;
    ListMints(boost::make_function_output_iterator([&] (const std::pair<MintEntryId, LelantusMint>& m) {
        if (m.second.IsSpent() || !m.second.IsOnChain()) {
            return;
        }

        if (property && m.second.property != property) {
            return;
        }

        mints.push_back(m);
    }));

    std::sort(mints.begin(), mints.end(),
        [](std::pair<elysium::MintEntryId, elysium::LelantusMint> const &a, std::pair<elysium::MintEntryId, elysium::LelantusMint> const &b) -> bool {
            if (a.second.amount != b.second.amount) {
                return a.second.amount > b.second.amount;
            }
            return a.second.chainState.block < b.second.chainState.block;
        });

    LelantusAmount amount = 0;
    for (auto const &m : mints) {
        if (amount >= required) {
            break;
        }

        amount += m.second.amount;

        auto privkey = GeneratePrivateKey(m.second.seedId);
        coins.emplace_back(privkey, m.second.amount, m.first);
    }

    if (amount < required) {
        throw InsufficientFunds();
    }

    change = amount - required;

    return amount;
}

lelantus::JoinSplit LelantusWallet::CreateJoinSplit(
    PropertyId property,
    CAmount amountToSpend,
    uint256 const &metadata,
    std::vector<SpendableCoin> &spendables,
    boost::optional<LelantusWallet::MintReservation> &changeMint,
    LelantusAmount &change)
{
    if (amountToSpend < 0) {
        throw std::invalid_argument("Amount to spend could not be negative");
    }

    spendables.clear();
    if (GetCoinsToJoinSplit(property, amountToSpend, spendables, change) < amountToSpend) {
        throw InsufficientFunds();
    }

    std::map<uint32_t, std::vector<lelantus::PublicCoin>> anonss;
    std::vector<std::pair<lelantus::PrivateCoin, uint32_t>> coins;
    coins.reserve(spendables.size());

    for (auto const &s : spendables) {
        auto priv = s.privateKey.GetPrivateCoin(s.amount);
        auto group = lelantusDb->GetGroup(property, priv.getPublicCoin());

        anonss[group] = {};

        coins.emplace_back(priv, group);
    }

    uint256 highestBlock;
    int highestBlockHeight = 0;

    std::map<uint32_t, uint256> blockHashes;
    for (auto &anons : anonss) {
        int blockHeight = INT_MAX;
        anons.second = lelantusDb->GetAnonymityGroup(property, anons.first, SIZE_MAX, blockHeight);
        auto block = chainActive[blockHeight];
        if (!block) throw std::runtime_error("Failed to create joinsplit due to invalid anonymity group input");
        blockHashes[anons.first] = block->GetBlockHash();

        if (block->nHeight > highestBlockHeight) {
            highestBlockHeight = block->nHeight;
            highestBlock = block->GetBlockHash();
        }
    }

    // It is safe to use the hashes of blocks instead of the hashes of anonymity sets because blocks hashes are
    // necessarily dependent on anonymity set hashes.
    std::vector<std::vector<unsigned char>> anonymitySetHashes;
    std::vector<unsigned char> anonymitySetHash(highestBlock.begin(), highestBlock.end());
    anonymitySetHashes.push_back(anonymitySetHash);

    // reserve change
    std::vector<lelantus::PrivateCoin> coinOuts;
    if (change) {
        changeMint = GenerateMint(property, change);
    }

    std::vector<lelantus::PublicCoin> pubCoinOuts;
    if (changeMint.get_ptr() != nullptr) {
        coinOuts = {changeMint->coin};
        pubCoinOuts = {changeMint->coin.getPublicCoin()};
    }

    // It is safe to use blockHash instead of hashes of the anonymity sets because any change in the latter will
    // necessarily result in a change in the former.
    auto js = elysium::CreateJoinSplit(coins, anonss, anonymitySetHashes, amountToSpend, coinOuts, blockHashes, metadata);

    if (!js.VerifyElysium(anonss, anonymitySetHashes, pubCoinOuts, amountToSpend, metadata)) {
        throw std::runtime_error("Fail to verify created join/split object");
    }

    return js;
}

LelantusWallet::Database::Connection::Connection(CWalletDB *db)
{
    if (db) {
        this->db.db = db;
        local = false;
    } else {
        new (this->db.local) CWalletDB(pwalletMain->strWalletFile);
        local = true;
    }
}

LelantusWallet::Database::Connection::~Connection()
{
    if (local) {
        reinterpret_cast<CWalletDB*>(db.local)->~CWalletDB();
    }
}

CWalletDB* LelantusWallet::Database::Connection::operator->() noexcept
{
    return local ? reinterpret_cast<CWalletDB*>(db.local) : db.db;
}

LelantusWallet::Database::Database()
{
}

bool LelantusWallet::Database::WriteMint(MintEntryId const &id, LelantusMint const &mint, CWalletDB *db)
{
    auto local = Connection(db);
    return local->WriteElysiumLelantusMint(id, mint);
}

bool LelantusWallet::Database::ReadMint(MintEntryId const &id, LelantusMint &mint, CWalletDB *db) const
{
    auto local = Connection(db);
    return local->ReadElysiumLelantusMint(id, mint);
}

bool LelantusWallet::Database::EraseMint(MintEntryId const &id, CWalletDB *db)
{
    auto local = Connection(db);
    return local->EraseElysiumLelantusMint(id);
}

bool LelantusWallet::Database::HasMint(MintEntryId const &id, CWalletDB *db) const
{
    auto local = Connection(db);
    return local->HasElysiumLelantusMint(id);
}

bool LelantusWallet::Database::WriteMintId(uint160 const &hash, MintEntryId const &mintId, CWalletDB *db)
{
    auto local = Connection(db);
    return local->WriteElysiumLelantusMintId(hash, mintId);
}

bool LelantusWallet::Database::ReadMintId(uint160 const &hash, MintEntryId &mintId, CWalletDB *db) const
{
    auto local = Connection(db);
    return local->ReadElysiumLelantusMintId(hash, mintId);
}

bool LelantusWallet::Database::EraseMintId(uint160 const &hash, CWalletDB *db)
{
    auto local = Connection(db);
    return local->EraseElysiumLelantusMintId(hash);
}

bool LelantusWallet::Database::HasMintId(uint160 const &hash, CWalletDB *db) const
{
    auto local = Connection(db);
    return local->HasElysiumLelantusMintId(hash);
}

bool LelantusWallet::Database::WriteMintPool(std::vector<MintPoolEntry> const &mints, CWalletDB *db)
{
    auto local = Connection(db);
    return local->WriteElysiumLelantusMintPool(mints);
}

bool LelantusWallet::Database::ReadMintPool(std::vector<MintPoolEntry> &mints, CWalletDB *db)
{
    auto local = Connection(db);
    return local->ReadElysiumLelantusMintPool(mints);
}

void LelantusWallet::Database::ListMints(std::function<void(MintEntryId&, LelantusMint&)> const &inserter, CWalletDB *db)
{
    auto local = Connection(db);
    local->ListElysiumLelantusMints<MintEntryId, LelantusMint>(inserter);
}

} // namespace elysium
