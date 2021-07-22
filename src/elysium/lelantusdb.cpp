// Copyright (c) 2020 The Zcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "../wallet/wallet.h"

#include "convert.h"
#include "lelantusdb.h"
#include "lelantusutils.h"

#include "ui_interface.h"

template<typename T>
T swapByteOrder(T t) {
    elysium::swapByteOrder(t);
    return t;
}

namespace elysium {

static const char DB_SERIAL                   = 's';
static const char DB_PENDING_COIN             = 'p';
static const char DB_COIN                     = 'c';
static const char DB_COIN_SEQUENCE            = 'C';
static const char DB_COIN_GROUP               = 'g';
static const char DB_COIN_ID                  = 'i';
static const char DB_UNDO                     = 'u';
static const char DB_GROUPSIZE                = 'x';

static const char UNDO_REMOVE_SERIAL          = 's';
static const char UNDO_REMOVE_COIN            = 'c';
static const char UNDO_REMOVE_COIN_SEQ        = 'S';
static const char UNDO_REMOVE_COIN_ID         = 'I';
static const char UNDO_REMOVE_GROUP           = 'g';
static const char UNDO_REVERSE_GROUP_DATA     = 'r';

namespace {

struct UndoEntry
{
    char undoType;
    int block;
    std::string data;

    UndoEntry() : undoType(0), block(0)
    {
    }

    UndoEntry(char undoType, int block, leveldb::Slice const &r) : undoType(undoType), block(block), data(r.data(), r.data() + r.size())
    {
    }

    UndoEntry(char undoType, int block, std::string const &r) : undoType(undoType), block(block), data(r)
    {
    }

    template <typename T>
    UndoEntry(char undoType, int block, T t) : undoType(undoType), block(block) {
        CDataStream ss(SER_DISK, CLIENT_VERSION);
        ss << t;
        data = ss.str();
    }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(undoType);
        READWRITE(block);
        READWRITE(data);
    }
};

template <typename ...T>
std::string MakeRaw(T ...t)
{
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << std::make_tuple(t...);

    return ss.str();
}

template <typename T>
bool ParseRaw(leveldb::Slice const &raw, T &t)
{
    CDataStream ss(raw.data(), raw.data() + raw.size(), SER_DISK, CLIENT_VERSION);
    ss >> t;

    return ss.eof();
}

template <typename T>
bool ParseRaw(std::string const &raw, T &t)
{
    CDataStream ss(raw.data(), raw.data() + raw.size(), SER_DISK, CLIENT_VERSION);
    try {
        ss >> t;
    } catch (std::iostream::failure const&) {
        return false;
    }

    return ss.eof();
}

// data models
struct CoinSequenceData {
    lelantus::PublicCoin publicCoin;
    int block;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(publicCoin);
        READWRITE(block);
    }
};
struct CoinData {
    MintEntryId id;
    LelantusAmount amount;
    std::vector<unsigned char> additionalData;
    LelantusIndex index;
    LelantusGroup group;
    int block;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(id);
        READWRITE(amount);
        READWRITE(additionalData);
        READWRITE(index);
        READWRITE(group);
        READWRITE(block);
    }
};

struct CoinGroupData {
    LelantusIndex firstSequence;
    int lastBlock;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(firstSequence);
        READWRITE(lastBlock);
    }
};

template<char Prefix, class Value, class ...Keys>
class Parser {
public:
    virtual std::string GetKey(Keys ...keys) const {
        return MakeRaw(Prefix, keys...);
    }

    virtual boost::optional<std::tuple<Keys...>> ParseKey(std::string val) const {
        std::pair<char, std::tuple<Keys...>> v;
        if (!ParseRaw(val, v)) {
            return boost::none;
        }

        if (v.first != Prefix) {
            return boost::none;
        }

        return v.second;
    }

    virtual std::string GetVal(Value value) const {
        return MakeRaw(value);
    }

    virtual boost::optional<Value> ParseVal(std::string val) const {
        Value v;
        if (!ParseRaw(val, v)) {
            return boost::none;
        }

        return v;
    }

    virtual std::pair<std::string, std::string> Get(Keys ...keys, Value value) const {
        return {GetKey(keys...), GetVal(value)};
    }
};

class SerialParser : public Parser<DB_SERIAL, uint256, PropertyId, Scalar> {};

class PendingCoinParser : public Parser<DB_PENDING_COIN,
    std::tuple<PropertyId, lelantus::PublicCoin, int>, uint64_t>
{
public:
    std::string GetKey(uint64_t seq) const override {
        seq = htobe64(seq);
        return Parser::GetKey(seq);
    }

    boost::optional<std::tuple<uint64_t>> ParseKey(std::string val) const override {
        auto v = Parser::ParseKey(val);
        if (v.get_ptr() == nullptr) {
            return v;
        }

        std::get<0>(v.get()) = be64toh(std::get<0>(v.get()));

        return v;
    }
};

class CoinParser : public Parser<DB_COIN, CoinData, PropertyId, lelantus::PublicCoin> {};

class CoinSequenceParser : public Parser<DB_COIN_SEQUENCE, CoinSequenceData, PropertyId, LelantusIndex>
{
public:
    std::string GetKey(PropertyId id, LelantusIndex index) const override {
        index = htobe64(index);
        return Parser::GetKey(id, index);
    }

    boost::optional<std::tuple<PropertyId, LelantusIndex>> ParseKey(std::string val) const override {
        auto v = Parser::ParseKey(val);
        if (v.get_ptr() == nullptr) {
            return v;
        }

        std::get<1>(v.get()) = be64toh(std::get<1>(v.get()));

        return v;
    }
};

class CoinGroupParser : public Parser<DB_COIN_GROUP, CoinGroupData, PropertyId, LelantusGroup> {};

class CoinIdParser : public Parser<DB_COIN_ID, std::tuple<char, PropertyId, lelantus::PublicCoin>, MintEntryId>
{};

// Utility struct to store undo entries
struct UndoRecorder
{
private:
    leveldb::WriteBatch &batch;
    uint64_t undoSequence;

public:
    UndoRecorder(leveldb::WriteBatch &batch, uint64_t nextUndoSequence)
        : batch(batch), undoSequence(nextUndoSequence)
    {
    }

    template <typename T>
    uint64_t Record(char undoType, int block, T t) {

        UndoEntry entry(undoType, block, t);
        CDataStream ss(SER_DISK, CLIENT_VERSION);
        ss << entry;

        batch.Put(MakeRaw(DB_UNDO, ::swapByteOrder(undoSequence)), leveldb::Slice(ss.data(), ss.size()));
        return ++undoSequence;
    }
};

} // unnamed namespace

// DB
LelantusDb::LelantusDb(const boost::filesystem::path& path, bool wipe, uint64_t groupSize, uint64_t startCoins)
    : groupSize(groupSize), startGroupSize(startCoins)
{
    auto status = Open(path, wipe);
    if (!status.ok()) {
        throw std::runtime_error("Failed to create " + path.string() + ": " + status.ToString());
    }

    auto size = ReadGroupSize();
    if (size != std::make_pair(groupSize, startCoins)) {
        if (!WriteGroupSize(groupSize, startCoins)) {
            throw std::runtime_error("Failed to write group size");
        }
    }

    auto it = NewIterator();
    it->Seek(PendingCoinParser().GetKey(0));

    /*
    if (it->Valid() && PendingCoinParser().ParseKey(it->key().ToString()) != boost::none) {
        throw std::runtime_error("Found pending coins");
    }
    */
}

bool LelantusDb::HasSerial(PropertyId id, Scalar const &serial, uint256 &spendTx)
{
    std::string data;
    auto status = pdb->Get(readoptions, SerialParser().GetKey(id, serial) , &data);
    if (!status.ok()) {
        return false;
    }

    auto tx = SerialParser().ParseVal(data);
    if (tx.get_ptr() != nullptr) {
        spendTx = tx.get();
    }

    return true;
}

bool LelantusDb::WriteSerial(
    PropertyId id,
    secp_primitives::Scalar serial,
    int block,
    uint256 const &spendTx)
{
    leveldb::WriteBatch batch;

    auto nextSequence = GetNextSequence(DB_UNDO);
    UndoRecorder undoRecorder(batch, nextSequence);

    uint256 tx;
    if (HasSerial(id, serial, tx)) {
        return false;
    }

    // write serial
    auto key = SerialParser().GetKey(id, serial);
    batch.Put(key, SerialParser().GetVal(spendTx));

    // write undo
    undoRecorder.Record(UNDO_REMOVE_SERIAL, block, key);

    return pdb->Write(syncoptions, &batch).ok();
}

std::vector<lelantus::PublicCoin> LelantusDb::GetAnonymityGroup(
    PropertyId id,
    LelantusGroup groupId,
    uint64_t count,
    int &block)
{
    LOCK(cs);

    std::vector<lelantus::PublicCoin> coins;
    CoinGroupData groupData;
    std::string rawGroupData;

    std::string strKey = CoinGroupParser().GetKey(id, groupId);
    leveldb::Slice key = strKey;
    if (!pdb->Get(readoptions, key, &rawGroupData).ok()) {
        // Groups which have no data written about them have no coins in them.
        return coins;
    }
    if (!ParseRaw(rawGroupData, groupData)) {
        throw std::runtime_error("Fail to parse first sequence in group");
    }

    auto it = NewIterator();
    it->Seek(CoinSequenceParser().GetKey(id, groupData.firstSequence));

    int outBlock = 0;

    CoinSequenceData coinSeqData;
    for (size_t i = 0;
        i != count
        && it->Valid()
        && it->key() == CoinSequenceParser().GetKey(id, groupData.firstSequence + i)
        ; it->Next(), i++) {

        ParseRaw(it->value(), coinSeqData);

        if (coinSeqData.block > block) {
            break;
        }
        outBlock = coinSeqData.block;

        coins.push_back(coinSeqData.publicCoin);
    }
    block = outBlock;

    return coins;
}

bool LelantusDb::HasMint(PropertyId propertyId, lelantus::PublicCoin const &pubKey)
{
    std::string val;
    return pdb->Get(readoptions, CoinParser().GetKey(propertyId, pubKey) , &val).ok();
}

bool LelantusDb::WriteMint(
    PropertyId propertyId,
    lelantus::PublicCoin const &pubKey,
    int block,
    MintEntryId const &id,
    LelantusAmount amount,
    std::vector<unsigned char> const &additional)
{
    leveldb::WriteBatch batch;

    auto nextUndoSeq = GetNextSequence(DB_UNDO);
    UndoRecorder undoRecorder(batch, nextUndoSeq);

    auto coinKey = CoinParser().GetKey(propertyId, pubKey);
    std::string data;
    if (pdb->Get(readoptions, coinKey, &data).ok()) {
        return false;
    }

    // add coin index
    batch.Put(coinKey, CoinParser().GetVal({
        .id = id,
        .amount = amount,
        .additionalData = additional,
        .index = UINT64_MAX
    }));

    undoRecorder.Record(UNDO_REMOVE_COIN, block, coinKey);

    // add tag index
    auto tagIndexKey = CoinIdParser().GetKey(id);
    batch.Put(tagIndexKey, coinKey);
    undoRecorder.Record(UNDO_REMOVE_COIN_ID, block, tagIndexKey);

    // add pending
    auto nextPendingSeq = GetNextSequence(DB_PENDING_COIN);
    batch.Put(PendingCoinParser().GetKey(nextPendingSeq),
        PendingCoinParser().GetVal(std::make_tuple(propertyId, pubKey, block)));

    return pdb->Write(syncoptions, &batch).ok();
}

bool LelantusDb::WriteMint(PropertyId propertyId, JoinSplitMint const &mint, int block)
{
    std::vector<unsigned char> additional;
    additional.insert(additional.end(), mint.encryptedValue, mint.encryptedValue + sizeof(mint.encryptedValue));
    return WriteMint(propertyId, mint.publicCoin, block, mint.id, 0, additional);
}

LelantusGroup LelantusDb::GetGroup(PropertyId property, lelantus::PublicCoin const &pubKey)
{
    std::string val;
    if (!pdb->Get(readoptions, CoinParser().GetKey(property, pubKey), &val).ok()) {
        throw std::invalid_argument("Mint data is not in database");
    }

    CoinData data;
    ParseRaw(val, data);

    uint64_t coinsCount;
    auto group = GetLastGroup(property, coinsCount);

    do {
        std::string val;
        if (!pdb->Get(readoptions, CoinGroupParser().GetKey(property, group), &val).ok()) {
            throw std::runtime_error("Fail to get group data");
        }
        CoinGroupData groupData;
        ParseRaw(val, groupData);

        if (data.index > groupData.firstSequence) {
            return group;
        }

    } while (group--);

    return 0;
}

LelantusGroup LelantusDb::GetGroup(PropertyId property, MintEntryId const &id)
{
    // get coin data
    std::string val;
    if (!pdb->Get(readoptions, CoinIdParser().GetKey(id), &val).ok()) {
        throw std::invalid_argument("Mint id is not in database");
    }

    std::tuple<char, PropertyId, lelantus::PublicCoin> keyData;
    ParseRaw(val, keyData);

    return GetGroup(property, std::get<2>(keyData));
}

bool LelantusDb::HasMint(MintEntryId const &id, PropertyId &property, lelantus::PublicCoin &publicKey, LelantusIndex &index, LelantusGroup &group, int &block, LelantusAmount &amount, std::vector<unsigned char> &additional)
{
    auto tagKey = CoinIdParser().GetKey(id);
    std::string val;
    auto success = pdb->Get(readoptions, tagKey, &val).ok();

    if (!success) {
        return false;
    }

    std::tuple<char, PropertyId, lelantus::PublicCoin> keyData;
    ParseRaw(val, keyData);

    property = std::get<1>(keyData);
    publicKey = std::get<2>(keyData);

    std::string raw;
    if (!pdb->Get(readoptions, val, &raw).ok()) {
        throw std::runtime_error("Fail to get coin data");
    }

    CoinData coinData;
    if (!ParseRaw(raw, coinData)) {
        throw std::runtime_error("Fail to parse coin data");
    }

    index = coinData.index;
    group = coinData.group;
    block = coinData.block;
    amount = coinData.amount;
    additional = coinData.additionalData;

    return true;
}

void LelantusDb::CommitCoins()
{
    LOCK(cs);

    leveldb::WriteBatch batch;

    auto nextUndoSeq = GetNextSequence(DB_UNDO);
    UndoRecorder undoRecorder(batch, nextUndoSeq);

    auto it = NewIterator();
    it->Seek(PendingCoinParser().GetKey(0));

    int block = -1;

    // get pendings
    std::map<PropertyId, std::vector<lelantus::PublicCoin>> entries;
    std::tuple<PropertyId, lelantus::PublicCoin, int> entry;
    leveldb::Slice key;
    for (; it->Valid() && (key = it->key()).size() > 0 && key[0] == DB_PENDING_COIN; it->Next()) {
        if (!ParseRaw(it->value(), entry)) {
            throw std::runtime_error("Fail to parse pending entry");
        }

        if (block == -1) {
            block = std::get<2>(entry);
        }

        if (block != std::get<2>(entry)) {
            throw std::runtime_error("Lelantus state is inconsistent");
        }

        entries[std::get<0>(entry)].push_back(std::get<1>(entry));

        batch.Delete(key);
    }

    // write all pendings
    for (auto const &idAndPubKeys : entries) {

        auto propertyId = idAndPubKeys.first;
        auto nextCoinSeq = GetNextSequence(DB_COIN_SEQUENCE, propertyId);

        std::vector<std::tuple<LelantusIndex, CoinData, lelantus::PublicCoin>> entries;


        uint64_t newCoins = idAndPubKeys.second.size();
        uint64_t coins = 0;
        auto lastGroup = GetLastGroup(propertyId, coins);

        if (coins + newCoins > groupSize) {
            // create new group
            auto required = newCoins > startGroupSize ? 0 : (startGroupSize - newCoins);

            // find best candidate
            auto nextCoinSeq = GetNextSequence(DB_COIN_SEQUENCE, propertyId);
            auto includedSeq = nextCoinSeq - required;

            // find first sequence in block
            auto it = NewIterator();
            it->Seek(CoinSequenceParser().GetKey(propertyId, includedSeq));

            int includedBlock = -1;
            auto firstSeq = includedSeq;
            CoinSequenceData data;
            for (; it->Valid() && it->key() == CoinSequenceParser().GetKey(propertyId, includedSeq); it->Prev(), includedSeq--) {
                if (!ParseRaw(it->value(), data)) {
                    throw std::runtime_error("Fail to parse sequence data");
                }

                includedBlock = includedBlock == -1 ? data.block : includedBlock;
                if (includedBlock != data.block) {
                    break;
                }

                firstSeq = includedSeq;
            }

            // write group
            auto groupKey = CoinGroupParser().GetKey(propertyId, ++lastGroup);
            batch.Put(groupKey, CoinGroupParser().GetVal({
                .firstSequence = firstSeq,
                .lastBlock = block
            }));

            undoRecorder.Record(UNDO_REMOVE_GROUP, block, groupKey);
        } else {
            auto groupKey = CoinGroupParser().GetKey(propertyId, lastGroup);

            std::string val;
            if (!pdb->Get(readoptions, groupKey, &val).ok()) {
                throw std::runtime_error("Fail to read group data");
            }

            auto groupData = CoinGroupParser().ParseVal(val);
            if (groupData.get_ptr() == nullptr) {
                throw std::runtime_error("Fail to parse value");
            }

            groupData->lastBlock = block;
            batch.Put(groupKey, CoinGroupParser().GetVal(groupData.get()));
            undoRecorder.Record(UNDO_REVERSE_GROUP_DATA, block, MakeRaw(groupKey, val));
        }

        // record sequence
        for (auto const &pubKey : idAndPubKeys.second) {
            auto coinSequenceKey = CoinSequenceParser().GetKey(propertyId, nextCoinSeq);
            batch.Put(coinSequenceKey,
                CoinSequenceParser().GetVal({ .publicCoin = pubKey, .block = block }));

            undoRecorder.Record(UNDO_REMOVE_COIN_SEQ, block, coinSequenceKey);

            // prepare data to emit
            auto coinKey = CoinParser().GetKey(propertyId, pubKey);
            std::string raw;
            if (!pdb->Get(readoptions, coinKey, &raw).ok()) {
                throw std::runtime_error("Fail to get coin data");
            }

            CoinData coinData;
            ParseRaw(raw, coinData);
            entries.emplace_back(nextCoinSeq, coinData, pubKey);

            // record index
            coinData.index = nextCoinSeq;
            coinData.block = block;
            coinData.group = lastGroup;
            batch.Put(coinKey, MakeRaw(coinData));

            nextCoinSeq++;
        }

        // emit mints
        for (auto const &e : entries) {
            auto coinData = std::get<1>(e);
            auto pubkey = std::get<2>(e);

            auto const &additional = coinData.additionalData;
            boost::optional<LelantusAmount> amount;
            if (coinData.amount > 0) {
                amount = coinData.amount;
            }

#ifdef ENABLE_WALLET
            if (pwalletMain && amount.get_ptr() == nullptr && additional.size() == 16) {
                EncryptedValue enc;
                std::copy(additional.begin(), additional.end(), &enc[0]);
                LelantusAmount retrieved;
                if (DecryptMintAmount(enc, pubkey.getValue(), retrieved)) {
                    LogPrint("handler", "Elysium handler: decrypted = %d\n", itostr(retrieved));

                    amount = retrieved;
                }
            }
#endif

            MintAdded(propertyId, coinData.id, lastGroup, std::get<0>(e), amount, block);
        }
    }

    pdb->Write(syncoptions, &batch);
}

void LelantusDb::DeleteAll(int startBlock)
{
    LOCK(cs);
    auto next = GetNextSequence(DB_UNDO);
    if (next == 0) {
        return;
    }

    auto it = NewIterator();
    it->Seek(MakeRaw(DB_UNDO, ::swapByteOrder(next - 1)));

    leveldb::WriteBatch batch;
    leveldb::Slice key;
    for (; it->Valid() && (key = it->key()).size() > 0 && key[0] == DB_UNDO; it->Prev()) {
        UndoEntry undoEntry;
        ParseRaw(it->value(), undoEntry);

        if (undoEntry.block < startBlock) {
            break;
        }

        switch (undoEntry.undoType) {
        case UNDO_REMOVE_SERIAL:
            batch.Delete(undoEntry.data);
            break;
        case UNDO_REMOVE_COIN:
            {
                std::tuple<char, PropertyId, lelantus::PublicCoin> coinKey;
                ParseRaw(undoEntry.data, coinKey);

                std::string rawCoinData;
                if (!pdb->Get(readoptions, undoEntry.data, &rawCoinData).ok()) {
                    throw std::runtime_error("Fail to read mint data");
                }

                CoinData coinData;
                ParseRaw(rawCoinData, coinData);

                MintRemoved(std::get<1>(coinKey), coinData.id);

                batch.Delete(undoEntry.data);
            }
            break;
        case UNDO_REMOVE_COIN_SEQ:
            batch.Delete(undoEntry.data);
            break;
        case UNDO_REMOVE_GROUP:
            batch.Delete(undoEntry.data);
            break;
        case UNDO_REVERSE_GROUP_DATA:
            {
                std::pair<std::string, std::string> data;
                ParseRaw(undoEntry.data, data);
                batch.Put(data.first, data.second);
            }
            break;
        case UNDO_REMOVE_COIN_ID:
            batch.Delete(undoEntry.data);
            break;
        default:
            throw std::runtime_error(strprintf("Unknown type : %d", undoEntry.undoType));
        }

        batch.Delete(it->key());
    }

    auto status = pdb->Write(syncoptions, &batch);
    if (!status.ok()) {
        throw std::runtime_error("Failed to write database: " + status.ToString());
    }
}

bool LelantusDb::WriteGroupSize(uint64_t groupSize, uint64_t mintAmount)
{
    assert(groupSize > mintAmount);
    std::string data;
    if (pdb->Get(readoptions, MakeRaw(DB_GROUPSIZE), &data).ok()) {
        return false;
    }

    return pdb->Put(writeoptions, MakeRaw(DB_GROUPSIZE), MakeRaw(groupSize, mintAmount)).ok();
}

std::pair<uint64_t, uint64_t> LelantusDb::ReadGroupSize()
{
    std::string data;
    if (!pdb->Get(readoptions, MakeRaw(DB_GROUPSIZE), &data).ok()) {
        return {0, 0};
    }

    std::pair<uint64_t, uint64_t> groupSizes;
    ParseRaw(data, groupSizes);

    assert(groupSizes.first > groupSizes.second);

    return groupSizes;
}

LelantusGroup LelantusDb::GetLastGroup(PropertyId id, uint64_t &coins)
{
    auto nextSeq = GetNextSequence(DB_COIN_SEQUENCE, id);
    coins = nextSeq;

    LelantusGroup group = 0;

    std::string data;
    if (!pdb->Get(readoptions, CoinGroupParser().GetKey(id, group), &data).ok()) {
        CoinGroupData groupData = {
            .firstSequence = 0,
            .lastBlock = -1,
        };
        if (!pdb->Put(writeoptions, CoinGroupParser().GetKey(id, group), MakeRaw(groupData)).ok()) {
            throw std::runtime_error("Fail to record group id 0");
        }
    }

    boost::optional<CoinGroupData> groupData;
    while (pdb->Get(readoptions, CoinGroupParser().GetKey(id, group + 1), &data).ok() && (groupData = CoinGroupParser().ParseVal(data)).get_ptr() != nullptr) {
        coins = nextSeq - groupData->firstSequence;
        group++;
    }

    return group;
}

std::unique_ptr<leveldb::Iterator> LelantusDb::NewIterator()
{
    return std::unique_ptr<leveldb::Iterator>(CDBBase::NewIterator());
}

LelantusDb *lelantusDb;

} // namespace elysium