// Copyright (c) 2020 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FIRO_ELYSIUM_LELANTUSDB_H
#define FIRO_ELYSIUM_LELANTUSDB_H

#include "../dbwrapper.h"
#include "../sync.h"
#include "../liblelantus/coin.h"

#include "lelantusprimitives.h"
#include "persistence.h"
#include "property.h"

namespace elysium {

class LelantusDb : public CDBBase
{
protected:
    CCriticalSection cs;

    static const uint64_t DEFAULT_GROUPSIZE = 65000;
    static const uint64_t DEFAULT_STARTCOINS = 16000;

    uint64_t groupSize;
    uint64_t startGroupSize;

public:
    LelantusDb(const boost::filesystem::path& path, bool wipe, uint64_t groupSize = DEFAULT_GROUPSIZE, uint64_t startCoins = DEFAULT_STARTCOINS);

public:
    bool HasSerial(PropertyId id, Scalar const &serial, uint256 &spendTx);
    bool WriteSerial(PropertyId id, secp_primitives::Scalar serial, int block, uint256 const &spendTx);

    std::vector<lelantus::PublicCoin> GetAnonymityGroup(PropertyId id, LelantusGroup groupId, uint64_t count, int &block);
    bool HasMint(PropertyId propertyId, lelantus::PublicCoin const &pubKey);
    bool HasMint(MintEntryId const &id, PropertyId &property, lelantus::PublicCoin &publicKey, LelantusIndex &index, LelantusGroup &group, int &block, LelantusAmount &amount, std::vector<unsigned char> &additional);
    bool WriteMint(PropertyId propertyId, lelantus::PublicCoin const &pubKey, int block, MintEntryId const &id, LelantusAmount amount, std::vector<unsigned char> const &additional);
    bool WriteMint(PropertyId propertyId, JoinSplitMint const &mint, int block);

    LelantusGroup GetGroup(PropertyId property, lelantus::PublicCoin const &pubKey);
    LelantusGroup GetGroup(PropertyId property, MintEntryId const &id);

    void DeleteAll(int startBlock);

    void CommitCoins();

public:
    boost::signals2::signal<void(PropertyId, MintEntryId, LelantusGroup, LelantusIndex, boost::optional<LelantusAmount>, int)> MintAdded;
    boost::signals2::signal<void(PropertyId, MintEntryId)> MintRemoved;

protected:

    template<typename ...T>
    uint64_t GetNextSequence(T ...t) {
        auto key = std::make_tuple(t..., UINT64_MAX);
        auto it = NewIterator();

        {
            CDataStream ss(SER_DISK, CLIENT_VERSION);
            ss << key;
            it->Seek(ss.str());
        }

        if (!it->Valid()) {
            return 0;
        }

        it->Prev();
        if (!it->Valid()) {
            return 0;
        }

        std::tuple<T..., uint64_t> key2;
        {
            auto k = it->key();
            CDataStream ss(k.data(), k.data() + k.size(), SER_DISK, CLIENT_VERSION);
            ss >> key2;
        }

        std::get<sizeof...(t)>(key) = std::get<sizeof...(t)>(key2);

        if (key != key2) {
            return 0;
        }

        auto v = std::get<sizeof...(t)>(key);
        swapByteOrder(v);

        return v + 1;
    }

    bool WriteGroupSize(uint64_t groupSize, uint64_t mintAmount);
    std::pair<uint64_t, uint64_t> ReadGroupSize();

    LelantusGroup GetLastGroup(PropertyId id, uint64_t &coins);

    std::unique_ptr<leveldb::Iterator> NewIterator();
};

extern LelantusDb *lelantusDb;

} // namespace elysium

#endif // FIRO_ELYSIUM_LELANTUSDB_H