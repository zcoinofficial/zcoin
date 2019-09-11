#ifndef ZCOIN_EXODUS_SIGMADB_H
#define ZCOIN_EXODUS_SIGMADB_H

#include "convert.h"
#include "persistence.h"
#include "property.h"
#include "sigma.h"

#include <univalue.h>

#include <boost/filesystem/path.hpp>
#include <boost/signals2/signal.hpp>

#include <leveldb/slice.h>

#include <string>
#include <vector>

#include <inttypes.h>

template<typename T, typename = void>
struct is_iterator
{
    static constexpr bool value = false;
};

template<typename T>
struct is_iterator<T, typename std::enable_if<!std::is_same<typename std::iterator_traits<T>::iterator_category, void>::value>::type>
{
    static constexpr bool value = true;
};

namespace exodus {

typedef uint32_t MintGroupId;
typedef uint16_t MintGroupIndex;

class SigmaDatabase : public CDBBase
{
public:
    /**
     * Limit of sigma anonimity group, which is 2 ^ 14.
     */
    static constexpr uint16_t MAX_GROUP_SIZE = 16384;

public:
    SigmaDatabase(const boost::filesystem::path& path, bool wipe, uint16_t groupSize = 0);
    ~SigmaDatabase() override;

public:
    std::pair<MintGroupId, MintGroupIndex> RecordMint(
        PropertyId propertyId,
        DenominationId denomination,
        const SigmaPublicKey& pubKey,
        int height);
    void RecordSpendSerial(uint32_t propertyId, uint8_t denomination, secp_primitives::Scalar const &serial, int height);

    template<
        class OutputIt,
        typename std::enable_if<is_iterator<OutputIt>::value, void>::type* = nullptr
    > OutputIt GetAnonimityGroup(uint32_t propertyId, uint8_t denomination, uint32_t groupId, size_t count, OutputIt firstIt)
    {
        GetAnonimityGroup(propertyId, denomination, groupId, count, [&firstIt](exodus::SigmaPublicKey& pub) mutable {
            *firstIt++ = std::move(pub);
        });

        return firstIt;
    }
    size_t GetAnonimityGroup(uint32_t propertyId, uint8_t denomination, uint32_t groupId, size_t count,
        std::function<void(exodus::SigmaPublicKey&)>);

    template<class OutputIt>
    OutputIt GetAnonimityGroup(uint32_t propertyId, uint8_t denomination, uint32_t groupId, OutputIt firstIt)
    {
        auto mintCount = GetMintCount(propertyId, denomination, groupId);
        if (mintCount) {
            firstIt = GetAnonimityGroup(propertyId, denomination, groupId, mintCount, firstIt);
        }
        return firstIt;
    }

    void DeleteAll(int startBlock);

    uint32_t GetLastGroupId(uint32_t propertyId, uint8_t denomination);
    size_t GetMintCount(uint32_t propertyId, uint8_t denomination, uint32_t groupId);
    uint64_t GetNextSequence();
    SigmaPublicKey GetMint(uint32_t propertyId, uint8_t denomination, uint32_t groupId, uint16_t index);
    bool HasSpendSerial(uint32_t propertyId, uint8_t denomination, secp_primitives::Scalar const &serial);

    uint16_t groupSize;

public:
    boost::signals2::signal<void(PropertyId, DenominationId, MintGroupId, MintGroupIndex, const SigmaPublicKey&, int)> MintAdded;
    boost::signals2::signal<void(PropertyId, DenominationId, const SigmaPublicKey&)> MintRemoved;

protected:
    void AddEntry(const leveldb::Slice& key, const leveldb::Slice& value, int block);

private:
    void RecordGroupSize(uint16_t groupSize);

    std::unique_ptr<leveldb::Iterator> NewIterator() const;

protected:
    uint16_t InitGroupSize(uint16_t groupSize);
    uint16_t GetGroupSize();
};

extern SigmaDatabase *sigmaDb;

} // namespace exodus

#endif // ZCOIN_EXODUS_SIGMADB_H