#ifndef FIRO_ELYSIUM_SP_H
#define FIRO_ELYSIUM_SP_H

#include "log.h"
#include "persistence.h"
#include "property.h"

#include "../validation.h"
#include "../serialize.h"

#include <boost/filesystem.hpp>

#include <openssl/sha.h>

#include <fstream>
#include <ios>
#include <limits>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>

namespace elysium {

constexpr size_t MAX_DENOMINATIONS = std::numeric_limits<uint8_t>::max();

} // namespace elysium

/** LevelDB based storage for currencies, smart properties and tokens.
 *
 * DB Schema:
 *
 *  Key:
 *      char 'B'
 *  Value:
 *      uint256 hashBlock
 *
 *  Key:
 *      char 's'
 *      uint32_t propertyId
 *  Value:
 *      CMPSPInfo::Entry info
 *
 *  Key:
 *      char 't'
 *      uint256 hashTxid
 *  Value:
 *      uint32_t propertyId
 *
 *  Key:
 *      char 'b'
 *      uint256 hashBlock
 *      uint32_t propertyId
 *  Value:
 *      CMPSPInfo::Entry info
 */
class CMPSPInfo : public CDBBase
{
public:
    struct Entry {
        // common SP data
        std::string issuer;
        uint16_t prop_type;
        uint32_t prev_prop_id;
        std::string category;
        std::string subcategory;
        std::string name;
        std::string url;
        std::string data;
        int64_t num_tokens;

        // other information
        uint256 txid;
        uint256 creation_block;
        uint256 update_block;
        bool fixed;
        bool manual;
        elysium::LelantusStatus lelantusStatus;
        std::vector<int64_t> denominations;

        // For managed properties:
        //   txid -> granted amount, revoked amount
        std::map<uint256, std::vector<int64_t> > historicalData;

        Entry();

        ADD_SERIALIZE_METHODS;

        template <typename Stream, typename Operation>
        inline void SerializationOp(Stream& s, Operation ser_action) {
            auto lelantusStatus = static_cast<uint8_t>(this->lelantusStatus);

            READWRITE(issuer);
            READWRITE(prop_type);
            READWRITE(prev_prop_id);
            READWRITE(category);
            READWRITE(subcategory);
            READWRITE(name);
            READWRITE(url);
            READWRITE(data);
            READWRITE(num_tokens);            
            READWRITE(txid);
            READWRITE(creation_block);
            READWRITE(update_block);
            READWRITE(fixed);
            READWRITE(manual);
            READWRITE(historicalData);

            if (ser_action.ForRead()) {
                // If it is EOF when trying to read additional field that mean it is data before we introduced it.
                 try {
                    READWRITE(lelantusStatus);
                } catch (std::ios_base::failure&) {
                    lelantusStatus = static_cast<uint8_t>(elysium::LelantusStatus::SoftDisabled);
                }
            } else {
                READWRITE(lelantusStatus);
            }
            this->lelantusStatus = static_cast<elysium::LelantusStatus>(lelantusStatus);
        }

        bool isDivisible() const;
        void print() const;
    };

private:
    // implied version of ELYSIUM and TELYSIUM so they don't hit the leveldb
    Entry implied_elysium;
    Entry implied_telysium;

    uint32_t next_spid;
    uint32_t next_test_spid;

public:
    CMPSPInfo(const boost::filesystem::path& path, bool fWipe);
    virtual ~CMPSPInfo();

    /** Extends clearing of CDBBase. */
    void Clear();

    void init(uint32_t nextSPID = 0x3UL, uint32_t nextTestSPID = TEST_ECO_PROPERTY_1);

    uint32_t peekNextSPID(uint8_t ecosystem) const;
    bool updateSP(uint32_t propertyId, const Entry& info);
    uint32_t putSP(uint8_t ecosystem, const Entry& info);
    bool getSP(uint32_t propertyId, Entry& info) const;
    bool hasSP(uint32_t propertyId) const;
    uint32_t findSPByTX(const uint256& txid) const;

    int64_t popBlock(const uint256& block_hash);

    void setWatermark(const uint256& watermark);
    bool getWatermark(uint256& watermark) const;

    bool getPrevVersion(uint32_t propertyId, Entry &info) const;

    void printAll() const;
};


namespace elysium {

extern CMPSPInfo* _my_sps;

std::string strPropertyType(uint16_t propertyType);
std::string strEcosystem(uint8_t ecosystem);

std::string getPropertyName(uint32_t propertyId);
bool isPropertyDivisible(uint32_t propertyId);
bool IsPropertyIdValid(uint32_t propertyId);

bool IsLelantusStatusValid(LelantusStatus status);
bool IsLelantusEnabled(PropertyId property);
bool IsLelantusStatusUpdatable(PropertyId property);

} // namespace elysium

namespace std {

using namespace elysium;

string to_string(LelantusStatus status);

} // namespace std

#endif // FIRO_ELYSIUM_SP_H
