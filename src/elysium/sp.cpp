#include "sp.h"

#include "log.h"
#include "elysium.h"
#include "packetencoder.h"
#include "uint256_extensions.h"
#include "utilsbitcoin.h"

#include "../arith_uint256.h"
#include "../base58.h"
#include "../clientversion.h"
#include "../validation.h"
#include "../serialize.h"
#include "../streams.h"
#include "../tinyformat.h"
#include "../uint256.h"
#include "../utiltime.h"

#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>

#include <leveldb/db.h>
#include <leveldb/write_batch.h>

#include <stdint.h>

#include <map>
#include <string>
#include <vector>
#include <utility>

using namespace elysium;

CMPSPInfo::Entry::Entry()
  : prop_type(0), prev_prop_id(0), num_tokens(0), 
    fixed(false), manual(false), lelantusStatus(LelantusStatus::SoftDisabled) {}

bool CMPSPInfo::Entry::isDivisible() const
{
    switch (prop_type) {
        case ELYSIUM_PROPERTY_TYPE_DIVISIBLE:
        case ELYSIUM_PROPERTY_TYPE_DIVISIBLE_REPLACING:
        case ELYSIUM_PROPERTY_TYPE_DIVISIBLE_APPENDING:
            return true;
    }
    return false;
}

void CMPSPInfo::Entry::print() const
{
    PrintToLog("%s:%s(Fixed=%s,Divisible=%s):%d:%s/%s, %s %s\n",
            issuer,
            name,
            fixed ? "Yes" : "No",
            isDivisible() ? "Yes" : "No",
            num_tokens,
            category, subcategory, url, data);
}

CMPSPInfo::CMPSPInfo(const boost::filesystem::path& path, bool fWipe)
{
    leveldb::Status status = Open(path, fWipe);
    PrintToLog("Loading smart property database: %s\n", status.ToString());

    // special cases for constant SPs ELYSIUM and TELYSIUM
    implied_elysium.issuer = GetSystemAddress().ToString();
    implied_elysium.prop_type = ELYSIUM_PROPERTY_TYPE_DIVISIBLE;
    implied_elysium.num_tokens = 700000;
    implied_elysium.category = "N/A";
    implied_elysium.subcategory = "N/A";
    implied_elysium.name = "Elysium";
    implied_elysium.url = "https://www.firo.org";
    implied_elysium.data = "Elysium serve as the binding between Firo, smart properties and contracts created on the Elysium Layer.";
    implied_telysium.issuer = GetSystemAddress().ToString();
    implied_telysium.prop_type = ELYSIUM_PROPERTY_TYPE_DIVISIBLE;
    implied_telysium.num_tokens = 700000;
    implied_telysium.category = "N/A";
    implied_telysium.subcategory = "N/A";
    implied_telysium.name = "Test Elysium";
    implied_telysium.url = "https://www.firo.org";
    implied_telysium.data = "Test Elysium serve as the binding between Firo, smart properties and contracts created on the Elysium Layer.";

    init();
}

CMPSPInfo::~CMPSPInfo()
{
    if (elysium_debug_persistence) PrintToLog("CMPSPInfo closed\n");
}

void CMPSPInfo::Clear()
{
    // wipe database via parent class
    CDBBase::Clear();
    // reset "next property identifiers"
    init();
}

void CMPSPInfo::init(uint32_t nextSPID, uint32_t nextTestSPID)
{
    next_spid = nextSPID;
    next_test_spid = nextTestSPID;
}

uint32_t CMPSPInfo::peekNextSPID(uint8_t ecosystem) const
{
    uint32_t nextId = 0;

    switch (ecosystem) {
        case ELYSIUM_PROPERTY_ELYSIUM: // Main ecosystem, ELYSIUM: 1, TELYSIUM: 2, First available SP = 3
            nextId = next_spid;
            break;
        case ELYSIUM_PROPERTY_TELYSIUM: // Test ecosystem, same as above with high bit set
            nextId = next_test_spid;
            break;
        default: // Non-standard ecosystem, ID's start at 0
            nextId = 0;
    }

    return nextId;
}

bool CMPSPInfo::updateSP(uint32_t propertyId, const Entry& info)
{
    // cannot update implied SP
    if (ELYSIUM_PROPERTY_ELYSIUM == propertyId || ELYSIUM_PROPERTY_TELYSIUM == propertyId) {
        return false;
    }

    // DB key for property entry
    CDataStream ssSpKey(SER_DISK, CLIENT_VERSION);
    ssSpKey << std::make_pair('s', propertyId);
    leveldb::Slice slSpKey(&ssSpKey[0], ssSpKey.size());

    // DB value for property entry
    CDataStream ssSpValue(SER_DISK, CLIENT_VERSION);
    ssSpValue << info;
    leveldb::Slice slSpValue(&ssSpValue[0], ssSpValue.size());

    // DB key for historical property entry
    CDataStream ssSpPrevKey(SER_DISK, CLIENT_VERSION);
    ssSpPrevKey << 'b';
    ssSpPrevKey << info.update_block;
    ssSpPrevKey << propertyId;
    leveldb::Slice slSpPrevKey(&ssSpPrevKey[0], ssSpPrevKey.size());

    leveldb::WriteBatch batch;
    std::string strSpPrevValue;

    // if a value exists move it to the old key
    if (!pdb->Get(readoptions, slSpKey, &strSpPrevValue).IsNotFound()) {
        batch.Put(slSpPrevKey, strSpPrevValue);
    }
    batch.Put(slSpKey, slSpValue);
    leveldb::Status status = pdb->Write(syncoptions, &batch);

    if (!status.ok()) {
        PrintToLog("%s(): ERROR for SP %d: %s\n", __func__, propertyId, status.ToString());
        return false;
    }

    PrintToLog("%s(): updated entry for SP %d successfully\n", __func__, propertyId);
    return true;
}

uint32_t CMPSPInfo::putSP(uint8_t ecosystem, const Entry& info)
{
    uint32_t propertyId = 0;
    switch (ecosystem) {
        case ELYSIUM_PROPERTY_ELYSIUM: // Main ecosystem, ELYSIUM: 1, TELYSIUM: 2, First available SP = 3
            propertyId = next_spid++;
            break;
        case ELYSIUM_PROPERTY_TELYSIUM: // Test ecosystem, same as above with high bit set
            propertyId = next_test_spid++;
            break;
        default: // Non-standard ecosystem, ID's start at 0
            propertyId = 0;
    }

    // DB key for property entry
    CDataStream ssSpKey(SER_DISK, CLIENT_VERSION);
    ssSpKey << std::make_pair('s', propertyId);
    leveldb::Slice slSpKey(&ssSpKey[0], ssSpKey.size());

    // DB value for property entry
    CDataStream ssSpValue(SER_DISK, CLIENT_VERSION);
    ssSpValue << info;
    leveldb::Slice slSpValue(&ssSpValue[0], ssSpValue.size());

    // DB key for identifier lookup entry
    CDataStream ssTxIndexKey(SER_DISK, CLIENT_VERSION);
    ssTxIndexKey << std::make_pair('t', info.txid);
    leveldb::Slice slTxIndexKey(&ssTxIndexKey[0], ssTxIndexKey.size());

    // DB value for identifier
    CDataStream ssTxValue(SER_DISK, CLIENT_VERSION);
    ssTxValue << propertyId;
    leveldb::Slice slTxValue(&ssTxValue[0], ssTxValue.size());

    // sanity checking
    std::string existingEntry;
    if (!pdb->Get(readoptions, slSpKey, &existingEntry).IsNotFound() && slSpValue.compare(existingEntry) != 0) {
        std::string strError = strprintf("writing SP %d to DB, when a different SP already exists for that identifier", propertyId);
        PrintToLog("%s() ERROR: %s\n", __func__, strError);
        throw std::runtime_error("error writing index: SP already exists for that identifier");
    } else if (!pdb->Get(readoptions, slTxIndexKey, &existingEntry).IsNotFound() && slTxValue.compare(existingEntry) != 0) {
        std::string strError = strprintf("writing index txid %s : SP %d is overwriting a different value", info.txid.ToString(), propertyId);
        PrintToLog("%s() ERROR: %s\n", __func__, strError);
        throw std::runtime_error("error writing index: writing SP would overwrite another value");
    }

    // atomically write both the the SP and the index to the database
    leveldb::WriteBatch batch;
    batch.Put(slSpKey, slSpValue);
    batch.Put(slTxIndexKey, slTxValue);

    leveldb::Status status = pdb->Write(syncoptions, &batch);

    if (!status.ok()) {
        PrintToLog("%s(): ERROR for SP %d: %s\n", __func__, propertyId, status.ToString());
        throw std::runtime_error("failed to write SP");
    }

    return propertyId;
}

bool CMPSPInfo::getSP(uint32_t propertyId, Entry& info) const
{
    // special cases for constant SPs ELYSIUM and TELYSIUM
    if (ELYSIUM_PROPERTY_ELYSIUM == propertyId) {
        info = implied_elysium;
        return true;
    } else if (ELYSIUM_PROPERTY_TELYSIUM == propertyId) {
        info = implied_telysium;
        return true;
    }

    // DB key for property entry
    CDataStream ssSpKey(SER_DISK, CLIENT_VERSION);
    ssSpKey << std::make_pair('s', propertyId);
    leveldb::Slice slSpKey(&ssSpKey[0], ssSpKey.size());

    // DB value for property entry
    std::string strSpValue;
    leveldb::Status status = pdb->Get(readoptions, slSpKey, &strSpValue);
    if (!status.ok()) {
        if (!status.IsNotFound()) {
            PrintToLog("%s(): ERROR for SP %d: %s\n", __func__, propertyId, status.ToString());
        }
        return false;
    }

    try {
        CDataStream ssSpValue(strSpValue.data(), strSpValue.data() + strSpValue.size(), SER_DISK, CLIENT_VERSION);
        ssSpValue >> info;
    } catch (const std::exception& e) {
        PrintToLog("%s(): ERROR for SP %d: %s\n", __func__, propertyId, e.what());
        return false;
    }

    return true;
}

bool CMPSPInfo::hasSP(uint32_t propertyId) const
{
    // Special cases for constant SPs MSC and TMSC
    if (ELYSIUM_PROPERTY_ELYSIUM == propertyId || ELYSIUM_PROPERTY_TELYSIUM == propertyId) {
        return true;
    }

    // DB key for property entry
    CDataStream ssSpKey(SER_DISK, CLIENT_VERSION);
    ssSpKey << std::make_pair('s', propertyId);
    leveldb::Slice slSpKey(&ssSpKey[0], ssSpKey.size());

    // DB value for property entry
    std::string strSpValue;
    leveldb::Status status = pdb->Get(readoptions, slSpKey, &strSpValue);

    return status.ok();
}

uint32_t CMPSPInfo::findSPByTX(const uint256& txid) const
{
    uint32_t propertyId = 0;

    // DB key for identifier lookup entry
    CDataStream ssTxIndexKey(SER_DISK, CLIENT_VERSION);
    ssTxIndexKey << std::make_pair('t', txid);
    leveldb::Slice slTxIndexKey(&ssTxIndexKey[0], ssTxIndexKey.size());

    // DB value for identifier
    std::string strTxIndexValue;
    if (!pdb->Get(readoptions, slTxIndexKey, &strTxIndexValue).ok()) {
        std::string strError = strprintf("failed to find property created with %s", txid.GetHex());
        PrintToLog("%s(): ERROR: %s", __func__, strError);
        return 0;
    }

    try {
        CDataStream ssValue(strTxIndexValue.data(), strTxIndexValue.data() + strTxIndexValue.size(), SER_DISK, CLIENT_VERSION);
        ssValue >> propertyId;
    } catch (const std::exception& e) {
        PrintToLog("%s(): ERROR: %s\n", __func__, e.what());
        return 0;
    }

    return propertyId;
}

int64_t CMPSPInfo::popBlock(const uint256& block_hash)
{
    int64_t remainingSPs = 0;
    leveldb::WriteBatch commitBatch;
    leveldb::Iterator* iter = NewIterator();

    CDataStream ssSpKeyPrefix(SER_DISK, CLIENT_VERSION);
    ssSpKeyPrefix << 's';
    leveldb::Slice slSpKeyPrefix(&ssSpKeyPrefix[0], ssSpKeyPrefix.size());

    for (iter->Seek(slSpKeyPrefix); iter->Valid() && iter->key().starts_with(slSpKeyPrefix); iter->Next()) {
        // deserialize the persisted value
        leveldb::Slice slSpValue = iter->value();
        Entry info;
        try {
            CDataStream ssValue(slSpValue.data(), slSpValue.data() + slSpValue.size(), SER_DISK, CLIENT_VERSION);
            ssValue >> info;
        } catch (const std::exception& e) {
            PrintToLog("%s(): ERROR: %s\n", __func__, e.what());
            return -1;
        }
        // pop the block
        if (info.update_block == block_hash) {
            leveldb::Slice slSpKey = iter->key();

            // need to roll this SP back
            if (info.update_block == info.creation_block) {
                // this is the block that created this SP, so delete the SP and the tx index entry
                CDataStream ssTxIndexKey(SER_DISK, CLIENT_VERSION);
                ssTxIndexKey << std::make_pair('t', info.txid);
                leveldb::Slice slTxIndexKey(&ssTxIndexKey[0], ssTxIndexKey.size());
                commitBatch.Delete(slSpKey);
                commitBatch.Delete(slTxIndexKey);
            } else {
                uint32_t propertyId = 0;
                try {
                    CDataStream ssValue(1+slSpKey.data(), 1+slSpKey.data()+slSpKey.size(), SER_DISK, CLIENT_VERSION);
                    ssValue >> propertyId;
                } catch (const std::exception& e) {
                    PrintToLog("%s(): ERROR: %s\n", __func__, e.what());
                    return -2;
                }

                CDataStream ssSpPrevKey(SER_DISK, CLIENT_VERSION);
                ssSpPrevKey << 'b';
                ssSpPrevKey << info.update_block;
                ssSpPrevKey << propertyId;
                leveldb::Slice slSpPrevKey(&ssSpPrevKey[0], ssSpPrevKey.size());

                std::string strSpPrevValue;
                if (!pdb->Get(readoptions, slSpPrevKey, &strSpPrevValue).IsNotFound()) {
                    // copy the prev state to the current state and delete the old state
                    commitBatch.Put(slSpKey, strSpPrevValue);
                    commitBatch.Delete(slSpPrevKey);
                    ++remainingSPs;
                } else {
                    // failed to find a previous SP entry, trigger reparse
                    PrintToLog("%s(): ERROR: failed to retrieve previous SP entry\n", __func__);
                    return -3;
                }
            }
        } else {
            ++remainingSPs;
        }
    }

    // clean up the iterator
    delete iter;

    leveldb::Status status = pdb->Write(syncoptions, &commitBatch);

    if (!status.ok()) {
        PrintToLog("%s(): ERROR: %s\n", __func__, status.ToString());
        return -4;
    }

    return remainingSPs;
}

void CMPSPInfo::setWatermark(const uint256& watermark)
{
    leveldb::WriteBatch batch;

    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    ssKey << 'B';
    leveldb::Slice slKey(&ssKey[0], ssKey.size());

    CDataStream ssValue(SER_DISK, CLIENT_VERSION);
    ssValue << watermark;
    leveldb::Slice slValue(&ssValue[0], ssValue.size());

    batch.Delete(slKey);
    batch.Put(slKey, slValue);

    leveldb::Status status = pdb->Write(syncoptions, &batch);
    if (!status.ok()) {
        PrintToLog("%s(): ERROR: failed to write watermark: %s\n", __func__, status.ToString());
    }
}

bool CMPSPInfo::getWatermark(uint256& watermark) const
{
    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    ssKey << 'B';
    leveldb::Slice slKey(&ssKey[0], ssKey.size());

    std::string strValue;
    leveldb::Status status = pdb->Get(readoptions, slKey, &strValue);
    if (!status.ok()) {
        if (!status.IsNotFound()) {
            PrintToLog("%s(): ERROR: failed to retrieve watermark: %s\n", __func__, status.ToString());
        }
        return false;
    }

    try {
        CDataStream ssValue(strValue.data(), strValue.data() + strValue.size(), SER_DISK, CLIENT_VERSION);
        ssValue >> watermark;
    } catch (const std::exception& e) {
        PrintToLog("%s(): ERROR: failed to deserialize watermark: %s\n", __func__, e.what());
        return false;
    }

    return true;
}

bool CMPSPInfo::getPrevVersion(uint32_t propertyId, Entry &info) const
{
    CDataStream prevKeyData(SER_DISK, CLIENT_VERSION);
    prevKeyData << 'b';
    prevKeyData << info.update_block;
    prevKeyData << propertyId;
    leveldb::Slice prevKey(&prevKeyData[0], prevKeyData.size());

    std::string prevValueData;
    auto status = pdb->Get(readoptions, prevKey, &prevValueData);
    if (!status.ok()) {
        if (status.IsNotFound()) {
            return false;
        }
        LogPrintf("%s() : fail to get previous version of property %d\n", __func__, propertyId);
        throw std::runtime_error("fail to get previous version of sp");
    }

    CDataStream prevValue(
        prevValueData.data(),
        prevValueData.data() + prevValueData.size(),
        SER_DISK, CLIENT_VERSION
    );
    prevValue >> info;

    return true;
}

void CMPSPInfo::printAll() const
{
    // print off the hard coded MSC and TMSC entries
    for (uint32_t idx = ELYSIUM_PROPERTY_ELYSIUM; idx <= ELYSIUM_PROPERTY_TELYSIUM; idx++) {
        Entry info;
        PrintToLog("%10d => ", idx);
        if (getSP(idx, info)) {
            info.print();
        } else {
            PrintToLog("<Internal Error on implicit SP>\n");
        }
    }

    leveldb::Iterator* iter = NewIterator();

    CDataStream ssSpKeyPrefix(SER_DISK, CLIENT_VERSION);
    ssSpKeyPrefix << 's';
    leveldb::Slice slSpKeyPrefix(&ssSpKeyPrefix[0], ssSpKeyPrefix.size());

    for (iter->Seek(slSpKeyPrefix); iter->Valid() && iter->key().starts_with(slSpKeyPrefix); iter->Next()) {
        leveldb::Slice slSpKey = iter->key();
        uint32_t propertyId = 0;
        try {
            CDataStream ssValue(1+slSpKey.data(), 1+slSpKey.data()+slSpKey.size(), SER_DISK, CLIENT_VERSION);
            ssValue >> propertyId;
        } catch (const std::exception& e) {
            PrintToLog("<Malformed key in DB>\n");
            PrintToLog("%s(): ERROR: %s\n", __func__, e.what());
            continue;
        }
        PrintToLog("%10s => ", propertyId);

        // deserialize the persisted data
        leveldb::Slice slSpValue = iter->value();
        Entry info;
        try {
            CDataStream ssSpValue(slSpValue.data(), slSpValue.data() + slSpValue.size(), SER_DISK, CLIENT_VERSION);
            ssSpValue >> info;
        } catch (const std::exception& e) {
            PrintToLog("<Malformed value in DB>\n");
            PrintToLog("%s(): ERROR: %s\n", __func__, e.what());
            continue;
        }
        info.print();
    }

    // clean up the iterator
    delete iter;
}



bool elysium::IsPropertyIdValid(uint32_t propertyId)
{
    if (propertyId == 0) return false;

    uint32_t nextId = 0;

    if (propertyId < TEST_ECO_PROPERTY_1) {
        nextId = _my_sps->peekNextSPID(1);
    } else {
        nextId = _my_sps->peekNextSPID(2);
    }

    if (propertyId < nextId) {
        return true;
    }

    return false;
}

bool elysium::IsLelantusStatusValid(LelantusStatus status)
{
    return status == LelantusStatus::SoftDisabled ||
           status == LelantusStatus::SoftEnabled ||
           status == LelantusStatus::HardDisabled ||
           status == LelantusStatus::HardEnabled;
}

bool elysium::IsLelantusEnabled(PropertyId property)
{
    CMPSPInfo::Entry info;

    LOCK(cs_main);

    if (!_my_sps->getSP(property, info)) {
        throw std::invalid_argument("property identifier is not valid");
    }

    return IsEnabledFlag(info.lelantusStatus);
}

bool elysium::IsLelantusStatusUpdatable(PropertyId property)
{
    CMPSPInfo::Entry info;

    LOCK(cs_main);

    if (!_my_sps->getSP(property, info)) {
        throw std::invalid_argument("property identifier is not valid");
    }

    return info.lelantusStatus == elysium::LelantusStatus::SoftDisabled ||
        info.lelantusStatus == elysium::LelantusStatus::SoftEnabled;
}

std::string std::to_string(LelantusStatus status)
{
    switch (status) {
    case LelantusStatus::SoftDisabled:
        return "SoftDisabled";
    case LelantusStatus::SoftEnabled:
        return "SoftEnabled";
    case LelantusStatus::HardDisabled:
        return "HardDisabled";
    case LelantusStatus::HardEnabled:
        return "HardEnabled";
    default:
        throw std::invalid_argument("lelantus status is invalid");
    }
}

bool elysium::isPropertyDivisible(uint32_t propertyId)
{
    // TODO: is a lock here needed
    CMPSPInfo::Entry sp;

    if (_my_sps->getSP(propertyId, sp)) return sp.isDivisible();

    return true;
}

std::string elysium::getPropertyName(uint32_t propertyId)
{
    CMPSPInfo::Entry sp;
    if (_my_sps->getSP(propertyId, sp)) return sp.name;
    return "Property Name Not Found";
}

std::string elysium::strPropertyType(uint16_t propertyType)
{
    switch (propertyType) {
        case ELYSIUM_PROPERTY_TYPE_DIVISIBLE: return "divisible";
        case ELYSIUM_PROPERTY_TYPE_INDIVISIBLE: return "indivisible";
    }

    return "unknown";
}

std::string elysium::strEcosystem(uint8_t ecosystem)
{
    switch (ecosystem) {
        case ELYSIUM_PROPERTY_ELYSIUM: return "main";
        case ELYSIUM_PROPERTY_TELYSIUM: return "test";
    }

    return "unknown";
}
