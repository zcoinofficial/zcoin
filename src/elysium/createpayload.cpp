#include "createpayload.h"

#include "convert.h"
#include "sigma.h"
#include "tx.h"
#include "utils.h"

#include "../clientversion.h"
#include "../tinyformat.h"
#include "../streams.h"
#include "../version.h"

#include <string>
#include <vector>

#include <inttypes.h>

/**
 * Pushes bytes to the end of a vector.
 */
#define PUSH_BACK_BYTES(vector, value)\
    vector.insert(vector.end(), reinterpret_cast<unsigned char *>(&(value)),\
    reinterpret_cast<unsigned char *>(&(value)) + sizeof((value)));

/**
 * Pushes bytes to the end of a vector based on a pointer.
 */
#define PUSH_BACK_BYTES_PTR(vector, ptr, size)\
    vector.insert(vector.end(), reinterpret_cast<unsigned char *>((ptr)),\
    reinterpret_cast<unsigned char *>((ptr)) + (size));


std::vector<unsigned char> CreatePayload_SimpleSend(uint32_t propertyId, uint64_t amount)
{
    std::vector<unsigned char> payload;
    uint16_t messageType = ELYSIUM_TYPE_SIMPLE_SEND;
    uint16_t messageVer = 0;
    elysium::swapByteOrder16(messageType);
    elysium::swapByteOrder16(messageVer);
    elysium::swapByteOrder32(propertyId);
    elysium::swapByteOrder64(amount);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, propertyId);
    PUSH_BACK_BYTES(payload, amount);

    return payload;
}

std::vector<unsigned char> CreatePayload_SendAll(uint8_t ecosystem)
{
    std::vector<unsigned char> payload;
    uint16_t messageVer = 0;
    uint16_t messageType = ELYSIUM_TYPE_SEND_ALL;
    elysium::swapByteOrder16(messageVer);
    elysium::swapByteOrder16(messageType);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, ecosystem);

    return payload;
}

std::vector<unsigned char> CreatePayload_SendToOwners(uint32_t propertyId, uint64_t amount, uint32_t distributionProperty)
{
    bool v0 = (propertyId == distributionProperty) ? true : false;

    std::vector<unsigned char> payload;

    uint16_t messageType = ELYSIUM_TYPE_SEND_TO_OWNERS;
    uint16_t messageVer = (v0) ? 0 : 1;
    elysium::swapByteOrder16(messageType);
    elysium::swapByteOrder16(messageVer);
    elysium::swapByteOrder32(propertyId);
    elysium::swapByteOrder64(amount);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, propertyId);
    PUSH_BACK_BYTES(payload, amount);
    if (!v0) {
        elysium::swapByteOrder32(distributionProperty);
        PUSH_BACK_BYTES(payload, distributionProperty);
    }

    return payload;
}

std::vector<unsigned char> CreatePayload_IssuanceFixed(uint8_t ecosystem, uint16_t propertyType, uint32_t previousPropertyId, std::string category,
                                                       std::string subcategory, std::string name, std::string url, std::string data, uint64_t amount,
                                                       boost::optional<elysium::LelantusStatus> lelantusStatus)
{
    std::vector<unsigned char> payload;
    uint16_t messageType = ELYSIUM_TYPE_CREATE_PROPERTY_FIXED;
    uint16_t messageVer = lelantusStatus ? 2 : 0;

    elysium::swapByteOrder16(messageVer);
    elysium::swapByteOrder16(messageType);
    elysium::swapByteOrder16(propertyType);
    elysium::swapByteOrder32(previousPropertyId);
    elysium::swapByteOrder64(amount);

    if (category.size() > 255) category = category.substr(0,255);
    if (subcategory.size() > 255) subcategory = subcategory.substr(0,255);
    if (name.size() > 255) name = name.substr(0,255);
    if (url.size() > 255) url = url.substr(0,255);
    if (data.size() > 255) data = data.substr(0,255);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, ecosystem);
    PUSH_BACK_BYTES(payload, propertyType);
    PUSH_BACK_BYTES(payload, previousPropertyId);
    payload.insert(payload.end(), category.begin(), category.end());
    payload.push_back('\0');
    payload.insert(payload.end(), subcategory.begin(), subcategory.end());
    payload.push_back('\0');
    payload.insert(payload.end(), name.begin(), name.end());
    payload.push_back('\0');
    payload.insert(payload.end(), url.begin(), url.end());
    payload.push_back('\0');
    payload.insert(payload.end(), data.begin(), data.end());
    payload.push_back('\0');
    PUSH_BACK_BYTES(payload, amount);

    if (lelantusStatus) {
        PUSH_BACK_BYTES(payload, lelantusStatus.get());
    }

    return payload;
}

std::vector<unsigned char> CreatePayload_IssuanceManaged(uint8_t ecosystem, uint16_t propertyType, uint32_t previousPropertyId, std::string category,
                                                       std::string subcategory, std::string name, std::string url, std::string data,
                                                       boost::optional<elysium::LelantusStatus> lelantusStatus)
{
    std::vector<unsigned char> payload;
    uint16_t messageType = ELYSIUM_TYPE_CREATE_PROPERTY_MANUAL;
    uint16_t messageVer = lelantusStatus ? 2 : 0;

    elysium::swapByteOrder16(messageVer);
    elysium::swapByteOrder16(messageType);
    elysium::swapByteOrder16(propertyType);
    elysium::swapByteOrder32(previousPropertyId);

    if (category.size() > 255) category = category.substr(0,255);
    if (subcategory.size() > 255) subcategory = subcategory.substr(0,255);
    if (name.size() > 255) name = name.substr(0,255);
    if (url.size() > 255) url = url.substr(0,255);
    if (data.size() > 255) data = data.substr(0,255);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, ecosystem);
    PUSH_BACK_BYTES(payload, propertyType);
    PUSH_BACK_BYTES(payload, previousPropertyId);
    payload.insert(payload.end(), category.begin(), category.end());
    payload.push_back('\0');
    payload.insert(payload.end(), subcategory.begin(), subcategory.end());
    payload.push_back('\0');
    payload.insert(payload.end(), name.begin(), name.end());
    payload.push_back('\0');
    payload.insert(payload.end(), url.begin(), url.end());
    payload.push_back('\0');
    payload.insert(payload.end(), data.begin(), data.end());
    payload.push_back('\0');

    if (lelantusStatus) {
        PUSH_BACK_BYTES(payload, lelantusStatus.get());
    }

    return payload;
}

std::vector<unsigned char> CreatePayload_Grant(uint32_t propertyId, uint64_t amount, std::string memo)
{
	std::vector<unsigned char> payload;
	uint16_t messageType = ELYSIUM_TYPE_GRANT_PROPERTY_TOKENS;
	uint16_t messageVer = 0;
	elysium::swapByteOrder16(messageType);
	elysium::swapByteOrder16(messageVer);
	elysium::swapByteOrder32(propertyId);
	elysium::swapByteOrder64(amount);
	if (memo.size() > 255) memo = memo.substr(0, 255);

	PUSH_BACK_BYTES(payload, messageVer);
	PUSH_BACK_BYTES(payload, messageType);
	PUSH_BACK_BYTES(payload, propertyId);
	PUSH_BACK_BYTES(payload, amount);
	payload.insert(payload.end(), memo.begin(), memo.end());
	payload.push_back('\0');

	return payload;
}


std::vector<unsigned char> CreatePayload_Revoke(uint32_t propertyId, uint64_t amount, std::string memo)
{
    std::vector<unsigned char> payload;
    uint16_t messageType = ELYSIUM_TYPE_REVOKE_PROPERTY_TOKENS;
    uint16_t messageVer = 0;
    elysium::swapByteOrder16(messageType);
    elysium::swapByteOrder16(messageVer);
    elysium::swapByteOrder32(propertyId);
    elysium::swapByteOrder64(amount);
    if (memo.size() > 255) memo = memo.substr(0,255);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, propertyId);
    PUSH_BACK_BYTES(payload, amount);
    payload.insert(payload.end(), memo.begin(), memo.end());
    payload.push_back('\0');

    return payload;
}

std::vector<unsigned char> CreatePayload_ChangeIssuer(uint32_t propertyId)
{
    std::vector<unsigned char> payload;
    uint16_t messageType = ELYSIUM_TYPE_CHANGE_ISSUER_ADDRESS;
    uint16_t messageVer = 0;
    elysium::swapByteOrder16(messageType);
    elysium::swapByteOrder16(messageVer);
    elysium::swapByteOrder32(propertyId);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, propertyId);

    return payload;
}

std::vector<unsigned char> CreatePayload_EnableFreezing(uint32_t propertyId)
{
    std::vector<unsigned char> payload;
    uint16_t messageType = ELYSIUM_TYPE_ENABLE_FREEZING;
    uint16_t messageVer = 0;
    elysium::swapByteOrder16(messageType);
    elysium::swapByteOrder16(messageVer);
    elysium::swapByteOrder32(propertyId);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, propertyId);

    return payload;
}

std::vector<unsigned char> CreatePayload_DisableFreezing(uint32_t propertyId)
{
    std::vector<unsigned char> payload;
    uint16_t messageType = ELYSIUM_TYPE_DISABLE_FREEZING;
    uint16_t messageVer = 0;
    elysium::swapByteOrder16(messageType);
    elysium::swapByteOrder16(messageVer);
    elysium::swapByteOrder32(propertyId);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, propertyId);

    return payload;
}

std::vector<unsigned char> CreatePayload_FreezeTokens(uint32_t propertyId, uint64_t amount, const std::string& address)
{
    std::vector<unsigned char> payload;
    uint16_t messageType = ELYSIUM_TYPE_FREEZE_PROPERTY_TOKENS;
    uint16_t messageVer = 0;
    elysium::swapByteOrder16(messageType);
    elysium::swapByteOrder16(messageVer);
    elysium::swapByteOrder32(propertyId);
    elysium::swapByteOrder64(amount);
    std::vector<unsigned char> addressBytes = AddressToBytes(address);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, propertyId);
    PUSH_BACK_BYTES(payload, amount);
    payload.insert(payload.end(), addressBytes.begin(), addressBytes.end());

    return payload;
}

std::vector<unsigned char> CreatePayload_UnfreezeTokens(uint32_t propertyId, uint64_t amount, const std::string& address)
{
    std::vector<unsigned char> payload;
    uint16_t messageType = ELYSIUM_TYPE_UNFREEZE_PROPERTY_TOKENS;
    uint16_t messageVer = 0;
    elysium::swapByteOrder16(messageType);
    elysium::swapByteOrder16(messageVer);
    elysium::swapByteOrder32(propertyId);
    elysium::swapByteOrder64(amount);
    std::vector<unsigned char> addressBytes = AddressToBytes(address);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, propertyId);
    PUSH_BACK_BYTES(payload, amount);
    payload.insert(payload.end(), addressBytes.begin(), addressBytes.end());

    return payload;
}

std::vector<unsigned char> CreatePayload_DeactivateFeature(uint16_t featureId)
{
    std::vector<unsigned char> payload;

    uint16_t messageVer = 65535;
    uint16_t messageType = ELYSIUM_MESSAGE_TYPE_DEACTIVATION;

    elysium::swapByteOrder16(messageVer);
    elysium::swapByteOrder16(messageType);
    elysium::swapByteOrder16(featureId);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, featureId);

    return payload;
}

std::vector<unsigned char> CreatePayload_ActivateFeature(uint16_t featureId, uint32_t activationBlock, uint32_t minClientVersion)
{
    std::vector<unsigned char> payload;

    uint16_t messageVer = 65535;
    uint16_t messageType = ELYSIUM_MESSAGE_TYPE_ACTIVATION;

    elysium::swapByteOrder16(messageVer);
    elysium::swapByteOrder16(messageType);
    elysium::swapByteOrder16(featureId);
    elysium::swapByteOrder32(activationBlock);
    elysium::swapByteOrder32(minClientVersion);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, featureId);
    PUSH_BACK_BYTES(payload, activationBlock);
    PUSH_BACK_BYTES(payload, minClientVersion);

    return payload;
}

std::vector<unsigned char> CreatePayload_ElysiumAlert(uint16_t alertType, uint32_t expiryValue, const std::string& alertMessage)
{
    std::vector<unsigned char> payload;
    uint16_t messageType = ELYSIUM_MESSAGE_TYPE_ALERT;
    uint16_t messageVer = 65535;

    elysium::swapByteOrder16(messageVer);
    elysium::swapByteOrder16(messageType);
    elysium::swapByteOrder16(alertType);
    elysium::swapByteOrder32(expiryValue);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, alertType);
    PUSH_BACK_BYTES(payload, expiryValue);
    payload.insert(payload.end(), alertMessage.begin(), alertMessage.end());
    payload.push_back('\0');

    return payload;
}

std::vector<unsigned char> CreatePayload_CreateLelantusMint(
    uint32_t propertyId, lelantus::PublicCoin const &pubcoin, elysium::MintEntryId const &id,
    uint64_t value,  std::vector<unsigned char> const &schnorrProof)
{
    if (schnorrProof.size() != 98) {
        throw std::invalid_argument("Schnorr proof size is invalid");
    }

    std::vector<unsigned char> payload;
    uint16_t messageVer = 0;
    uint16_t messageType = ELYSIUM_TYPE_LELANTUS_MINT;
    elysium::swapByteOrder(messageVer);
    elysium::swapByteOrder(messageType);
    elysium::swapByteOrder(propertyId);
    elysium::swapByteOrder(value);

    // Meta data
    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, propertyId);

    // Mint data
    CDataStream serialized(SER_NETWORK, CLIENT_VERSION);
    serialized << pubcoin;
    serialized << id;
    payload.insert(payload.end(), serialized.begin(), serialized.end());

    // Additional mint data
    PUSH_BACK_BYTES(payload, value);
    payload.insert(payload.end(), schnorrProof.begin(), schnorrProof.end());

    return payload;
}

std::vector<unsigned char> CreatePayload_CreateLelantusJoinSplit(
    uint32_t propertyId,
    uint64_t amount,
    lelantus::JoinSplit const &joinSplit,
    boost::optional<elysium::JoinSplitMint> const &mint)
{
    std::vector<unsigned char> payload;
    uint16_t messageVer = 0;
    uint16_t messageType = ELYSIUM_TYPE_LELANTUS_JOINSPLIT;
    elysium::swapByteOrder(messageVer);
    elysium::swapByteOrder(messageType);
    elysium::swapByteOrder(propertyId);

    // Meta data
    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, propertyId);

    // amount
    elysium::swapByteOrder(amount);
    PUSH_BACK_BYTES(payload, amount);

    // Mint data
    {
        CDataStream serialized(SER_NETWORK, CLIENT_VERSION);
        serialized << joinSplit;
        payload.insert(payload.end(), serialized.begin(), serialized.end());
    }

    // change
    if (mint.get_ptr() != nullptr) {
        CDataStream serialized(SER_NETWORK, CLIENT_VERSION);
        serialized << mint.get();
        payload.insert(payload.end(), serialized.begin(), serialized.end());
    }

    return payload;
}

std::vector<unsigned char> CreatePayload_ChangeLelantusStatus(uint32_t propertyId, elysium::LelantusStatus status)
{
    std::vector<unsigned char> payload;
    uint16_t messageType = ELYSIUM_TYPE_CHANGE_LELANTUS_STATUS;
    uint16_t messageVer = 0;
    elysium::swapByteOrder16(messageType);
    elysium::swapByteOrder16(messageVer);
    elysium::swapByteOrder32(propertyId);

    PUSH_BACK_BYTES(payload, messageVer);
    PUSH_BACK_BYTES(payload, messageType);
    PUSH_BACK_BYTES(payload, propertyId);
    PUSH_BACK_BYTES(payload, status);

    return payload;
}

#undef PUSH_BACK_BYTES
#undef PUSH_BACK_BYTES_PTR
