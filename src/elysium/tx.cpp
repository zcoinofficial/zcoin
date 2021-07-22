// Elysium Protocol transaction code

#include "elysium/tx.h"

#include "elysium/activation.h"
#include "elysium/convert.h"
#include "elysium/log.h"
#include "elysium/notifications.h"
#include "elysium/elysium.h"
#include "elysium/rules.h"
#include "elysium/sp.h"
#include "elysium/sto.h"
#include "elysium/utils.h"
#include "elysium/utilsbitcoin.h"
#include "elysium/version.h"

#include "amount.h"
#include "base58.h"
#include "validation.h"
#include "sync.h"
#include "utiltime.h"

#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>

#include <stdio.h>
#include <string.h>

#include <algorithm>
#include <utility>
#include <vector>

using boost::algorithm::token_compress_on;

using namespace elysium;

/** Returns a label for the given transaction type. */
std::string elysium::strTransactionType(uint16_t txType)
{
    switch (txType) {
        case ELYSIUM_TYPE_SIMPLE_SEND: return "Simple Send";
        case ELYSIUM_TYPE_RESTRICTED_SEND: return "Restricted Send";
        case ELYSIUM_TYPE_SEND_TO_OWNERS: return "Send To Owners";
        case ELYSIUM_TYPE_SEND_ALL: return "Send All";
        case ELYSIUM_TYPE_SAVINGS_MARK: return "Savings";
        case ELYSIUM_TYPE_SAVINGS_COMPROMISED: return "Savings COMPROMISED";
        case ELYSIUM_TYPE_RATELIMITED_MARK: return "Rate-Limiting";
        case ELYSIUM_TYPE_AUTOMATIC_DISPENSARY: return "Automatic Dispensary";
        case ELYSIUM_TYPE_CREATE_PROPERTY_FIXED: return "Create Property - Fixed";
        case ELYSIUM_TYPE_CREATE_PROPERTY_VARIABLE: return "Create Property - Variable";
        case ELYSIUM_TYPE_CREATE_PROPERTY_MANUAL: return "Create Property - Manual";
        case ELYSIUM_TYPE_GRANT_PROPERTY_TOKENS: return "Grant Property Tokens";
        case ELYSIUM_TYPE_REVOKE_PROPERTY_TOKENS: return "Revoke Property Tokens";
        case ELYSIUM_TYPE_CHANGE_ISSUER_ADDRESS: return "Change Issuer Address";
        case ELYSIUM_TYPE_ENABLE_FREEZING: return "Enable Freezing";
        case ELYSIUM_TYPE_DISABLE_FREEZING: return "Disable Freezing";
        case ELYSIUM_TYPE_FREEZE_PROPERTY_TOKENS: return "Freeze Property Tokens";
        case ELYSIUM_TYPE_UNFREEZE_PROPERTY_TOKENS: return "Unfreeze Property Tokens";
        case ELYSIUM_TYPE_NOTIFICATION: return "Notification";
        case ELYSIUM_MESSAGE_TYPE_ALERT: return "ALERT";
        case ELYSIUM_MESSAGE_TYPE_DEACTIVATION: return "Feature Deactivation";
        case ELYSIUM_MESSAGE_TYPE_ACTIVATION: return "Feature Activation";
        case ELYSIUM_TYPE_LELANTUS_MINT: return "Lelantus Mint";
        case ELYSIUM_TYPE_LELANTUS_JOINSPLIT: return "Lelantus JoinSplit";
        case ELYSIUM_TYPE_CHANGE_LELANTUS_STATUS: return "Change Lelantus Status";

        default: return "* unknown type *";
    }
}

void CMPTransaction::Set(
    const std::string& s,
    const std::string& r,
    uint64_t n,
    const uint256& t,
    int b,
    unsigned int idx,
    unsigned char *p,
    unsigned int size,
    const boost::optional<elysium::PacketClass>& packetClass,
    uint64_t txf,
    const boost::optional<CAmount>& referenceAmount)
{
    sender = s;
    receiver = r;
    txid = t;
    block = b;
    tx_idx = idx;
    nValue = n;
    nNewValue = n;
    this->packetClass = packetClass;
    tx_fee_paid = txf;
    raw.clear();
    raw.insert(raw.end(), p, p + size);
    this->referenceAmount = referenceAmount;
}

/** Checks whether a pointer to the payload is past it's last position. */
bool CMPTransaction::isOverrun(const unsigned char *p)
{
    ptrdiff_t pos = p - raw.data();
    assert(pos >= 0);
    return (static_cast<size_t>(pos) > raw.size());
}

// -------------------- PACKET PARSING -----------------------

/** Parses the packet or payload. */
bool CMPTransaction::interpret_Transaction()
{
    if (!interpret_TransactionType()) {
        PrintToLog("Failed to interpret type and version\n");
        return false;
    }

    switch (type) {
        case ELYSIUM_TYPE_SIMPLE_SEND:
            return interpret_SimpleSend();

        case ELYSIUM_TYPE_SEND_TO_OWNERS:
            return interpret_SendToOwners();

        case ELYSIUM_TYPE_SEND_ALL:
            return interpret_SendAll();

        case ELYSIUM_TYPE_CREATE_PROPERTY_FIXED:
            return interpret_CreatePropertyFixed();

        case ELYSIUM_TYPE_CREATE_PROPERTY_MANUAL:
            return interpret_CreatePropertyManaged();

        case ELYSIUM_TYPE_GRANT_PROPERTY_TOKENS:
            return interpret_GrantTokens();

        case ELYSIUM_TYPE_REVOKE_PROPERTY_TOKENS:
            return interpret_RevokeTokens();

        case ELYSIUM_TYPE_CHANGE_ISSUER_ADDRESS:
            return interpret_ChangeIssuer();

        case ELYSIUM_TYPE_ENABLE_FREEZING:
            return interpret_EnableFreezing();

        case ELYSIUM_TYPE_DISABLE_FREEZING:
            return interpret_DisableFreezing();

        case ELYSIUM_TYPE_FREEZE_PROPERTY_TOKENS:
            return interpret_FreezeTokens();

        case ELYSIUM_TYPE_UNFREEZE_PROPERTY_TOKENS:
            return interpret_UnfreezeTokens();

        case ELYSIUM_TYPE_LELANTUS_MINT:
            return interpret_LelantusMint();

        case ELYSIUM_TYPE_LELANTUS_JOINSPLIT:
            return interpret_LelantusJoinSplit();

        case ELYSIUM_TYPE_CHANGE_LELANTUS_STATUS:
            return interpret_ChangeLelantusStatus();

        case ELYSIUM_MESSAGE_TYPE_DEACTIVATION:
            return interpret_Deactivation();

        case ELYSIUM_MESSAGE_TYPE_ACTIVATION:
            return interpret_Activation();

        case ELYSIUM_MESSAGE_TYPE_ALERT:
            return interpret_Alert();
    }

    return false;
}

/** Version and type */
bool CMPTransaction::interpret_TransactionType()
{
    if (raw.size() < 4) {
        return false;
    }
    uint16_t txVersion = 0;
    uint16_t txType = 0;
    memcpy(&txVersion, &raw[0], 2);
    swapByteOrder16(txVersion);
    memcpy(&txType, &raw[2], 2);
    swapByteOrder16(txType);
    version = txVersion;
    type = txType;

    if ((!rpcOnly && elysium_debug_packets) || elysium_debug_packets_readonly) {
        PrintToLog("\t------------------------------\n");
        PrintToLog("\t         version: %d, class %s\n", txVersion, std::to_string(*packetClass));
        PrintToLog("\t            type: %d (%s)\n", txType, strTransactionType(txType));
    }

    return true;
}

/** Tx 1 */
bool CMPTransaction::interpret_SimpleSend()
{
    if (raw.size() < 16) {
        return false;
    }
    memcpy(&property, &raw[4], 4);
    swapByteOrder32(property);
    memcpy(&nValue, &raw[8], 8);
    swapByteOrder64(nValue);
    nNewValue = nValue;

    if ((!rpcOnly && elysium_debug_packets) || elysium_debug_packets_readonly) {
        PrintToLog("\t        property: %d (%s)\n", property, strMPProperty(property));
        PrintToLog("\t           value: %s\n", FormatMP(property, nValue));
    }

    return true;
}

/** Tx 3 */
bool CMPTransaction::interpret_SendToOwners()
{
    unsigned expectedSize = (version == MP_TX_PKT_V0) ? 16 : 20;
    if (raw.size() < expectedSize) {
        return false;
    }
    memcpy(&property, &raw[4], 4);
    swapByteOrder32(property);
    memcpy(&nValue, &raw[8], 8);
    swapByteOrder64(nValue);
    nNewValue = nValue;
    if (version > MP_TX_PKT_V0) {
        memcpy(&distribution_property, &raw[16], 4);
        swapByteOrder32(distribution_property);
    }

    if ((!rpcOnly && elysium_debug_packets) || elysium_debug_packets_readonly) {
        PrintToLog("\t             property: %d (%s)\n", property, strMPProperty(property));
        PrintToLog("\t                value: %s\n", FormatMP(property, nValue));
        if (version > MP_TX_PKT_V1) {
            PrintToLog("\t distributionproperty: %d (%s)\n", distribution_property, strMPProperty(distribution_property));
        }
    }

    return true;
}

/** Tx 4 */
bool CMPTransaction::interpret_SendAll()
{
    if (raw.size() < 5) {
        return false;
    }
    memcpy(&ecosystem, &raw[4], 1);

    property = ecosystem; // provide a hint for the UI, TODO: better handling!

    if ((!rpcOnly && elysium_debug_packets) || elysium_debug_packets_readonly) {
        PrintToLog("\t       ecosystem: %d\n", (int)ecosystem);
    }

    return true;
}

/** Tx 50 */
bool CMPTransaction::interpret_CreatePropertyFixed()
{
    switch (version) {
    case 0:
        if (raw.size() < 25) {
            return false;
        }
        break;
    case 1:
        if (raw.size() < 26) {
            return false;
        }
        break;
    case 2:
        if (raw.size() < 27) {
            return false;
        }
        break;
    default:
        return false;
    }

    auto p = raw.data() + 11;
    auto end = raw.data() + raw.size();
    std::vector<std::string> spstr;
    memcpy(&ecosystem, &raw[4], 1);
    memcpy(&prop_type, &raw[5], 2);
    swapByteOrder16(prop_type);
    memcpy(&prev_prop_id, &raw[7], 4);
    swapByteOrder32(prev_prop_id);
    for (int i = 0; i < 5; i++) {
        auto last = std::find(p, end, 0);
        if (last == end) {
            return false;
        }
        spstr.push_back(std::string(p, last));
        p += spstr.back().size() + 1;
    }
    int i = 0;
    memcpy(category, spstr[i].c_str(), std::min(spstr[i].length(), sizeof(category)-1)); i++;
    memcpy(subcategory, spstr[i].c_str(), std::min(spstr[i].length(), sizeof(subcategory)-1)); i++;
    memcpy(name, spstr[i].c_str(), std::min(spstr[i].length(), sizeof(name)-1)); i++;
    memcpy(url, spstr[i].c_str(), std::min(spstr[i].length(), sizeof(url)-1)); i++;
    memcpy(data, spstr[i].c_str(), std::min(spstr[i].length(), sizeof(data)-1)); i++;
    memcpy(&nValue, p, 8);
    swapByteOrder64(nValue);
    p += 8;
    nNewValue = nValue;

    if (version >= 2) {
        memcpy(&lelantusStatus, p, 1);
        p += 1;
    }

    if ((!rpcOnly && elysium_debug_packets) || elysium_debug_packets_readonly) {
        PrintToLog("\t       ecosystem: %d\n", ecosystem);
        PrintToLog("\t   property type: %d (%s)\n", prop_type, strPropertyType(prop_type));
        PrintToLog("\tprev property id: %d\n", prev_prop_id);
        PrintToLog("\t        category: %s\n", category);
        PrintToLog("\t     subcategory: %s\n", subcategory);
        PrintToLog("\t            name: %s\n", name);
        PrintToLog("\t             url: %s\n", url);
        PrintToLog("\t            data: %s\n", data);
        PrintToLog("\t           value: %s\n", FormatByType(nValue, prop_type));
        PrintToLog("\t lelantus status: %u\n", static_cast<uint8_t>(lelantusStatus));
    }

    if (isOverrun(p)) {
        PrintToLog("%s(): rejected: malformed string value(s)\n", __func__);
        return false;
    }

    return true;
}

/** Tx 54 */
bool CMPTransaction::interpret_CreatePropertyManaged()
{
    switch (version) {
    case 0:
        if (raw.size() < 17) {
            return false;
        }
        break;
    case 1:
        if (raw.size() < 18) {
            return false;
        }
        break;
    case 2:
        if (raw.size() < 19) {
            return false;
        }
        break;
    default:
        return false;
    }

    auto p = raw.data() + 11;
    auto end = raw.data() + raw.size();
    std::vector<std::string> spstr;
    memcpy(&ecosystem, &raw[4], 1);
    memcpy(&prop_type, &raw[5], 2);
    swapByteOrder16(prop_type);
    memcpy(&prev_prop_id, &raw[7], 4);
    swapByteOrder32(prev_prop_id);
    for (int i = 0; i < 5; i++) {
        auto last = std::find(p, end, 0);
        if (last == end) {
            return false;
        }
        spstr.push_back(std::string(p, last));
        p += spstr.back().size() + 1;
    }
    int i = 0;
    memcpy(category, spstr[i].c_str(), std::min(spstr[i].length(), sizeof(category)-1)); i++;
    memcpy(subcategory, spstr[i].c_str(), std::min(spstr[i].length(), sizeof(subcategory)-1)); i++;
    memcpy(name, spstr[i].c_str(), std::min(spstr[i].length(), sizeof(name)-1)); i++;
    memcpy(url, spstr[i].c_str(), std::min(spstr[i].length(), sizeof(url)-1)); i++;
    memcpy(data, spstr[i].c_str(), std::min(spstr[i].length(), sizeof(data)-1)); i++;

    if (version >= 2) {
        memcpy(&lelantusStatus, p, 1);
        p += 1;
    }

    if ((!rpcOnly && elysium_debug_packets) || elysium_debug_packets_readonly) {
        PrintToLog("\t       ecosystem: %d\n", ecosystem);
        PrintToLog("\t   property type: %d (%s)\n", prop_type, strPropertyType(prop_type));
        PrintToLog("\tprev property id: %d\n", prev_prop_id);
        PrintToLog("\t        category: %s\n", category);
        PrintToLog("\t     subcategory: %s\n", subcategory);
        PrintToLog("\t            name: %s\n", name);
        PrintToLog("\t             url: %s\n", url);
        PrintToLog("\t            data: %s\n", data);
        PrintToLog("\t lelantus status: %u\n", static_cast<uint8_t>(lelantusStatus));
    }

    if (isOverrun(p)) {
        PrintToLog("%s(): rejected: malformed string value(s)\n", __func__);
        return false;
    }

    return true;
}

/** Tx 55 */
bool CMPTransaction::interpret_GrantTokens()
{
    if (raw.size() < 16) {
        return false;
    }
    memcpy(&property, &raw[4], 4);
    swapByteOrder32(property);
    memcpy(&nValue, &raw[8], 8);
    swapByteOrder64(nValue);
    nNewValue = nValue;

    if ((!rpcOnly && elysium_debug_packets) || elysium_debug_packets_readonly) {
        PrintToLog("\t        property: %d (%s)\n", property, strMPProperty(property));
        PrintToLog("\t           value: %s\n", FormatMP(property, nValue));
    }

    return true;
}

/** Tx 56 */
bool CMPTransaction::interpret_RevokeTokens()
{
    if (raw.size() < 16) {
        return false;
    }
    memcpy(&property, &raw[4], 4);
    swapByteOrder32(property);
    memcpy(&nValue, &raw[8], 8);
    swapByteOrder64(nValue);
    nNewValue = nValue;

    if ((!rpcOnly && elysium_debug_packets) || elysium_debug_packets_readonly) {
        PrintToLog("\t        property: %d (%s)\n", property, strMPProperty(property));
        PrintToLog("\t           value: %s\n", FormatMP(property, nValue));
    }

    return true;
}

/** Tx 70 */
bool CMPTransaction::interpret_ChangeIssuer()
{
    if (raw.size() < 8) {
        return false;
    }
    memcpy(&property, &raw[4], 4);
    swapByteOrder32(property);

    if ((!rpcOnly && elysium_debug_packets) || elysium_debug_packets_readonly) {
        PrintToLog("\t        property: %d (%s)\n", property, strMPProperty(property));
    }

    return true;
}

/** Tx 71 */
bool CMPTransaction::interpret_EnableFreezing()
{
    if (raw.size() < 8) {
        return false;
    }
    memcpy(&property, &raw[4], 4);
    swapByteOrder32(property);

    if ((!rpcOnly && elysium_debug_packets) || elysium_debug_packets_readonly) {
        PrintToLog("\t        property: %d (%s)\n", property, strMPProperty(property));
    }

    return true;
}

/** Tx 72 */
bool CMPTransaction::interpret_DisableFreezing()
{
    if (raw.size() < 8) {
        return false;
    }
    memcpy(&property, &raw[4], 4);
    swapByteOrder32(property);

    if ((!rpcOnly && elysium_debug_packets) || elysium_debug_packets_readonly) {
        PrintToLog("\t        property: %d (%s)\n", property, strMPProperty(property));
    }

    return true;
}

/** Tx 185 */
bool CMPTransaction::interpret_FreezeTokens()
{
    if (raw.size() < 37) {
        return false;
    }
    memcpy(&property, &raw[4], 4);
    swapByteOrder32(property);
    memcpy(&nValue, &raw[8], 8);
    swapByteOrder64(nValue);
    nNewValue = nValue;

    /**
        Note, TX185 is a virtual reference transaction type.
              With virtual reference transactions a hash160 in the payload sets the receiver.
              Reference outputs are ignored.
    **/
    unsigned char address_version;
    uint160 address_hash160;
    memcpy(&address_version, &raw[16], 1);
    memcpy(&address_hash160, &raw[17], 20);
    receiver = HashToAddress(address_version, address_hash160);
    if (receiver.empty()) {
        return false;
    }
    CBitcoinAddress recAddress(receiver);
    if (!recAddress.IsValid()) {
        return false;
    }

    if ((!rpcOnly && elysium_debug_packets) || elysium_debug_packets_readonly) {
        PrintToLog("\t        property: %d (%s)\n", property, strMPProperty(property));
        PrintToLog("\t  value (unused): %s\n", FormatMP(property, nValue));
        PrintToLog("\t         address: %s\n", receiver);
    }

    return true;
}

/** Tx 186 */
bool CMPTransaction::interpret_UnfreezeTokens()
{
    if (raw.size() < 37) {
        return false;
    }
    memcpy(&property, &raw[4], 4);
    swapByteOrder32(property);
    memcpy(&nValue, &raw[8], 8);
    swapByteOrder64(nValue);
    nNewValue = nValue;

    /**
        Note, TX186 virtual reference transaction type.
              With virtual reference transactions a hash160 in the payload sets the receiver.
              Reference outputs are ignored.
    **/
    unsigned char address_version;
    uint160 address_hash160;
    memcpy(&address_version, &raw[16], 1);
    memcpy(&address_hash160, &raw[17], 20);
    receiver = HashToAddress(address_version, address_hash160);
    if (receiver.empty()) {
        return false;
    }
    CBitcoinAddress recAddress(receiver);
    if (!recAddress.IsValid()) {
        return false;
    }

    if ((!rpcOnly && elysium_debug_packets) || elysium_debug_packets_readonly) {
        PrintToLog("\t        property: %d (%s)\n", property, strMPProperty(property));
        PrintToLog("\t  value (unused): %s\n", FormatMP(property, nValue));
        PrintToLog("\t         address: %s\n", receiver);
    }

    return true;
}

/** Tx 1027 */
bool CMPTransaction::interpret_LelantusMint()
{
    constexpr unsigned ElysiumMintSize = 34,
        IdSize = 32,
        SchnorrProofSize = 98;

    if (raw.size() != 16 + ElysiumMintSize + IdSize + SchnorrProofSize) {
        return false;
    }

    memcpy(&property, &raw[4], 4);
    swapByteOrder(property);

    CDataStream deserialized(
        reinterpret_cast<char*>(&raw[8]),
        reinterpret_cast<char*>(&raw[8] + ElysiumMintSize + IdSize),
        SER_NETWORK, CLIENT_VERSION
    );

    lelantusMint = lelantus::PublicCoin();
    lelantusId = MintEntryId();

    deserialized >> lelantusMint.get();
    deserialized >> lelantusId.get();

    memcpy(&lelantusMintValue, &raw[8 + ElysiumMintSize + IdSize], 8);
    swapByteOrder(lelantusMintValue);

    lelantusSchnorrProof.insert(lelantusSchnorrProof.end(),
        raw.begin() + 8 + ElysiumMintSize + IdSize + 8, raw.end());

    if ((!rpcOnly && elysium_debug_packets) || elysium_debug_packets_readonly) {
        PrintToLog("\t        property: %d (%s)\n", property, strMPProperty(property));
        PrintToLog("\t           mints: %d\n", FormatShortMP(property, lelantusMintValue));
    }

    return true;
}

/** Tx 1028 */
bool CMPTransaction::interpret_LelantusJoinSplit()
{
    PrintToLog("=== %s(): interpreting: calling...\n", __func__);
    if (raw.size() < 8) {
        return false;
    }

    memcpy(&property, &raw[4], 4);
    memcpy(&lelantusSpendAmount, &raw[8], 8);
    swapByteOrder(property);
    swapByteOrder(lelantusSpendAmount);

    CDataStream deserialized(
        reinterpret_cast<char*>(&raw[16]),
        reinterpret_cast<char*>(&raw[raw.size()]),
        SER_NETWORK, CLIENT_VERSION
    );

    lelantusJoinSplit = lelantus::JoinSplit(lelantus::Params::get_elysium(), deserialized);

    if (!deserialized.eof()) {
        lelantusJoinSplitMint = JoinSplitMint();
        deserialized >> lelantusJoinSplitMint.get();
    }

    if ((!rpcOnly && elysium_debug_packets) || elysium_debug_packets_readonly) {
        PrintToLog("\t        property: %d (%s)\n", property, strMPProperty(property));
        PrintToLog("\t           value: %s\n", FormatMP(property, lelantusSpendAmount));
    }

    return true;
}

/** Tx 1029 */
bool CMPTransaction::interpret_ChangeLelantusStatus()
{
    if (raw.size() < 9) {
        return false;
    }
    memcpy(&property, &raw[4], 4);
    swapByteOrder32(property);
    memcpy(&lelantusStatus, &raw[8], 1);

    if ((!rpcOnly && elysium_debug_packets) || elysium_debug_packets_readonly) {
        PrintToLog("\t        property: %d (%s)\n", property, strMPProperty(property));
    }

    return true;
}

/** Tx 65533 */
bool CMPTransaction::interpret_Deactivation()
{
    if (raw.size() < 6) {
        return false;
    }
    memcpy(&feature_id, &raw[4], 2);
    swapByteOrder16(feature_id);

    if ((!rpcOnly && elysium_debug_packets) || elysium_debug_packets_readonly) {
        PrintToLog("\t      feature id: %d\n", feature_id);
    }

    return true;
}

/** Tx 65534 */
bool CMPTransaction::interpret_Activation()
{
    if (raw.size() < 14) {
        return false;
    }
    memcpy(&feature_id, &raw[4], 2);
    swapByteOrder16(feature_id);
    memcpy(&activation_block, &raw[6], 4);
    swapByteOrder32(activation_block);
    memcpy(&min_client_version, &raw[10], 4);
    swapByteOrder32(min_client_version);

    if ((!rpcOnly && elysium_debug_packets) || elysium_debug_packets_readonly) {
        PrintToLog("\t      feature id: %d\n", feature_id);
        PrintToLog("\tactivation block: %d\n", activation_block);
        PrintToLog("\t minimum version: %d\n", min_client_version);
    }

    return true;
}

/** Tx 65535 */
bool CMPTransaction::interpret_Alert()
{
    if (raw.size() < 11) {
        return false;
    }

    memcpy(&alert_type, &raw[4], 2);
    swapByteOrder16(alert_type);
    memcpy(&alert_expiry, &raw[6], 4);
    swapByteOrder32(alert_expiry);

    auto p = raw.data() + 10;
    auto end = raw.data() + raw.size();
    auto last = std::find(p, end, 0);
    if (last == end) {
        return false;
    }
    std::string spstr(p, last);
    memcpy(alert_text, spstr.c_str(), std::min(spstr.length(), sizeof(alert_text)-1));

    if ((!rpcOnly && elysium_debug_packets) || elysium_debug_packets_readonly) {
        PrintToLog("\t      alert type: %d\n", alert_type);
        PrintToLog("\t    expiry value: %d\n", alert_expiry);
        PrintToLog("\t   alert message: %s\n", alert_text);
    }

    if (isOverrun(p)) {
        PrintToLog("%s(): rejected: malformed string value(s)\n", __func__);
        return false;
    }

    return true;
}

// ---------------------- CORE LOGIC -------------------------

/**
 * Interprets the payload and executes the logic.
 *
 * @return  0  if the transaction is fully valid
 *         <0  if the transaction is invalid
 */
int CMPTransaction::interpretPacket()
{
    if (rpcOnly) {
        PrintToLog("%s(): ERROR: attempt to execute logic in RPC mode\n", __func__);
        return (PKT_ERROR -1);
    }

    if (!interpret_Transaction()) {
        return (PKT_ERROR -2);
    }

    LOCK(cs_main);

    if (isAddressFrozen(sender, property)) {
        PrintToLog("%s(): REJECTED: address %s is frozen for property %d\n", __func__, sender, property);
        return (PKT_ERROR -3);
    }

    int status;
    switch (type) {
        case ELYSIUM_TYPE_SIMPLE_SEND:
            status = logicMath_SimpleSend();
            break;

        case ELYSIUM_TYPE_SEND_TO_OWNERS:
            status = logicMath_SendToOwners();
            break;

        case ELYSIUM_TYPE_SEND_ALL:
            status = logicMath_SendAll();
            break;        

        case ELYSIUM_TYPE_CREATE_PROPERTY_FIXED:
            status = logicMath_CreatePropertyFixed();
            break;

        case ELYSIUM_TYPE_CREATE_PROPERTY_MANUAL:
            status = logicMath_CreatePropertyManaged();
            break;

        case ELYSIUM_TYPE_GRANT_PROPERTY_TOKENS:
            status = logicMath_GrantTokens();
            break;

        case ELYSIUM_TYPE_REVOKE_PROPERTY_TOKENS:
            status = logicMath_RevokeTokens();
            break;

        case ELYSIUM_TYPE_CHANGE_ISSUER_ADDRESS:
            status = logicMath_ChangeIssuer();
            break;

        case ELYSIUM_TYPE_ENABLE_FREEZING:
            status = logicMath_EnableFreezing();
            break;

        case ELYSIUM_TYPE_DISABLE_FREEZING:
            status = logicMath_DisableFreezing();
            break;

        case ELYSIUM_TYPE_FREEZE_PROPERTY_TOKENS:
            status = logicMath_FreezeTokens();
            break;

        case ELYSIUM_TYPE_UNFREEZE_PROPERTY_TOKENS:
            status = logicMath_UnfreezeTokens();
            break;

		case ELYSIUM_MESSAGE_TYPE_DEACTIVATION:
            status = logicMath_Deactivation();
            break;

        case ELYSIUM_MESSAGE_TYPE_ACTIVATION:
            status = logicMath_Activation();
            break;

        case ELYSIUM_MESSAGE_TYPE_ALERT:
            status = logicMath_Alert();
            break;

        default:
            return (PKT_ERROR -100);
    }

    return status;
}

/** Tx 0 */
int CMPTransaction::logicMath_SimpleSend()
{
    if (!IsTransactionTypeAllowed(block, property, type, version)) {
        PrintToLog("%s(): rejected: type %d or version %d not permitted for property %d at block %d\n",
                __func__,
                type,
                version,
                property,
                block);
        return (PKT_ERROR_SEND -22);
    }

    if (nValue <= 0 || MAX_INT_8_BYTES < nValue) {
        PrintToLog("%s(): rejected: value out of range or zero: %d", __func__, nValue);
        return (PKT_ERROR_SEND -23);
    }

    if (!IsPropertyIdValid(property)) {
        PrintToLog("%s(): rejected: property %d does not exist\n", __func__, property);
        return (PKT_ERROR_SEND -24);
    }

    int64_t nBalance = getMPbalance(sender, property, BALANCE);
    if (nBalance < (int64_t) nValue) {
        PrintToLog("%s(): rejected: sender %s has insufficient balance of property %d [%s < %s]\n",
                __func__,
                sender,
                property,
                FormatMP(property, nBalance),
                FormatMP(property, nValue));
        return (PKT_ERROR_SEND -25);
    }

    // ------------------------------------------

    // Special case: if can't find the receiver -- assume send to self!
    if (receiver.empty()) {
        receiver = sender;
    }

    // Move the tokens
    assert(update_tally_map(sender, property, -nValue, BALANCE));
    assert(update_tally_map(receiver, property, nValue, BALANCE));

    return 0;
}

/** Tx 3 */
int CMPTransaction::logicMath_SendToOwners()
{
    if (!IsTransactionTypeAllowed(block, property, type, version)) {
        PrintToLog("%s(): rejected: type %d or version %d not permitted for property %d at block %d\n",
                __func__,
                type,
                version,
                property,
                block);
        return (PKT_ERROR_STO -22);
    }

    if (nValue <= 0 || MAX_INT_8_BYTES < nValue) {
        PrintToLog("%s(): rejected: value out of range or zero: %d\n", __func__, nValue);
        return (PKT_ERROR_STO -23);
    }

    if (!IsPropertyIdValid(property)) {
        PrintToLog("%s(): rejected: property %d does not exist\n", __func__, property);
        return (PKT_ERROR_STO -24);
    }

    if (version > MP_TX_PKT_V0) {
        if (!IsPropertyIdValid(distribution_property)) {
            PrintToLog("%s(): rejected: distribution property %d does not exist\n", __func__, distribution_property);
            return (PKT_ERROR_STO -24);
        }
    }

    int64_t nBalance = getMPbalance(sender, property, BALANCE);
    if (nBalance < (int64_t) nValue) {
        PrintToLog("%s(): rejected: sender %s has insufficient balance of property %d [%s < %s]\n",
                __func__,
                sender,
                FormatMP(property, nBalance),
                FormatMP(property, nValue),
                property);
        return (PKT_ERROR_STO -25);
    }

    // ------------------------------------------

    uint32_t distributeTo = (version == MP_TX_PKT_V0) ? property : distribution_property;
    OwnerAddrType receiversSet = STO_GetReceivers(sender, distributeTo, nValue);
    uint64_t numberOfReceivers = receiversSet.size();

    // make sure we found some owners
    if (numberOfReceivers <= 0) {
        PrintToLog("%s(): rejected: no other owners of property %d [owners=%d <= 0]\n", __func__, distributeTo, numberOfReceivers);
        return (PKT_ERROR_STO -26);
    }

    // split up what was taken and distribute between all holders
    int64_t sent_so_far = 0;
    for (OwnerAddrType::reverse_iterator it = receiversSet.rbegin(); it != receiversSet.rend(); ++it) {
        const std::string& address = it->second;

        int64_t will_really_receive = it->first;
        sent_so_far += will_really_receive;

        // real execution of the loop
        assert(update_tally_map(sender, property, -will_really_receive, BALANCE));
        assert(update_tally_map(address, property, will_really_receive, BALANCE));

        // add to stodb
        s_stolistdb->recordSTOReceive(address, txid, block, property, will_really_receive);

        if (sent_so_far != (int64_t)nValue) {
            PrintToLog("sent_so_far= %14d, nValue= %14d, n_owners= %d\n", sent_so_far, nValue, numberOfReceivers);
        } else {
            PrintToLog("SendToOwners: DONE HERE\n");
        }
    }

    // sent_so_far must equal nValue here
    assert(sent_so_far == (int64_t)nValue);

    // Number of tokens has changed, update fee distribution thresholds
    // if (version == MP_TX_PKT_V0) NotifyTotalTokensChanged(ELYSIUM_PROPERTY_ELYSIUM, block); // fee was burned

    return 0;
}

/** Tx 4 */
int CMPTransaction::logicMath_SendAll()
{
    if (!IsTransactionTypeAllowed(block, ecosystem, type, version)) {
        PrintToLog("%s(): rejected: type %d or version %d not permitted for property %d at block %d\n",
                __func__,
                type,
                version,
                ecosystem,
                block);
        return (PKT_ERROR_SEND_ALL -22);
    }

    // ------------------------------------------

    // Special case: if can't find the receiver -- assume send to self!
    if (receiver.empty()) {
        receiver = sender;
    }

    CMPTally* ptally = getTally(sender);
    if (ptally == NULL) {
        PrintToLog("%s(): rejected: sender %s has no tokens to send\n", __func__, sender);
        return (PKT_ERROR_SEND_ALL -54);
    }

    uint32_t propertyId = ptally->init();
    int numberOfPropertiesSent = 0;

    while (0 != (propertyId = ptally->next())) {
        // only transfer tokens in the specified ecosystem
        if (ecosystem == ELYSIUM_PROPERTY_ELYSIUM && isTestEcosystemProperty(propertyId)) {
            continue;
        }
        if (ecosystem == ELYSIUM_PROPERTY_TELYSIUM && isMainEcosystemProperty(propertyId)) {
            continue;
        }

        // do not transfer tokens from a frozen property
        if (isAddressFrozen(sender, propertyId)) {
            PrintToLog("%s(): sender %s is frozen for property %d - the property will not be included in processing.\n", __func__, sender, propertyId);
            continue;
        }

        int64_t moneyAvailable = ptally->getMoney(propertyId, BALANCE);
        if (moneyAvailable > 0) {
            ++numberOfPropertiesSent;
            assert(update_tally_map(sender, propertyId, -moneyAvailable, BALANCE));
            assert(update_tally_map(receiver, propertyId, moneyAvailable, BALANCE));
            p_txlistdb->recordSendAllSubRecord(txid, numberOfPropertiesSent, propertyId, moneyAvailable);
        }
    }

    if (!numberOfPropertiesSent) {
        PrintToLog("%s(): rejected: sender %s has no tokens to send\n", __func__, sender);
        return (PKT_ERROR_SEND_ALL -55);
    }

    nNewValue = numberOfPropertiesSent;

    return 0;
}

/** Tx 50 */
int CMPTransaction::logicMath_CreatePropertyFixed()
{
    uint256 blockHash;
    {
        LOCK(cs_main);

        CBlockIndex* pindex = chainActive[block];
        if (pindex == NULL) {
            PrintToLog("%s(): ERROR: block %d not in the active chain\n", __func__, block);
            return (PKT_ERROR_SP -20);
        }
        blockHash = pindex->GetBlockHash();
    }

    if (ELYSIUM_PROPERTY_ELYSIUM != ecosystem && ELYSIUM_PROPERTY_TELYSIUM != ecosystem) {
        PrintToLog("%s(): rejected: invalid ecosystem: %d\n", __func__, (uint32_t) ecosystem);
        return (PKT_ERROR_SP -21);
    }

    if (!IsTransactionTypeAllowed(block, ecosystem, type, version)) {
        PrintToLog("%s(): rejected: type %d or version %d not permitted for property %d at block %d\n",
                __func__,
                type,
                version,
                property,
                block);
        return (PKT_ERROR_SP -22);
    }

    if (nValue <= 0 || MAX_INT_8_BYTES < nValue) {
        PrintToLog("%s(): rejected: value out of range or zero: %d\n", __func__, nValue);
        return (PKT_ERROR_SP -23);
    }

    if (ELYSIUM_PROPERTY_TYPE_INDIVISIBLE != prop_type && ELYSIUM_PROPERTY_TYPE_DIVISIBLE != prop_type) {
        PrintToLog("%s(): rejected: invalid property type: %d\n", __func__, prop_type);
        return (PKT_ERROR_SP -36);
    }

    if ('\0' == name[0]) {
        PrintToLog("%s(): rejected: property name must not be empty\n", __func__);
        return (PKT_ERROR_SP -37);
    }

    if (IsRequireCreationFee(ecosystem, block) && !CheckPropertyCreationFee()) {
        PrintToLog("%s(): rejected: not enough fee for property creation\n", __func__);
        return PKT_ERROR_SP - 105;
    }

    CMPSPInfo::Entry newSP;

    if (IsFeatureActivated(FEATURE_LELANTUS, block)) {
        if (!IsLelantusStatusValid(lelantusStatus)) {
            PrintToLog("%s(): rejected: lelantus status %u is not valid\n", __func__, static_cast<uint8_t>(lelantusStatus));
            return PKT_ERROR_SP - 900;
        }

        newSP.lelantusStatus = lelantusStatus;
    }

    // ------------------------------------------

    newSP.issuer = sender;
    newSP.txid = txid;
    newSP.prop_type = prop_type;
    newSP.num_tokens = nValue;
    newSP.category.assign(category);
    newSP.subcategory.assign(subcategory);
    newSP.name.assign(name);
    newSP.url.assign(url);
    newSP.data.assign(data);
    newSP.fixed = true;
    newSP.creation_block = blockHash;
    newSP.update_block = newSP.creation_block;

    const uint32_t propertyId = _my_sps->putSP(ecosystem, newSP);
    assert(propertyId > 0);
    assert(update_tally_map(sender, propertyId, nValue, BALANCE));

    // NotifyTotalTokensChanged(propertyId, block);

	LogPrintf("CREATED MANUAL PROPERTY id: %d admin: %s\n", propertyId, sender);

    return 0;
}

/** Tx 54 */
int CMPTransaction::logicMath_CreatePropertyManaged()
{
    uint256 blockHash;
    {
        LOCK(cs_main);

        CBlockIndex* pindex = chainActive[block];
        if (pindex == NULL) {
            PrintToLog("%s(): ERROR: block %d not in the active chain\n", __func__, block);
            return (PKT_ERROR_SP -20);
        }
        blockHash = pindex->GetBlockHash();
    }

    if (ELYSIUM_PROPERTY_ELYSIUM != ecosystem && ELYSIUM_PROPERTY_TELYSIUM != ecosystem) {
        PrintToLog("%s(): rejected: invalid ecosystem: %d\n", __func__, (uint32_t) ecosystem);
        return (PKT_ERROR_SP -21);
    }

    if (!IsTransactionTypeAllowed(block, ecosystem, type, version)) {
        PrintToLog("%s(): rejected: type %d or version %d not permitted for property %d at block %d\n",
                __func__,
                type,
                version,
                property,
                block);
        return (PKT_ERROR_SP -22);
    }

    if (ELYSIUM_PROPERTY_TYPE_INDIVISIBLE != prop_type && ELYSIUM_PROPERTY_TYPE_DIVISIBLE != prop_type) {
        PrintToLog("%s(): rejected: invalid property type: %d\n", __func__, prop_type);
        return (PKT_ERROR_SP -36);
    }

    if ('\0' == name[0]) {
        PrintToLog("%s(): rejected: property name must not be empty\n", __func__);
        return (PKT_ERROR_SP -37);
    }

    if (IsRequireCreationFee(ecosystem, block) && !CheckPropertyCreationFee()) {
        PrintToLog("%s(): rejected: not enough fee for property creation\n", __func__);
        return PKT_ERROR_SP - 105;
    }

    CMPSPInfo::Entry newSP;

    if (IsFeatureActivated(FEATURE_LELANTUS, block)) {
        if (!IsLelantusStatusValid(lelantusStatus)) {
            PrintToLog("%s(): rejected: lelantus status %u is not valid\n", __func__, static_cast<uint8_t>(lelantusStatus));
            return PKT_ERROR_SP - 900;
        }

        newSP.lelantusStatus = lelantusStatus;
    }

    // ------------------------------------------

    newSP.issuer = sender;
    newSP.txid = txid;
    newSP.prop_type = prop_type;
    newSP.category.assign(category);
    newSP.subcategory.assign(subcategory);
    newSP.name.assign(name);
    newSP.url.assign(url);
    newSP.data.assign(data);
    newSP.fixed = false;
    newSP.manual = true;
    newSP.creation_block = blockHash;
    newSP.update_block = newSP.creation_block;

    uint32_t propertyId = _my_sps->putSP(ecosystem, newSP);
    assert(propertyId > 0);

    PrintToLog("CREATED MANUAL PROPERTY id: %d admin: %s\n", propertyId, sender);

    return 0;
}

/** Tx 55 */
int CMPTransaction::logicMath_GrantTokens()
{
    uint256 blockHash;
    {
        LOCK(cs_main);

        CBlockIndex* pindex = chainActive[block];
        if (pindex == NULL) {
            PrintToLog("%s(): ERROR: block %d not in the active chain\n", __func__, block);
            return (PKT_ERROR_SP -20);
        }
        blockHash = pindex->GetBlockHash();
    }

    if (!IsTransactionTypeAllowed(block, property, type, version)) {
        PrintToLog("%s(): rejected: type %d or version %d not permitted for property %d at block %d\n",
                __func__,
                type,
                version,
                property,
                block);
        return (PKT_ERROR_TOKENS -22);
    }

    if (nValue <= 0 || MAX_INT_8_BYTES < nValue) {
        PrintToLog("%s(): rejected: value out of range or zero: %d\n", __func__, nValue);
        return (PKT_ERROR_TOKENS -23);
    }

    if (!IsPropertyIdValid(property)) {
        PrintToLog("%s(): rejected: property %d does not exist\n", __func__, property);
        return (PKT_ERROR_TOKENS -24);
    }

    CMPSPInfo::Entry sp;
    assert(_my_sps->getSP(property, sp));

    if (!sp.manual) {
        PrintToLog("%s(): rejected: property %d is not managed\n", __func__, property);
        return (PKT_ERROR_TOKENS -42);
    }

    if (sender != sp.issuer) {
        PrintToLog("%s(): rejected: sender %s is not issuer of property %d [issuer=%s]\n", __func__, sender, property, sp.issuer);
        return (PKT_ERROR_TOKENS -43);
    }

    int64_t nTotalTokens = getTotalTokens(property);
    if (nValue > (MAX_INT_8_BYTES - nTotalTokens)) {
        PrintToLog("%s(): rejected: no more than %s tokens can ever exist [%s + %s > %s]\n",
                __func__,
                FormatMP(property, MAX_INT_8_BYTES),
                FormatMP(property, nTotalTokens),
                FormatMP(property, nValue),
                FormatMP(property, MAX_INT_8_BYTES));
        return (PKT_ERROR_TOKENS -44);
    }

    // ------------------------------------------

    std::vector<int64_t> dataPt;
    dataPt.push_back(nValue);
    dataPt.push_back(0);
    sp.historicalData.insert(std::make_pair(txid, dataPt));
    sp.update_block = blockHash;

    // Persist the number of granted tokens
    assert(_my_sps->updateSP(property, sp));

    // Special case: if can't find the receiver -- assume grant to self!
    if (receiver.empty()) {
        receiver = sender;
    }

    // Move the tokens
    assert(update_tally_map(receiver, property, nValue, BALANCE));

    // NotifyTotalTokensChanged(property, block);

    return 0;
}

/** Tx 56 */
int CMPTransaction::logicMath_RevokeTokens()
{
    uint256 blockHash;
    {
        LOCK(cs_main);

        CBlockIndex* pindex = chainActive[block];
        if (pindex == NULL) {
            PrintToLog("%s(): ERROR: block %d not in the active chain\n", __func__, block);
            return (PKT_ERROR_TOKENS -20);
        }
        blockHash = pindex->GetBlockHash();
    }

    if (!IsTransactionTypeAllowed(block, property, type, version)) {
        PrintToLog("%s(): rejected: type %d or version %d not permitted for property %d at block %d\n",
                __func__,
                type,
                version,
                property,
                block);
        return (PKT_ERROR_TOKENS -22);
    }

    if (nValue <= 0 || MAX_INT_8_BYTES < nValue) {
        PrintToLog("%s(): rejected: value out of range or zero: %d\n", __func__, nValue);
        return (PKT_ERROR_TOKENS -23);
    }

    if (!IsPropertyIdValid(property)) {
        PrintToLog("%s(): rejected: property %d does not exist\n", __func__, property);
        return (PKT_ERROR_TOKENS -24);
    }

    CMPSPInfo::Entry sp;
    assert(_my_sps->getSP(property, sp));

    if (!sp.manual) {
        PrintToLog("%s(): rejected: property %d is not managed\n", __func__, property);
        return (PKT_ERROR_TOKENS -42);
    }

    int64_t nBalance = getMPbalance(sender, property, BALANCE);
    if (nBalance < (int64_t) nValue) {
        PrintToLog("%s(): rejected: sender %s has insufficient balance of property %d [%s < %s]\n",
                __func__,
                sender,
                property,
                FormatMP(property, nBalance),
                FormatMP(property, nValue));
        return (PKT_ERROR_TOKENS -25);
    }

    // ------------------------------------------

    std::vector<int64_t> dataPt;
    dataPt.push_back(0);
    dataPt.push_back(nValue);
    sp.historicalData.insert(std::make_pair(txid, dataPt));
    sp.update_block = blockHash;

    assert(update_tally_map(sender, property, -nValue, BALANCE));
    assert(_my_sps->updateSP(property, sp));

    // NotifyTotalTokensChanged(property, block);

    return 0;
}

/** Tx 70 */
int CMPTransaction::logicMath_ChangeIssuer()
{
    uint256 blockHash;
    {
        LOCK(cs_main);

        CBlockIndex* pindex = chainActive[block];
        if (pindex == NULL) {
            PrintToLog("%s(): ERROR: block %d not in the active chain\n", __func__, block);
            return (PKT_ERROR_TOKENS -20);
        }
        blockHash = pindex->GetBlockHash();
    }

    if (!IsTransactionTypeAllowed(block, property, type, version)) {
        PrintToLog("%s(): rejected: type %d or version %d not permitted for property %d at block %d\n",
                __func__,
                type,
                version,
                property,
                block);
        return (PKT_ERROR_TOKENS -22);
    }

    if (!IsPropertyIdValid(property)) {
        PrintToLog("%s(): rejected: property %d does not exist\n", __func__, property);
        return (PKT_ERROR_TOKENS -24);
    }

    CMPSPInfo::Entry sp;
    assert(_my_sps->getSP(property, sp));

    if (sender != sp.issuer) {
        PrintToLog("%s(): rejected: sender %s is not issuer of property %d [issuer=%s]\n", __func__, sender, property, sp.issuer);
        return (PKT_ERROR_TOKENS -43);
    }

    if (receiver.empty()) {
        PrintToLog("%s(): rejected: receiver is empty\n", __func__);
        return (PKT_ERROR_TOKENS -45);
    }

    // ------------------------------------------

    sp.issuer = receiver;
    sp.update_block = blockHash;

    assert(_my_sps->updateSP(property, sp));

    return 0;
}

/** Tx 71 */
int CMPTransaction::logicMath_EnableFreezing()
{
    uint256 blockHash;
    {
        LOCK(cs_main);

        CBlockIndex* pindex = chainActive[block];
        if (pindex == NULL) {
            PrintToLog("%s(): ERROR: block %d not in the active chain\n", __func__, block);
            return (PKT_ERROR_TOKENS -20);
        }
        blockHash = pindex->GetBlockHash();
    }

    if (!IsTransactionTypeAllowed(block, property, type, version)) {
        PrintToLog("%s(): rejected: type %d or version %d not permitted for property %d at block %d\n",
                __func__,
                type,
                version,
                property,
                block);
        return (PKT_ERROR_TOKENS -22);
    }

    if (!IsPropertyIdValid(property)) {
        PrintToLog("%s(): rejected: property %d does not exist\n", __func__, property);
        return (PKT_ERROR_TOKENS -24);
    }

    CMPSPInfo::Entry sp;
    assert(_my_sps->getSP(property, sp));

    if (!sp.manual) {
        PrintToLog("%s(): rejected: property %d is not managed\n", __func__, property);
        return (PKT_ERROR_TOKENS -42);
    }

    if (sender != sp.issuer) {
        PrintToLog("%s(): rejected: sender %s is not issuer of property %d [issuer=%s]\n", __func__, sender, property, sp.issuer);
        return (PKT_ERROR_TOKENS -43);
    }

    if (isFreezingEnabled(property, block)) {
        PrintToLog("%s(): rejected: freezing is already enabled for property %d\n", __func__, property);
        return (PKT_ERROR_TOKENS -49);
    }

    int liveBlock = 0;
    if (!IsFeatureActivated(FEATURE_FREEZENOTICE, block)) {
        liveBlock = block;
    } else {
        const CConsensusParams& params = ConsensusParams();
        liveBlock = params.ELYSIUM_FREEZE_WAIT_PERIOD + block;
    }

    enableFreezing(property, liveBlock);

    return 0;
}

/** Tx 72 */
int CMPTransaction::logicMath_DisableFreezing()
{
    uint256 blockHash;
    {
        LOCK(cs_main);

        CBlockIndex* pindex = chainActive[block];
        if (pindex == NULL) {
            PrintToLog("%s(): ERROR: block %d not in the active chain\n", __func__, block);
            return (PKT_ERROR_TOKENS -20);
        }
        blockHash = pindex->GetBlockHash();
    }

    if (!IsTransactionTypeAllowed(block, property, type, version)) {
        PrintToLog("%s(): rejected: type %d or version %d not permitted for property %d at block %d\n",
                __func__,
                type,
                version,
                property,
                block);
        return (PKT_ERROR_TOKENS -22);
    }

    if (!IsPropertyIdValid(property)) {
        PrintToLog("%s(): rejected: property %d does not exist\n", __func__, property);
        return (PKT_ERROR_TOKENS -24);
    }

    CMPSPInfo::Entry sp;
    assert(_my_sps->getSP(property, sp));

    if (!sp.manual) {
        PrintToLog("%s(): rejected: property %d is not managed\n", __func__, property);
        return (PKT_ERROR_TOKENS -42);
    }

    if (sender != sp.issuer) {
        PrintToLog("%s(): rejected: sender %s is not issuer of property %d [issuer=%s]\n", __func__, sender, property, sp.issuer);
        return (PKT_ERROR_TOKENS -43);
    }

    if (!isFreezingEnabled(property, block)) {
        PrintToLog("%s(): rejected: freezing is not enabled for property %d\n", __func__, property);
        return (PKT_ERROR_TOKENS -47);
    }

    disableFreezing(property);

    return 0;
}

/** Tx 185 */
int CMPTransaction::logicMath_FreezeTokens()
{
    uint256 blockHash;
    {
        LOCK(cs_main);

        CBlockIndex* pindex = chainActive[block];
        if (pindex == NULL) {
            PrintToLog("%s(): ERROR: block %d not in the active chain\n", __func__, block);
            return (PKT_ERROR_TOKENS -20);
        }
        blockHash = pindex->GetBlockHash();
    }

    if (!IsTransactionTypeAllowed(block, property, type, version)) {
        PrintToLog("%s(): rejected: type %d or version %d not permitted for property %d at block %d\n",
                __func__,
                type,
                version,
                property,
                block);
        return (PKT_ERROR_TOKENS -22);
    }

    if (!IsPropertyIdValid(property)) {
        PrintToLog("%s(): rejected: property %d does not exist\n", __func__, property);
        return (PKT_ERROR_TOKENS -24);
    }

    CMPSPInfo::Entry sp;
    assert(_my_sps->getSP(property, sp));

    if (!sp.manual) {
        PrintToLog("%s(): rejected: property %d is not managed\n", __func__, property);
        return (PKT_ERROR_TOKENS -42);
    }

    if (sender != sp.issuer) {
        PrintToLog("%s(): rejected: sender %s is not issuer of property %d [issuer=%s]\n", __func__, sender, property, sp.issuer);
        return (PKT_ERROR_TOKENS -43);
    }

    if (!isFreezingEnabled(property, block)) {
        PrintToLog("%s(): rejected: freezing is not enabled for property %d\n", __func__, property);
        return (PKT_ERROR_TOKENS -47);
    }

    if (isAddressFrozen(receiver, property)) {
        PrintToLog("%s(): rejected: address %s is already frozen for property %d\n", __func__, receiver, property);
        return (PKT_ERROR_TOKENS -50);
    }

    freezeAddress(receiver, property);

    return 0;
}

/** Tx 186 */
int CMPTransaction::logicMath_UnfreezeTokens()
{
    uint256 blockHash;
    {
        LOCK(cs_main);

        CBlockIndex* pindex = chainActive[block];
        if (pindex == NULL) {
            PrintToLog("%s(): ERROR: block %d not in the active chain\n", __func__, block);
            return (PKT_ERROR_TOKENS -20);
        }
        blockHash = pindex->GetBlockHash();
    }

    if (!IsTransactionTypeAllowed(block, property, type, version)) {
        PrintToLog("%s(): rejected: type %d or version %d not permitted for property %d at block %d\n",
                __func__,
                type,
                version,
                property,
                block);
        return (PKT_ERROR_TOKENS -22);
    }

    if (!IsPropertyIdValid(property)) {
        PrintToLog("%s(): rejected: property %d does not exist\n", __func__, property);
        return (PKT_ERROR_TOKENS -24);
    }

    CMPSPInfo::Entry sp;
    assert(_my_sps->getSP(property, sp));

    if (!sp.manual) {
        PrintToLog("%s(): rejected: property %d is not managed\n", __func__, property);
        return (PKT_ERROR_TOKENS -42);
    }

    if (sender != sp.issuer) {
        PrintToLog("%s(): rejected: sender %s is not issuer of property %d [issuer=%s]\n", __func__, sender, property, sp.issuer);
        return (PKT_ERROR_TOKENS -43);
    }

    if (!isFreezingEnabled(property, block)) {
        PrintToLog("%s(): rejected: freezing is not enabled for property %d\n", __func__, property);
        return (PKT_ERROR_TOKENS -47);
    }

    if (!isAddressFrozen(receiver, property)) {
        PrintToLog("%s(): rejected: address %s is not frozen for property %d\n", __func__, receiver, property);
        return (PKT_ERROR_TOKENS -48);
    }

    unfreezeAddress(receiver, property);

    return 0;
}

/** Tx 65533 */
int CMPTransaction::logicMath_Deactivation()
{
    if (!IsTransactionTypeAllowed(block, property, type, version)) {
        PrintToLog("%s(): rejected: type %d or version %d not permitted for property %d at block %d\n",
                __func__,
                type,
                version,
                property,
                block);
        return (PKT_ERROR -22);
    }

    // is sender authorized
    bool authorized = CheckDeactivationAuthorization(sender);

    PrintToLog("\t          sender: %s\n", sender);
    PrintToLog("\t      authorized: %s\n", authorized);

    if (!authorized) {
        PrintToLog("%s(): rejected: sender %s is not authorized to deactivate features\n", __func__, sender);
        return (PKT_ERROR -51);
    }

    // authorized, request feature deactivation
    bool DeactivationSuccess = DeactivateFeature(feature_id, block);

    if (!DeactivationSuccess) {
        PrintToLog("%s(): DeactivateFeature failed\n", __func__);
        return (PKT_ERROR -54);
    }

    return 0;
}

/** Tx 65534 */
int CMPTransaction::logicMath_Activation()
{
    if (!IsTransactionTypeAllowed(block, property, type, version)) {
        PrintToLog("%s(): rejected: type %d or version %d not permitted for property %d at block %d\n",
                __func__,
                type,
                version,
                property,
                block);
        return (PKT_ERROR -22);
    }

    // is sender authorized - temporarily use alert auths but ## TO BE MOVED TO FOUNDATION P2SH KEY ##
    bool authorized = CheckActivationAuthorization(sender);

    PrintToLog("\t          sender: %s\n", sender);
    PrintToLog("\t      authorized: %s\n", authorized);

    if (!authorized) {
        PrintToLog("%s(): rejected: sender %s is not authorized for feature activations\n", __func__, sender);
        return (PKT_ERROR -51);
    }

    // authorized, request feature activation
    bool activationSuccess = ActivateFeature(feature_id, activation_block, min_client_version, block);

    if (!activationSuccess) {
        PrintToLog("%s(): ActivateFeature failed to activate this feature\n", __func__);
        return (PKT_ERROR -54);
    }

    return 0;
}

/** Tx 65535 */
int CMPTransaction::logicMath_Alert()
{
    if (!IsTransactionTypeAllowed(block, property, type, version)) {
        PrintToLog("%s(): rejected: type %d or version %d not permitted for property %d at block %d\n",
                __func__,
                type,
                version,
                property,
                block);
        return (PKT_ERROR -22);
    }

    // is sender authorized?
    bool authorized = CheckAlertAuthorization(sender);

    PrintToLog("\t          sender: %s\n", sender);
    PrintToLog("\t      authorized: %s\n", authorized);

    if (!authorized) {
        PrintToLog("%s(): rejected: sender %s is not authorized for alerts\n", __func__, sender);
        return (PKT_ERROR -51);
    }

    if (alert_type == ALERT_CLIENT_VERSION_EXPIRY && ELYSIUM_VERSION < alert_expiry) {
        // regular alert keys CANNOT be used to force a client upgrade on mainnet - at least 3 signatures from board/devs are required
        if (sender == "a1kCCGddf5pMXSipLVD9hBG2MGGVNaJ15U" || isNonMainNet()) {
            std::string msgText = "Client upgrade is required!  Shutting down due to unsupported consensus state!";
            PrintToLog(msgText);
            if (!GetBoolArg("-overrideforcedshutdown", false)) {
                boost::filesystem::path persistPath = GetDataDir() / "MP_persist";
                if (boost::filesystem::exists(persistPath)) boost::filesystem::remove_all(persistPath); // prevent the node being restarted without a reparse after forced shutdown
                AbortNode(msgText, msgText);
            }
        }
    }

    if (alert_type == 65535) { // set alert type to FFFF to clear previously sent alerts
        DeleteAlerts(sender);
    } else {
        AddAlert(sender, alert_type, alert_expiry, alert_text);
    }

    // we have a new alert, fire a notify event if needed
    AlertNotify(alert_text);

    return 0;
}

bool CMPTransaction::CheckPropertyCreationFee()
{
    if (receiver.empty() || !referenceAmount) {
        return false;
    }

    auto& consensus = ConsensusParams();

    return receiver == consensus.PROPERTY_CREATION_FEE_RECEIVER.ToString() && *referenceAmount >= consensus.PROPERTY_CREATION_FEE;
}
