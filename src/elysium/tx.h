#ifndef FIRO_ELYSIUM_TX_H
#define FIRO_ELYSIUM_TX_H

class CMPMetaDEx;
class CMPOffer;
class CTransaction;

#include "ecdsa_signature.h"
#include "elysium.h"
#include "packetencoder.h"
#include "sp.h"
#include "lelantusprimitives.h"

#include <boost/iterator/transform_iterator.hpp>
#include <boost/optional.hpp>

#include "../uint256.h"
#include "../utilstrencodings.h"

#include <memory>
#include <string>
#include <vector>

#include <inttypes.h>

using elysium::strTransactionType;

enum TransactionType {
    ELYSIUM_TYPE_SIMPLE_SEND                 =  0,
    ELYSIUM_TYPE_RESTRICTED_SEND             =  2,
    ELYSIUM_TYPE_SEND_TO_OWNERS              =  3,
    ELYSIUM_TYPE_SEND_ALL                    =  4,
    ELYSIUM_TYPE_SAVINGS_MARK                = 10,
    ELYSIUM_TYPE_SAVINGS_COMPROMISED         = 11,
    ELYSIUM_TYPE_RATELIMITED_MARK            = 12,
    ELYSIUM_TYPE_AUTOMATIC_DISPENSARY        = 15,
    ELYSIUM_TYPE_NOTIFICATION                = 31,
    ELYSIUM_TYPE_CREATE_PROPERTY_FIXED       = 50,
    ELYSIUM_TYPE_CREATE_PROPERTY_VARIABLE    = 51,
    ELYSIUM_TYPE_CREATE_PROPERTY_MANUAL      = 54,
    ELYSIUM_TYPE_GRANT_PROPERTY_TOKENS       = 55,
    ELYSIUM_TYPE_REVOKE_PROPERTY_TOKENS      = 56,
    ELYSIUM_TYPE_CHANGE_ISSUER_ADDRESS       = 70,
    ELYSIUM_TYPE_ENABLE_FREEZING             = 71,
    ELYSIUM_TYPE_DISABLE_FREEZING            = 72,
    ELYSIUM_TYPE_FREEZE_PROPERTY_TOKENS      = 185,
    ELYSIUM_TYPE_UNFREEZE_PROPERTY_TOKENS    = 186,
    ELYSIUM_TYPE_LELANTUS_MINT               = 1027,
    ELYSIUM_TYPE_LELANTUS_JOINSPLIT          = 1028,
    ELYSIUM_TYPE_CHANGE_LELANTUS_STATUS      = 1029,
    ELYSIUM_MESSAGE_TYPE_DEACTIVATION        = 65533,
    ELYSIUM_MESSAGE_TYPE_ACTIVATION          = 65534,
    ELYSIUM_MESSAGE_TYPE_ALERT               = 65535
};

/** The class is responsible for transaction interpreting/parsing.
 *
 * It invokes other classes and methods: offers, accepts, tallies (balances).
 */
class CMPTransaction
{
private:
    uint256 txid;
    int block = -1;
    int64_t blockTime;  // internally nTime is still an "unsigned int"
    unsigned int tx_idx;  // tx # within the block, 0-based
    uint64_t tx_fee_paid;

    boost::optional<elysium::PacketClass> packetClass;

    std::string sender;
    std::string receiver;
    boost::optional<CAmount> referenceAmount;

    unsigned int type;
    unsigned short version; // = MP_TX_PKT_V0;

    // SimpleSend, SendToOwners, TradeOffer, MetaDEx, AcceptOfferBTC,
    // CreatePropertyFixed, CreatePropertyVariable, GrantTokens, RevokeTokens
    uint64_t nValue;
    uint64_t nNewValue;

    // SimpleSend, SendToOwners, TradeOffer, MetaDEx, AcceptOfferBTC,
    // CreatePropertyFixed, CreatePropertyVariable, CloseCrowdsale,
    // CreatePropertyMananged, GrantTokens, RevokeTokens, ChangeIssuer
    unsigned int property;

    // SendToOwners v1
    unsigned int distribution_property;

    // CreatePropertyFixed, CreatePropertyVariable, CreatePropertyMananged, MetaDEx, SendAll
    unsigned char ecosystem;

    // CreatePropertyFixed, CreatePropertyVariable, CreatePropertyMananged
    unsigned short prop_type;
    unsigned int prev_prop_id;
    char category[SP_STRING_FIELD_LEN];
    char subcategory[SP_STRING_FIELD_LEN];
    char name[SP_STRING_FIELD_LEN];
    char url[SP_STRING_FIELD_LEN];
    char data[SP_STRING_FIELD_LEN];

    // Alert
    uint16_t alert_type;
    uint32_t alert_expiry;
    char alert_text[SP_STRING_FIELD_LEN];

    // Activation
    uint16_t feature_id;
    uint32_t activation_block;
    uint32_t min_client_version;

    // Lelantus
    elysium::LelantusStatus lelantusStatus;
    boost::optional<lelantus::PublicCoin> lelantusMint;
    uint64_t lelantusMintValue;
    boost::optional<elysium::MintEntryId> lelantusId;
    std::vector<unsigned char> lelantusSchnorrProof;

    boost::optional<lelantus::JoinSplit> lelantusJoinSplit;
    uint64_t lelantusSpendAmount;
    boost::optional<elysium::JoinSplitMint> lelantusJoinSplitMint;

    // Indicates whether the transaction can be used to execute logic
    bool rpcOnly;

    /** Checks whether a pointer to the payload is past it's last position. */
    bool isOverrun(const unsigned char *p);

    /**
     * Payload parsing
     */
    bool interpret_TransactionType();
    bool interpret_SimpleSend();
    bool interpret_SendToOwners();
    bool interpret_SendAll();
    bool interpret_CreatePropertyFixed();
    bool interpret_CreatePropertyManaged();
    bool interpret_GrantTokens();
    bool interpret_RevokeTokens();
    bool interpret_ChangeIssuer();
    bool interpret_EnableFreezing();
    bool interpret_DisableFreezing();
    bool interpret_FreezeTokens();
    bool interpret_UnfreezeTokens();
    bool interpret_LelantusMint();
    bool interpret_LelantusJoinSplit();
    bool interpret_ChangeLelantusStatus();
    bool interpret_Activation();
    bool interpret_Deactivation();
    bool interpret_Alert();

    /**
     * Logic and "effects"
     */
    int logicMath_SimpleSend();
    int logicMath_SendToOwners();
    int logicMath_SendAll();
    int logicMath_CreatePropertyFixed();
    int logicMath_CreatePropertyManaged();
    int logicMath_GrantTokens();
    int logicMath_RevokeTokens();
    int logicMath_ChangeIssuer();
    int logicMath_EnableFreezing();
    int logicMath_DisableFreezing();
    int logicMath_FreezeTokens();
    int logicMath_UnfreezeTokens();
    int logicMath_Activation();
    int logicMath_Deactivation();
    int logicMath_Alert();


public:

    uint256 getHash() const { return txid; }
    int getBlock() const { return block; }
    const std::vector<unsigned char>& getRaw() const { return raw; }
    unsigned int getType() const { return type; }
    std::string getTypeString() const { return strTransactionType(getType()); }
    unsigned int getProperty() const { return property; }
    unsigned short getVersion() const { return version; }
    unsigned short getPropertyType() const { return prop_type; }
    uint64_t getFeePaid() const { return tx_fee_paid; }
    const std::string& getSender() const { return sender; }
    const std::string& getReceiver() const { return receiver; }
    const boost::optional<CAmount>& getReferenceAmount() const { return referenceAmount; }
    uint64_t getAmount() const { return nValue; }
    uint64_t getNewAmount() const { return nNewValue; }
    uint8_t getEcosystem() const { return ecosystem; }
    uint32_t getPreviousId() const { return prev_prop_id; }
    std::string getSPCategory() const { return category; }
    std::string getSPSubCategory() const { return subcategory; }
    std::string getSPName() const { return name; }
    std::string getSPUrl() const { return url; }
    std::string getSPData() const { return data; }
    bool isRpcOnly() const { return rpcOnly; }
    const boost::optional<elysium::PacketClass>& getPacketClass() const { return packetClass; }
    uint16_t getAlertType() const { return alert_type; }
    uint32_t getAlertExpiry() const { return alert_expiry; }
    std::string getAlertMessage() const { return alert_text; }
    uint16_t getFeatureId() const { return feature_id; }
    uint32_t getActivationBlock() const { return activation_block; }
    uint32_t getMinClientVersion() const { return min_client_version; }
    unsigned int getIndexInBlock() const { return tx_idx; }
    uint32_t getDistributionProperty() const { return distribution_property; }

    /** Lelantus */
    lelantus::PublicCoin getLelantusMint() const { return lelantusMint.get(); }
    uint64_t getLelantusMintValue() const { return lelantusMintValue; }
    elysium::MintEntryId getLelantusMintId() const { return lelantusId.get(); }
    std::vector<unsigned char> getLelantusSchnorrProof() const { return lelantusSchnorrProof; }
    elysium::LelantusStatus getLelantusStatus() const { return lelantusStatus; }

    lelantus::JoinSplit getLelantusJoinSplit() const { return lelantusJoinSplit.get(); };
    uint64_t getLelantusSpendAmount() const { return lelantusSpendAmount; }
    boost::optional<elysium::JoinSplitMint> getLelantusJoinSplitMint() const { return lelantusJoinSplitMint; }

    /** Creates a new CMPTransaction object. */
    CMPTransaction()
    {
        SetNull();
    }

    /** Resets and clears all values. */
    void SetNull()
    {
        txid.SetNull();
        block = -1;
        blockTime = 0;
        raw.clear();
        tx_idx = 0;
        tx_fee_paid = 0;
        packetClass = boost::none;
        sender.clear();
        receiver.clear();
        referenceAmount = boost::none;
        type = 0;
        version = 0;
        nValue = 0;
        nNewValue = 0;
        property = 0;
        ecosystem = 0;
        prop_type = 0;
        prev_prop_id = 0;
        memset(&category, 0, sizeof(category));
        memset(&subcategory, 0, sizeof(subcategory));
        memset(&name, 0, sizeof(name));
        memset(&url, 0, sizeof(url));
        memset(&data, 0, sizeof(data));
        alert_type = 0;
        alert_expiry = 0;
        memset(&alert_text, 0, sizeof(alert_text));
        rpcOnly = true;
        feature_id = 0;
        activation_block = 0;
        min_client_version = 0;
        distribution_property = 0;
        lelantusStatus = elysium::LelantusStatus::SoftDisabled;
    }

    /** Sets the given values. */
    void Set(const uint256& t, int b, unsigned int idx, int64_t bt)
    {
        txid = t;
        block = b;
        tx_idx = idx;
        blockTime = bt;
    }

    /** Sets the given values. */
    void Set(
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
        const boost::optional<CAmount>& referenceAmount);

    /** Parses the packet or payload. */
    bool interpret_Transaction();

    /** Interprets the payload and executes the logic. */
    int interpretPacket();

    /** Enables access of interpretPacket. */
    void unlockLogic() { rpcOnly = false; };

    /** Compares transaction objects based on block height and position within the block. */
    bool operator<(const CMPTransaction& other) const
    {
        if (block != other.block) return block > other.block;
        return tx_idx > other.tx_idx;
    }

private:
    bool CheckPropertyCreationFee();

private:
    std::vector<unsigned char> raw;
};

/** Parses a transaction and populates the CMPTransaction object. */
int ParseTransaction(const CTransaction& tx, int nBlock, unsigned int idx, CMPTransaction& mptx, unsigned int nTime=0);

#endif // FIRO_ELYSIUM_TX_H
