#ifndef FIRO_ELYSIUM_RULES_H
#define FIRO_ELYSIUM_RULES_H

#include "../amount.h"
#include "../base58.h"
#include "../uint256.h"

#include <string>
#include <vector>

#include <inttypes.h>

namespace elysium {

/**
 * Feature identifier to enable Class C transaction parsing and processing.
 **/
constexpr uint16_t FEATURE_CLASS_C = 1;

/**
 * Feature identifier to disable crowdsale participations when "granting tokens".
 **/
constexpr uint16_t FEATURE_GRANTEFFECTS = 4;

/**
 * Feature identifier to enable Send All transactions.
 **/
constexpr uint16_t FEATURE_SENDALL = 6;

/**
 * Feature identifier to enable the fee cache and strip 0.05% fees from non-Omni pairs.
 **/
constexpr uint16_t FEATURE_FEES = 9;

/**
 * Feature identifier to enable cross property (v1) Send To Owners.
 **/
constexpr uint16_t FEATURE_STOV1 = 10;

/**
 * Feature identifier to activate the waiting period for enabling managed property address freezing.
 **/
constexpr uint16_t FEATURE_FREEZENOTICE = 14;

/**
 * Feature identifier to activate lelantus on elysium.
 **/
constexpr uint16_t FEATURE_LELANTUS = 17;

/** A structure to represent transaction restrictions.
 */
struct TransactionRestriction
{
    //! Transaction type
    uint16_t txType;
    //! Transaction version
    uint16_t txVersion;
    //! Whether the property identifier can be 0 (= BTC)
    bool allowWildcard;
    //! Block after which the feature or transaction is enabled
    int activationBlock;
};

/** A structure to represent a verification checkpoint.
 */
struct ConsensusCheckpoint
{
    int blockHeight;
    uint256 blockHash;
    uint256 consensusHash;
};

// TODO: rename allcaps variable names
// TODO: remove remaining global heights
// TODO: add Elysium addresses to params

/**
 * Base class for consensus parameters.
 **/
class CConsensusParams
{
public:
    /**
     * First block of the Elysium feature.
     **/
    int GENESIS_BLOCK;

    /**
     * Minimum number of blocks to use for notice rules on activation.
     **/
    int MIN_ACTIVATION_BLOCKS;

    /**
     * Maximum number of blocks to use for notice rules on activation.
     **/
    int MAX_ACTIVATION_BLOCKS;

    /**
     * Waiting period after enabling freezing before addresses may be frozen.
     **/
    int ELYSIUM_FREEZE_WAIT_PERIOD;

    /**
     * Block to enable pay-to-pubkey-hash support.
     **/
    int PUBKEYHASH_BLOCK;

    /**
     * Block to enable pay-to-script-hash support.
     **/
    int SCRIPTHASH_BLOCK;

    /**
     * Block to enable OP_RETURN based encoding.
     **/
    int NULLDATA_BLOCK;

    /**
     * Block to enable alerts and notifications.
     **/
    int ELYSIUM_ALERT_BLOCK;

    /**
     * Block to enable simple send transactions.
     **/
    int ELYSIUM_SEND_BLOCK;

    /**
     * Block to enable DEx transactions.
     **/
    int ELYSIUM_DEX_BLOCK;

    /**
     * Block to enable smart property transactions.
     **/
    int ELYSIUM_SP_BLOCK;

    /**
     * Block to enable managed properties.
     **/
    int ELYSIUM_MANUALSP_BLOCK;

    /**
     * Block to enable send-to-owners transactions.
     **/
    int ELYSIUM_STO_BLOCK;

    /**
     * Block to enable "send all" transactions.
     **/
    int ELYSIUM_SEND_ALL_BLOCK;

    /**
     * Block to enable cross property STO (v1).
     **/
    int ELYSIUM_STOV1_BLOCK;

    /**
     * Block to deactivate crowdsale participations when "granting tokens".
     **/
    int GRANTEFFECTS_FEATURE_BLOCK;

    /**
     * Block to activate the waiting period for enabling managed property address freezing.
     **/
    int FREEZENOTICE_FEATURE_BLOCK;

    /**
     * Block to activate Lelantus related features.
     **/
    int LELANTUS_FEATURE_BLOCK;

    /**
     * Block to activate property creation fee.
     **/
    int PROPERTY_CREATION_FEE_BLOCK;

    /**
     * Amount of FIRO to pay when create a new property on main ecosystem.
     **/
    CAmount PROPERTY_CREATION_FEE;

    /**
     * The address to receive property creation fee.
     **/
    CBitcoinAddress PROPERTY_CREATION_FEE_RECEIVER;

    /**
     * Returns a mapping of transaction types, and the blocks at which they are enabled.
     **/
    virtual std::vector<TransactionRestriction> GetRestrictions() const;

    /**
     * Returns an empty vector of consensus checkpoints.
     **/
    virtual std::vector<ConsensusCheckpoint> GetCheckpoints() const;

    virtual ~CConsensusParams() {}

protected:
    CConsensusParams() {}
};

/** Consensus parameters for mainnet.
 */
class CMainConsensusParams: public CConsensusParams
{
public:
    /** Constructor for mainnet consensus parameters. */
    CMainConsensusParams();
    /** Destructor. */
    virtual ~CMainConsensusParams() {}
};

/** Consensus parameters for testnet.
 */
class CTestNetConsensusParams: public CConsensusParams
{
public:
    /** Constructor for testnet consensus parameters. */
    CTestNetConsensusParams();
    /** Destructor. */
    virtual ~CTestNetConsensusParams() {}
};

/** Consensus parameters for regtest mode.
 */
class CRegTestConsensusParams: public CConsensusParams
{
public:
    /** Constructor for regtest consensus parameters. */
    CRegTestConsensusParams();
    /** Destructor. */
    virtual ~CRegTestConsensusParams() {}
};

/** Returns consensus parameters for the given network. */
CConsensusParams& ConsensusParams(const std::string& network);
/** Returns currently active consensus parameter. */
const CConsensusParams& ConsensusParams();
/** Returns currently active mutable consensus parameter. */
CConsensusParams& MutableConsensusParams();
/** Resets consensus paramters. */
void ResetConsensusParams();


/** Gets the display name for a feature ID */
std::string GetFeatureName(uint16_t featureId);
/** Activates a feature at a specific block height. */
bool ActivateFeature(uint16_t featureId, int activationBlock, uint32_t minClientVersion, int transactionBlock);
/** Deactivates a feature immediately, authorization has already been validated. */
bool DeactivateFeature(uint16_t featureId, int transactionBlock);
/** Checks, whether a feature is activated at the given block. */
bool IsFeatureActivated(uint16_t featureId, int transactionBlock);
/** Checks, if the script type is allowed as input. */
bool IsAllowedInputType(int whichType, int nBlock);
/** Checks, if the script type qualifies as output. */
bool IsAllowedOutputType(int whichType, int nBlock);
/** Checks, if the transaction type and version is supported and enabled. */
bool IsTransactionTypeAllowed(int txBlock, uint32_t txProperty, uint16_t txType, uint16_t version);

/** Compares a supplied block, block hash and consensus hash against a hardcoded list of checkpoints. */
bool VerifyCheckpoint(int block, const uint256& blockHash);

} // namespace elysium

#endif // FIRO_ELYSIUM_RULES_H
