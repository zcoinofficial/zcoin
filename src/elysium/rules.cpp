#include "rules.h"

#include "activation.h"
#include "consensushash.h"
#include "log.h"
#include "elysium.h"
#include "notifications.h"
#include "tx.h"
#include "utilsbitcoin.h"
#include "version.h"

#include "../chainparams.h"
#include "../validation.h"
#include "../script/standard.h"
#include "../uint256.h"
#include "../ui_interface.h"

#include <limits>
#include <string>
#include <vector>

#include <inttypes.h>

namespace elysium
{
/**
 * Returns a mapping of transaction types, and the blocks at which they are enabled.
 */
std::vector<TransactionRestriction> CConsensusParams::GetRestrictions() const
{
    const TransactionRestriction vTxRestrictions[] =
    { //  transaction type                    version        allow 0  activation block
      //  ----------------------------------  -------------  -------  ------------------
        { ELYSIUM_MESSAGE_TYPE_ALERT,        0xFFFF,        true,    ELYSIUM_ALERT_BLOCK    },
        { ELYSIUM_MESSAGE_TYPE_ACTIVATION,   0xFFFF,        true,    ELYSIUM_ALERT_BLOCK    },
        { ELYSIUM_MESSAGE_TYPE_DEACTIVATION, 0xFFFF,        true,    ELYSIUM_ALERT_BLOCK    },

        { ELYSIUM_TYPE_SIMPLE_SEND,               MP_TX_PKT_V0,  false,   ELYSIUM_SEND_BLOCK     },

        { ELYSIUM_TYPE_CREATE_PROPERTY_FIXED,     MP_TX_PKT_V0,  false,   ELYSIUM_SP_BLOCK       },
        { ELYSIUM_TYPE_CREATE_PROPERTY_FIXED,     MP_TX_PKT_V2,  false,   LELANTUS_FEATURE_BLOCK },
        { ELYSIUM_TYPE_CREATE_PROPERTY_VARIABLE,  MP_TX_PKT_V0,  false,   ELYSIUM_SP_BLOCK       },
        { ELYSIUM_TYPE_CREATE_PROPERTY_VARIABLE,  MP_TX_PKT_V2,  false,   LELANTUS_FEATURE_BLOCK },

        { ELYSIUM_TYPE_CREATE_PROPERTY_MANUAL,    MP_TX_PKT_V0,  false,   ELYSIUM_MANUALSP_BLOCK },
        { ELYSIUM_TYPE_CREATE_PROPERTY_MANUAL,    MP_TX_PKT_V2,  false,   LELANTUS_FEATURE_BLOCK },
        { ELYSIUM_TYPE_GRANT_PROPERTY_TOKENS,     MP_TX_PKT_V0,  false,   ELYSIUM_MANUALSP_BLOCK },
        { ELYSIUM_TYPE_REVOKE_PROPERTY_TOKENS,    MP_TX_PKT_V0,  false,   ELYSIUM_MANUALSP_BLOCK },
        { ELYSIUM_TYPE_CHANGE_ISSUER_ADDRESS,     MP_TX_PKT_V0,  false,   ELYSIUM_MANUALSP_BLOCK },
        { ELYSIUM_TYPE_ENABLE_FREEZING,           MP_TX_PKT_V0,  false,   ELYSIUM_MANUALSP_BLOCK },
        { ELYSIUM_TYPE_DISABLE_FREEZING,          MP_TX_PKT_V0,  false,   ELYSIUM_MANUALSP_BLOCK },
        { ELYSIUM_TYPE_FREEZE_PROPERTY_TOKENS,    MP_TX_PKT_V0,  false,   ELYSIUM_MANUALSP_BLOCK },
        { ELYSIUM_TYPE_UNFREEZE_PROPERTY_TOKENS,  MP_TX_PKT_V0,  false,   ELYSIUM_MANUALSP_BLOCK },

        { ELYSIUM_TYPE_SEND_TO_OWNERS,            MP_TX_PKT_V0,  false,   ELYSIUM_STO_BLOCK      },
        { ELYSIUM_TYPE_SEND_TO_OWNERS,            MP_TX_PKT_V1,  false,   ELYSIUM_STOV1_BLOCK    },

        { ELYSIUM_TYPE_SEND_ALL,                  MP_TX_PKT_V0,  false,   ELYSIUM_SEND_ALL_BLOCK },

        { ELYSIUM_TYPE_LELANTUS_MINT,             MP_TX_PKT_V0,  false,   LELANTUS_FEATURE_BLOCK      },
        { ELYSIUM_TYPE_LELANTUS_JOINSPLIT,        MP_TX_PKT_V0,  false,   LELANTUS_FEATURE_BLOCK      },
        { ELYSIUM_TYPE_CHANGE_LELANTUS_STATUS,    MP_TX_PKT_V0,  false,   LELANTUS_FEATURE_BLOCK      },
    };

    const size_t nSize = sizeof(vTxRestrictions) / sizeof(vTxRestrictions[0]);

    return std::vector<TransactionRestriction>(vTxRestrictions, vTxRestrictions + nSize);
}

/**
 * Returns an empty vector of consensus checkpoints.
 *
 * This method should be overwriten by the child classes, if needed.
 */
std::vector<ConsensusCheckpoint> CConsensusParams::GetCheckpoints() const
{
    return std::vector<ConsensusCheckpoint>();
}

/**
 * Constructor for mainnet consensus parameters.
 */
CMainConsensusParams::CMainConsensusParams()
{
    GENESIS_BLOCK = 108888;

    // Notice range for feature activations:
    MIN_ACTIVATION_BLOCKS = 2048;  // ~2 weeks
    MAX_ACTIVATION_BLOCKS = 12288; // ~12 weeks

    // Waiting period for enabling freezing
    ELYSIUM_FREEZE_WAIT_PERIOD = 4096; // ~4 weeks

    // Script related:
    PUBKEYHASH_BLOCK = 0;
    SCRIPTHASH_BLOCK = 0;
    NULLDATA_BLOCK = 0;

    // Transaction restrictions:
    ELYSIUM_ALERT_BLOCK = 0;
    ELYSIUM_SEND_BLOCK = 0;
    ELYSIUM_SP_BLOCK = 0;
    ELYSIUM_MANUALSP_BLOCK = 0;
    ELYSIUM_STO_BLOCK = 0;
    ELYSIUM_SEND_ALL_BLOCK = 0;
    ELYSIUM_STOV1_BLOCK = 999999;

    // Other feature activations:
    GRANTEFFECTS_FEATURE_BLOCK = 0;
    FREEZENOTICE_FEATURE_BLOCK = 999999;

    // Lelantus releated
    LELANTUS_FEATURE_BLOCK = 0;

    // Property creation fee
	// Set to false anyway, so this code just for be here for removing in the future
    PROPERTY_CREATION_FEE_BLOCK = 0;
    PROPERTY_CREATION_FEE = 1000 * COIN;
    PROPERTY_CREATION_FEE_RECEIVER.SetString("a1kCCGddf5pMXSipLVD9hBG2MGGVNaJ15U");
}

/**
 * Constructor for testnet consensus parameters.
 */
CTestNetConsensusParams::CTestNetConsensusParams()
{
    GENESIS_BLOCK = 29000;

    // Notice range for feature activations:
    MIN_ACTIVATION_BLOCKS = 0;
    MAX_ACTIVATION_BLOCKS = 999999;

    // Waiting period for enabling freezing
    ELYSIUM_FREEZE_WAIT_PERIOD = 0;

    // Script related:
    PUBKEYHASH_BLOCK = 0;
    SCRIPTHASH_BLOCK = 0;
    NULLDATA_BLOCK = 0;

    // Transaction restrictions:
    ELYSIUM_ALERT_BLOCK = 0;
    ELYSIUM_SEND_BLOCK = 0;
    ELYSIUM_DEX_BLOCK = 0;
    ELYSIUM_SP_BLOCK = 0;
    ELYSIUM_MANUALSP_BLOCK = 0;
    ELYSIUM_STO_BLOCK = 0;
    ELYSIUM_SEND_ALL_BLOCK = 0;
    ELYSIUM_STOV1_BLOCK = 29000;

    // Other feature activations:
    GRANTEFFECTS_FEATURE_BLOCK = 0;
    FREEZENOTICE_FEATURE_BLOCK = 29000;

    // Lelantus related
    LELANTUS_FEATURE_BLOCK = 29000;

    // Property creation fee
    PROPERTY_CREATION_FEE_BLOCK = 29000;
    PROPERTY_CREATION_FEE = 10 * COIN;
    PROPERTY_CREATION_FEE_RECEIVER.SetString("TKPbcG9QVLSfNvrtowQ7GzEEXq4zPjkej6");
}

/**
 * Constructor for regtest consensus parameters.
 */
CRegTestConsensusParams::CRegTestConsensusParams()
{
    GENESIS_BLOCK = 101;

    // Notice range for feature activations:
    MIN_ACTIVATION_BLOCKS = 5;
    MAX_ACTIVATION_BLOCKS = 10;

    // Waiting period for enabling freezing
    ELYSIUM_FREEZE_WAIT_PERIOD = 10;

    // Script related:
    PUBKEYHASH_BLOCK = 0;
    SCRIPTHASH_BLOCK = 0;
    NULLDATA_BLOCK = 0;

    // Transaction restrictions:
    ELYSIUM_ALERT_BLOCK = 0;
    ELYSIUM_SEND_BLOCK = 0;
    ELYSIUM_DEX_BLOCK = 0;
    ELYSIUM_SP_BLOCK = 0;
    ELYSIUM_MANUALSP_BLOCK = 0;
    ELYSIUM_STO_BLOCK = 0;
    ELYSIUM_SEND_ALL_BLOCK = 0;
    ELYSIUM_STOV1_BLOCK = 999999;

    // Other feature activations:
    GRANTEFFECTS_FEATURE_BLOCK = 0;
    FREEZENOTICE_FEATURE_BLOCK = 999999;

    // Lelantus related
    LELANTUS_FEATURE_BLOCK = 1000;

    // Property creation fee
    PROPERTY_CREATION_FEE_BLOCK = 250;
    PROPERTY_CREATION_FEE = 10 * COIN;
    PROPERTY_CREATION_FEE_RECEIVER.SetString("TKPbcG9QVLSfNvrtowQ7GzEEXq4zPjkej6");
}

//! Consensus parameters for mainnet
static CMainConsensusParams mainConsensusParams;
//! Consensus parameters for testnet
static CTestNetConsensusParams testNetConsensusParams;
//! Consensus parameters for regtest mode
static CRegTestConsensusParams regTestConsensusParams;

/**
 * Returns consensus parameters for the given network.
 */
CConsensusParams& ConsensusParams(const std::string& network)
{
    if (network == "main") {
        return mainConsensusParams;
    }
    if (network == "test") {
        return testNetConsensusParams;
    }
    if (network == "regtest") {
        return regTestConsensusParams;
    }
    // Fallback:
    return mainConsensusParams;
}

/**
 * Returns currently active consensus parameter.
 */
const CConsensusParams& ConsensusParams()
{
    const std::string& network = Params().NetworkIDString();

    return ConsensusParams(network);
}

/**
 * Returns currently active mutable consensus parameter.
 */
CConsensusParams& MutableConsensusParams()
{
    const std::string& network = Params().NetworkIDString();

    return ConsensusParams(network);
}

/**
 * Resets consensus paramters.
 */
void ResetConsensusParams()
{
    mainConsensusParams = CMainConsensusParams();
    testNetConsensusParams = CTestNetConsensusParams();
    regTestConsensusParams = CRegTestConsensusParams();
}

/**
 * Checks, if the script type is allowed as input.
 */
bool IsAllowedInputType(int whichType, int nBlock)
{
    const CConsensusParams& params = ConsensusParams();

    switch (whichType)
    {
        case TX_PUBKEYHASH:
            return (params.PUBKEYHASH_BLOCK <= nBlock);

        case TX_SCRIPTHASH:
            return (params.SCRIPTHASH_BLOCK <= nBlock);
    }

    return false;
}

/**
 * Checks, if the script type qualifies as output.
 */
bool IsAllowedOutputType(int whichType, int nBlock)
{
    const CConsensusParams& params = ConsensusParams();

    switch (whichType)
    {
        case TX_PUBKEYHASH:
            return (params.PUBKEYHASH_BLOCK <= nBlock);

        case TX_SCRIPTHASH:
            return (params.SCRIPTHASH_BLOCK <= nBlock);

        case TX_NULL_DATA:
            return (params.NULLDATA_BLOCK <= nBlock);
    }

    return false;
}

/**
 * Activates a feature at a specific block height, authorization has already been validated.
 *
 * Note: Feature activations are consensus breaking.  It is not permitted to activate a feature within
 *       the next 2048 blocks (roughly 2 weeks), nor is it permitted to activate a feature further out
 *       than 12288 blocks (roughly 12 weeks) to ensure sufficient notice.
 *       This does not apply for activation during initialization (where loadingActivations is set true).
 */
bool ActivateFeature(uint16_t featureId, int activationBlock, uint32_t minClientVersion, int transactionBlock)
{
    PrintToLog("Feature activation requested (ID %d to go active as of block: %d)\n", featureId, activationBlock);

    const CConsensusParams& params = ConsensusParams();

    // check activation block is allowed
    if ((activationBlock < (transactionBlock + params.MIN_ACTIVATION_BLOCKS)) ||
        (activationBlock > (transactionBlock + params.MAX_ACTIVATION_BLOCKS))) {
            PrintToLog("Feature activation of ID %d refused due to notice checks\n", featureId);
            return false;
    }

    // check whether the feature is already active
    if (IsFeatureActivated(featureId, transactionBlock)) {
        PrintToLog("Feature activation of ID %d refused as the feature is already live\n", featureId);
        return false;
    }

    // check feature is recognized and activation is successful
    std::string featureName = GetFeatureName(featureId);
    bool supported = ELYSIUM_VERSION >= minClientVersion;
    switch (featureId) {
        case FEATURE_CLASS_C:
            MutableConsensusParams().NULLDATA_BLOCK = activationBlock;
        break;
        case FEATURE_GRANTEFFECTS:
            MutableConsensusParams().GRANTEFFECTS_FEATURE_BLOCK = activationBlock;
        break;
        case FEATURE_SENDALL:
            MutableConsensusParams().ELYSIUM_SEND_ALL_BLOCK = activationBlock;
        break;
        case FEATURE_STOV1:
            MutableConsensusParams().ELYSIUM_STOV1_BLOCK = activationBlock;
        break;
        case FEATURE_FREEZENOTICE:
            MutableConsensusParams().FREEZENOTICE_FEATURE_BLOCK = activationBlock;
        break;
        case FEATURE_LELANTUS:
            MutableConsensusParams().LELANTUS_FEATURE_BLOCK = activationBlock;
        break;
        default:
            supported = false;
        break;
    }

    PrintToLog("Feature activation of ID %d processed. %s will be enabled at block %d.\n", featureId, featureName, activationBlock);
    AddPendingActivation(featureId, activationBlock, minClientVersion, featureName);

    if (!supported) {
        PrintToLog("WARNING!!! AS OF BLOCK %d THIS CLIENT WILL BE OUT OF CONSENSUS AND WILL AUTOMATICALLY SHUTDOWN.\n", activationBlock);
        std::string alertText = strprintf("Your client must be updated and will shutdown at block %d (unsupported feature %d ('%s') activated)\n",
                                          activationBlock, featureId, featureName);
        AddAlert("elysium", ALERT_BLOCK_EXPIRY, activationBlock, alertText);
        AlertNotify(alertText);
    }

    return true;
}

/**
 * Deactivates a feature immediately, authorization has already been validated.
 *
 * Note: There is no notice period for feature deactivation as:
 *       # It is reserved for emergency use in the event an exploit is found
 *       # No client upgrade is required
 *       # No action is required by users
 */
bool DeactivateFeature(uint16_t featureId, int transactionBlock)
{
    PrintToLog("Immediate feature deactivation requested (ID %d)\n", featureId);

    if (!IsFeatureActivated(featureId, transactionBlock)) {
        PrintToLog("Feature deactivation of ID %d refused as the feature is not yet live\n", featureId);
        return false;
    }

    std::string featureName = GetFeatureName(featureId);
    switch (featureId) {
        case FEATURE_CLASS_C:
            MutableConsensusParams().NULLDATA_BLOCK = 999999;
        break;
        case FEATURE_GRANTEFFECTS:
            MutableConsensusParams().GRANTEFFECTS_FEATURE_BLOCK = 999999;
        break;
        case FEATURE_SENDALL:
            MutableConsensusParams().ELYSIUM_SEND_ALL_BLOCK = 999999;
        break;
        case FEATURE_STOV1:
            MutableConsensusParams().ELYSIUM_STOV1_BLOCK = 999999;
        break;
        case FEATURE_FREEZENOTICE:
            MutableConsensusParams().FREEZENOTICE_FEATURE_BLOCK = 999999;
        break;
        case FEATURE_LELANTUS:
            MutableConsensusParams().LELANTUS_FEATURE_BLOCK = 999999;
        break;
        default:
            return false;
        break;
    }

    PrintToLog("Feature deactivation of ID %d processed. %s has been disabled.\n", featureId, featureName);

    std::string alertText = strprintf("An emergency deactivation of feature ID %d (%s) has occurred.", featureId, featureName);
    AddAlert("elysium", ALERT_BLOCK_EXPIRY, transactionBlock + 1024, alertText);
    AlertNotify(alertText);

    return true;
}

/**
 * Returns the display name of a feature ID
 */
std::string GetFeatureName(uint16_t featureId)
{
    switch (featureId) {
        case FEATURE_CLASS_C: return "Class C transaction encoding";
        case FEATURE_GRANTEFFECTS: return "Remove grant side effects";
        case FEATURE_SENDALL: return "Send All transactions";
        case FEATURE_FEES: return "Fee system (inc 0.05% fee from trades of non-Elysium pairs)";
        case FEATURE_STOV1: return "Cross-property Send To Owners";
        case FEATURE_FREEZENOTICE: return "Activate the waiting period for enabling freezing";
        case FEATURE_LELANTUS: return "Activate Lelantus transactions";
        default: return "Unknown feature";
    }
}

/**
 * Checks, whether a feature is activated at the given block.
 */
bool IsFeatureActivated(uint16_t featureId, int transactionBlock)
{
    const CConsensusParams& params = ConsensusParams();
    int activationBlock = std::numeric_limits<int>::max();

    switch (featureId) {
        case FEATURE_CLASS_C:
            activationBlock = params.NULLDATA_BLOCK;
            break;
        case FEATURE_GRANTEFFECTS:
            activationBlock = params.GRANTEFFECTS_FEATURE_BLOCK;
            break;
        case FEATURE_SENDALL:
            activationBlock = params.ELYSIUM_SEND_ALL_BLOCK;
            break;
        case FEATURE_STOV1:
            activationBlock = params.ELYSIUM_STOV1_BLOCK;
            break;
        case FEATURE_FREEZENOTICE:
            activationBlock = params.FREEZENOTICE_FEATURE_BLOCK;
            break;
        case FEATURE_LELANTUS:
            activationBlock = params.LELANTUS_FEATURE_BLOCK;
            break;
        default:
            return false;
    }

    return (transactionBlock >= activationBlock);
}

/**
 * Checks, if the transaction type and version is supported and enabled.
 *
 * In the test ecosystem, transactions, which are known to the client are allowed
 * without height restriction.
 *
 * Certain transactions use a property identifier of 0 (= BTC) as wildcard, which
 * must explicitly be allowed.
 */
bool IsTransactionTypeAllowed(int txBlock, uint32_t txProperty, uint16_t txType, uint16_t version)
{
    const std::vector<TransactionRestriction>& vTxRestrictions = ConsensusParams().GetRestrictions();

    for (std::vector<TransactionRestriction>::const_iterator it = vTxRestrictions.begin(); it != vTxRestrictions.end(); ++it)
    {
        const TransactionRestriction& entry = *it;
        if (entry.txType != txType || entry.txVersion != version) {
            continue;
        }
        // a property identifier of 0 (= FIRO) may be used as wildcard
        if (ELYSIUM_PROPERTY_FIRO == txProperty && !entry.allowWildcard) {
            continue;
        }
        // transactions are not restricted in the test ecosystem
        if (isTestEcosystemProperty(txProperty)) {
            return true;
        }
        if (txBlock >= entry.activationBlock) {
            return true;
        }
    }

    return false;
}

/**
 * Compares a supplied block, block hash and consensus hash against a hardcoded list of checkpoints.
 */
bool VerifyCheckpoint(int block, const uint256& blockHash)
{
    // optimization; we only checkpoint every 10,000 blocks - skip any further work if block not a multiple of 10K
    if (block % 10000 != 0) return true;

    const std::vector<ConsensusCheckpoint>& vCheckpoints = ConsensusParams().GetCheckpoints();

    for (std::vector<ConsensusCheckpoint>::const_iterator it = vCheckpoints.begin(); it != vCheckpoints.end(); ++it) {
        const ConsensusCheckpoint& checkpoint = *it;
        if (block != checkpoint.blockHeight) {
            continue;
        }

        if (blockHash != checkpoint.blockHash) {
            PrintToLog("%s(): block hash mismatch - expected %s, received %s\n", __func__, checkpoint.blockHash.GetHex(), blockHash.GetHex());
            return false;
        }

        // only verify if there is a checkpoint to verify against
        uint256 consensusHash = GetConsensusHash();
        if (consensusHash != checkpoint.consensusHash) {
            PrintToLog("%s(): consensus hash mismatch - expected %s, received %s\n", __func__, checkpoint.consensusHash.GetHex(), consensusHash.GetHex());
            return false;
        } else {
            break;
        }
    }

    // either checkpoint matched or we don't have a checkpoint for this block
    return true;
}

} // namespace elysium
