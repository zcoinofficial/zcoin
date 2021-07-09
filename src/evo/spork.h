#ifndef ZCOIN_SPORKTX_H
#define ZCOIN_SPORKTX_H

#include "consensus/validation.h"
#include "primitives/transaction.h"
#include "evo/evodb.h"

class CBlockIndex;
class UniValue;

typedef std::map<std::string, std::pair<int, int64_t>> ActiveSporkMap;

// one action to perform. Spork transaction can have multiple actions
struct CSporkAction
{
    static constexpr const char *featureLelantus = "lelantus";
    static constexpr const char *featureLelantusTransparentLimit = "lelantustransparentlimit";
    static constexpr const char *featureChainlocks = "chainlocks";
    static constexpr const char *featureInstantSend = "instantsend";

    enum ActionType {
        sporkDisable = 1,
        sporkEnable = 2,
        sporkLimit = 3
    };

    ActionType actionType;    // enable, disable or limit
    std::string feature;      // feature name
    int64_t parameter;        // parameter of feature (works if fEnable is false)
    int32_t nEnableAtHeight;  // if fEnable is false and nEnableAtHeight is not zero feature 
                              // is re-enabled automatically after this height

    /*
     * If actionType is sporkDisable or sporkLimit:
     *   - once accepted into the mempool the feature is disabled/limited in the mempool (irregardless of nEnableAtHeight). All
     *     the transactions violating the spork are immediately pushed out of the mempool
     * 
     *   - once mined into the block the feature is disabled/limited at block level (block is deemed invalid if the feature is used
     *     in it). If nEnableAtHeight is not zero feature is reenabled at given height. If it is zero feature is disabled
     *     until new spork tx. Feature is not accepted into the mempool while disabling spork is active at consensus level
     * 
     * If actionType is sporkEnable:
     *   - nEnableAtHeight is ignored
     * 
     *   - no immediate action for the mempool
     * 
     *   - when mined into the block feature becomes enabled starting with this block. nEnableAtHeight field is ignored.
     *     mempool starts accepting transactions with this feature
     * 
     * It's possible to change reactivation block number by issuing another spork tx with actionType=sporkDisable and updated
     * nEnableAtHeight field
     */

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        int16_t type;
        if (!ser_action.ForRead())
            type = (int16_t)actionType;
        READWRITE(type);
        if (ser_action.ForRead()) {
            if (type >= (int16_t)sporkDisable && type <= (int16_t)sporkLimit)
                actionType = (ActionType)type;
            else
                // safe action type
                actionType = sporkDisable;
        }
        READWRITE(feature);
        READWRITE(parameter);
        READWRITE(nEnableAtHeight);
    }
};

class CSporkTx
{
public:
    static const uint16_t CURRENT_VERSION = 1;

public:
    uint16_t nVersion{CURRENT_VERSION};     // version
    std::vector<CSporkAction> actions;      // list of actions to perform on spork activation
    std::vector<unsigned char> vchSig;      // spork signature
    uint256 inputsHash;

public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(nVersion);
        READWRITE(actions);
        READWRITE(inputsHash);
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(vchSig);
    }

    void ToJson(UniValue &obj) const;
};

bool CheckSporkTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state);

class CSporkManager
{
private:
    static CSporkManager *sharedSporkManager;

public:
    CSporkManager() {}

    // update spork state and block index with contents of spork transactions containted in block
    bool BlockConnected(const CBlock &block, CBlockIndex *pindex);

    // test if the feature is enabled at given block index
    bool IsFeatureEnabled(const std::string &featureName, const CBlockIndex *pindex);

    // test if transaction is allowed under current spork set
    bool IsTransactionAllowed(const CTransaction &tx, const ActiveSporkMap &sporkMap, CValidationState &state);

    // low level function to update spork state given previous state and new set of spork txs
    bool UpdateActiveSporkMap(ActiveSporkMap &sporkMap, const ActiveSporkMap &previousSporkMap, int nHeight, const std::vector<CTransactionRef> &sporkTransactions);

    // test if block is valid under current spork set
    bool IsBlockAllowed(const CBlock &block, const CBlockIndex *pindex, CValidationState &state);

    static CSporkManager *GetSporkManager() { return sharedSporkManager; };
};

class CMempoolSporkManager
{
private:
    // map of {feature name} -> {enable block height, parameter}
    ActiveSporkMap mempoolSporks;

public:
    CMempoolSporkManager() {}

    // accept transaction into memory pool
    // should be protected by cs_main and mempool.cs
    bool AcceptSporkToMemoryPool(const CTransaction &sporkTx);

    // transaction is removed from the mempool (mined into the block or other reason)
    // should be protected by cs_main and mempool.cs
    void RemovedFromMemoryPool(const CTransaction &sporkTx);

    // test if the feature is enabled
    bool IsFeatureEnabled(const std::string &featureName) const;
    bool IsTransactionAllowed(const CTransaction &tx, CValidationState &state) const;
    ActiveSporkMap GetActiveSporks() const { return mempoolSporks; }
};

inline bool IsNewInstantSendEnabled()
{
    return false;
}

inline bool IsChainlocksEnabled(const CBlockIndex *pindex)
{
    return CSporkManager::GetSporkManager()->IsFeatureEnabled(CSporkAction::featureChainlocks, pindex);
}

inline bool IsNewInstantSendEnabled(const CBlockIndex *pindex)
{
    return CSporkManager::GetSporkManager()->IsFeatureEnabled(CSporkAction::featureInstantSend, pindex);
}

inline bool IsBlockFilteringEnabled()
{
    return false;
}

#endif