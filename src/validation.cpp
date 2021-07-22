// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "validation.h"

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "arith_uint256.h"
#include "chainparams.h"
#include "checkpoints.h"
#include "checkqueue.h"
#include "consensus/consensus.h"
#include "consensus/merkle.h"
#include "consensus/validation.h"
#include "hash.h"
#include "init.h"
#include "base58.h"
#include "merkleblock.h"
#include "net.h"
#include "policy/fees.h"
#include "policy/policy.h"
#include "pow.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "random.h"
#include "script/script.h"
#include "script/sigcache.h"
#include "script/standard.h"
#include "timedata.h"
#include "tinyformat.h"
#include "txdb.h"
#include "txmempool.h"
#include "ui_interface.h"
#include "undo.h"
#include "util.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#include "batchproof_container.h"
#include "sigma.h"
#include "lelantus.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h"
#include "validationinterface.h"
#include "versionbits.h"
#include "definition.h"
#include "utiltime.h"
#include "mtpstate.h"

#include "coins.h"

#include "blacklists.h"

#include "sigma/coinspend.h"
#include "warnings.h"

#ifdef ENABLE_ELYSIUM
#include "elysium/elysium.h"
#endif

#include "masternode-payments.h"

#include "evo/specialtx.h"
#include "evo/providertx.h"
#include "evo/deterministicmns.h"
#include "evo/cbtx.h"
#include "evo/spork.h"

#include "llmq/quorums_instantsend.h"
#include "llmq/quorums_chainlocks.h"

#include <atomic>
#include <sstream>
#include <chrono>

#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/math/distributions/poisson.hpp>
#include <boost/thread.hpp>

#if defined(NDEBUG)
# error "Firo cannot be compiled without assertions."
#endif

bool AbortNode(const std::string& strMessage, const std::string& userMessage="");
bool AbortNode(CValidationState &state, const std::string& strMessage, const std::string& userMessage="");

/**
 * Global state
 */

CCriticalSection cs_main;

BlockMap mapBlockIndex;
PrevBlockMap mapPrevBlockIndex;
CChain chainActive;
CBlockIndex *pindexBestHeader = NULL;
CWaitableCriticalSection csBestBlock;
CConditionVariable cvBlockChange;
int nScriptCheckThreads = 0;
std::atomic_bool fImporting(false);
bool fReindex = false;
bool fTxIndex = false;
bool fHavePruned = false;
bool fPruneMode = false;
bool fAddressIndex = false;
bool fSpentIndex = false;
bool fTimestampIndex = false;
bool fIsBareMultisigStd = DEFAULT_PERMIT_BAREMULTISIG;
bool fRequireStandard = true;
bool fCheckBlockIndex = false;
bool fCheckpointsEnabled = DEFAULT_CHECKPOINTS_ENABLED;
size_t nCoinCacheUsage = 5000 * 300;
uint64_t nPruneTarget = 0;
int64_t nMaxTipAge = DEFAULT_MAX_TIP_AGE;
bool fEnableReplacement = DEFAULT_ENABLE_REPLACEMENT;

uint256 hashAssumeValid;

CFeeRate minRelayTxFee = CFeeRate(DEFAULT_MIN_RELAY_TX_FEE);
CAmount maxTxFee = DEFAULT_TRANSACTION_MAXFEE;

CTxMemPool mempool(::minRelayTxFee);
FeeFilterRounder filterRounder(::minRelayTxFee);
CTxPoolAggregate txpools(::minRelayTxFee);

// Firo znode
std::map <uint256, int64_t> mapRejectedBlocks GUARDED_BY(cs_main);


static void CheckBlockIndex(const Consensus::Params& consensusParams);

/** Constant stuff for coinbase transactions we create: */
CScript COINBASE_FLAGS;

const std::string strMessageMagic = "Zcoin Signed Message:\n";

// Internal stuff
namespace {

    struct CBlockIndexWorkComparator
    {
        bool operator()(CBlockIndex *pa, CBlockIndex *pb) const {
            // First sort by most total work, ...
            if (pa->nChainWork > pb->nChainWork) return false;
            if (pa->nChainWork < pb->nChainWork) return true;

            // ... then by earliest time received, ...
            if (pa->nSequenceId < pb->nSequenceId) return false;
            if (pa->nSequenceId > pb->nSequenceId) return true;

            // Use pointer address as tie breaker (should only happen with blocks
            // loaded from disk, as those all have id 0).
            if (pa < pb) return false;
            if (pa > pb) return true;

            // Identical blocks.
            return false;
        }
    };

    CBlockIndex *pindexBestInvalid;

    /**
     * The set of all CBlockIndex entries with BLOCK_VALID_TRANSACTIONS (for itself and all ancestors) and
     * as good as our current tip or better. Entries may be failed, though, and pruning nodes may be
     * missing the data for the block.
     */
    std::set<CBlockIndex*, CBlockIndexWorkComparator> setBlockIndexCandidates;
    /** All pairs A->B, where A (or one of its ancestors) misses transactions, but B has transactions.
     * Pruned nodes may have entries where B is missing data.
     */
    std::multimap<CBlockIndex*, CBlockIndex*> mapBlocksUnlinked;

    CCriticalSection cs_LastBlockFile;
    std::vector<CBlockFileInfo> vinfoBlockFile;
    int nLastBlockFile = 0;
    /** Global flag to indicate we should check to see if there are
     *  block/undo files that should be deleted.  Set on startup
     *  or if we allocate more file space when we're in prune mode
     */
    bool fCheckForPruning = false;

    /**
     * Every received block is assigned a unique and increasing identifier, so we
     * know which one to give priority in case of a fork.
     */
    CCriticalSection cs_nBlockSequenceId;
    /** Blocks loaded from disk are assigned id 0, so start the counter at 1. */
    int32_t nBlockSequenceId = 1;
    /** Decreasing counter (used by subsequent preciousblock calls). */
    int32_t nBlockReverseSequenceId = -1;
    /** chainwork for the last block that preciousblock has been applied to. */
    arith_uint256 nLastPreciousChainwork = 0;

    /** Dirty block index entries. */
    std::set<CBlockIndex*> setDirtyBlockIndex;

    /** Dirty block file entries. */
    std::set<int> setDirtyFileInfo;
} // anon namespace

int GetHeight()
{
    LOCK(cs_main);
    return chainActive.Height();
}

int GetNHeight(const CBlockHeader &block) {
    CBlockIndex *pindexPrev = NULL;
    int nHeight = 0;
    BlockMap::iterator mi = mapBlockIndex.find(block.hashPrevBlock);
    if (mi != mapBlockIndex.end()) {
        pindexPrev = (*mi).second;
        nHeight = pindexPrev->nHeight + 1;
    }
    return nHeight;
}

/* Use this class to start tracking transactions that are removed from the
 * mempool and pass all those transactions through SyncTransaction when the
 * object goes out of scope. This is currently only used to call SyncTransaction
 * on conflicts removed from the mempool during block connection.  Applied in
 * ActivateBestChain around ActivateBestStep which in turn calls:
 * ConnectTip->removeForBlock->removeConflicts
 */
class MemPoolConflictRemovalTracker
{
private:
    std::vector<CTransactionRef> conflictedTxs;
    CTxMemPool &pool;

public:
    MemPoolConflictRemovalTracker(CTxMemPool &_pool) : pool(_pool) {
        pool.NotifyEntryRemoved.connect(boost::bind(&MemPoolConflictRemovalTracker::NotifyEntryRemoved, this, _1, _2));
    }

    void NotifyEntryRemoved(CTransactionRef txRemoved, MemPoolRemovalReason reason) {
        if (reason == MemPoolRemovalReason::CONFLICT) {
            conflictedTxs.push_back(txRemoved);
        }
    }

    ~MemPoolConflictRemovalTracker() {
        pool.NotifyEntryRemoved.disconnect(boost::bind(&MemPoolConflictRemovalTracker::NotifyEntryRemoved, this, _1, _2));
        for (const auto& tx : conflictedTxs) {
            GetMainSignals().SyncTransaction(*tx, NULL, CMainSignals::SYNC_TRANSACTION_NOT_IN_BLOCK);
        }
        conflictedTxs.clear();
    }
};

CBlockIndex* FindForkInGlobalIndex(const CChain& chain, const CBlockLocator& locator)
{
    // Find the first block the caller has in the main chain
    BOOST_FOREACH(const uint256& hash, locator.vHave) {
        BlockMap::iterator mi = mapBlockIndex.find(hash);
        if (mi != mapBlockIndex.end())
        {
            CBlockIndex* pindex = (*mi).second;
            if (chain.Contains(pindex))
                return pindex;
            if (pindex->GetAncestor(chain.Height()) == chain.Tip()) {
                return chain.Tip();
            }
        }
    }
    return chain.Genesis();
}

CCoinsViewCache *pcoinsTip = NULL;
CBlockTreeDB *pblocktree = NULL;

enum FlushStateMode {
    FLUSH_STATE_NONE,
    FLUSH_STATE_IF_NEEDED,
    FLUSH_STATE_PERIODIC,
    FLUSH_STATE_ALWAYS
};

// See definition for documentation
bool static FlushStateToDisk(CValidationState &state, FlushStateMode mode, int nManualPruneHeight=0);
void FindFilesToPruneManual(std::set<int>& setFilesToPrune, int nManualPruneHeight);

bool IsFinalTx(const CTransaction &tx, int nBlockHeight, int64_t nBlockTime)
{
    if (tx.nLockTime == 0)
        return true;
    if ((int64_t)tx.nLockTime < ((int64_t)tx.nLockTime < LOCKTIME_THRESHOLD ? (int64_t)nBlockHeight : nBlockTime))
        return true;
    for (const auto& txin : tx.vin) {
        if (!(txin.nSequence == CTxIn::SEQUENCE_FINAL))
            return false;
    }
    return true;
}

bool CheckFinalTx(const CTransaction &tx, int flags)
{
    AssertLockHeld(cs_main);

    // By convention a negative value for flags indicates that the
    // current network-enforced consensus rules should be used. In
    // a future soft-fork scenario that would mean checking which
    // rules would be enforced for the next block and setting the
    // appropriate flags. At the present time no soft-forks are
    // scheduled, so no flags are set.
    flags = std::max(flags, 0);

    // CheckFinalTx() uses chainActive.Height()+1 to evaluate
    // nLockTime because when IsFinalTx() is called within
    // CBlock::AcceptBlock(), the height of the block *being*
    // evaluated is what is used. Thus if we want to know if a
    // transaction can be part of the *next* block, we need to call
    // IsFinalTx() with one more than chainActive.Height().
    const int nBlockHeight = chainActive.Height() + 1;

    // BIP113 will require that time-locked transactions have nLockTime set to
    // less than the median time of the previous block they're contained in.
    // When the next block is created its previous block will be the current
    // chain tip, so we use that to calculate the median time passed to
    // IsFinalTx() if LOCKTIME_MEDIAN_TIME_PAST is set.
    const int64_t nBlockTime = GetAdjustedTime();


    return IsFinalTx(tx, nBlockHeight, nBlockTime);
}

/**
 * Calculates the block height and previous block's median time past at
 * which the transaction will be considered final in the context of BIP 68.
 * Also removes from the vector of input heights any entries which did not
 * correspond to sequence locked inputs as they do not affect the calculation.
 */
static std::pair<int, int64_t> CalculateSequenceLocks(const CTransaction &tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block)
{
    assert(prevHeights->size() == tx.vin.size());

    // Will be set to the equivalent height- and time-based nLockTime
    // values that would be necessary to satisfy all relative lock-
    // time constraints given our view of block chain history.
    // The semantics of nLockTime are the last invalid height/time, so
    // use -1 to have the effect of any height or time being valid.
    int nMinHeight = -1;
    int64_t nMinTime = -1;

    // tx.nVersion is signed integer so requires cast to unsigned otherwise
    // we would be doing a signed comparison and half the range of nVersion
    // wouldn't support BIP 68.
    bool fEnforceBIP68 = static_cast<uint32_t>(tx.nVersion) >= 2
                      && flags & LOCKTIME_VERIFY_SEQUENCE;

    // Do not enforce sequence numbers as a relative lock time
    // unless we have been instructed to
    if (!fEnforceBIP68) {
        return std::make_pair(nMinHeight, nMinTime);
    }

    for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
        const CTxIn& txin = tx.vin[txinIndex];

        // Sequence numbers with the most significant bit set are not
        // treated as relative lock-times, nor are they given any
        // consensus-enforced meaning at this point.
        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) {
            // The height of this input is not relevant for sequence locks
            (*prevHeights)[txinIndex] = 0;
            continue;
        }

        int nCoinHeight = (*prevHeights)[txinIndex];

        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) {
            int64_t nCoinTime = block.GetAncestor(std::max(nCoinHeight-1, 0))->GetMedianTimePast();
            // NOTE: Subtract 1 to maintain nLockTime semantics
            // BIP 68 relative lock times have the semantics of calculating
            // the first block or time at which the transaction would be
            // valid. When calculating the effective block time or height
            // for the entire transaction, we switch to using the
            // semantics of nLockTime which is the last invalid block
            // time or height.  Thus we subtract 1 from the calculated
            // time or height.

            // Time-based relative lock-times are measured from the
            // smallest allowed timestamp of the block containing the
            // txout being spent, which is the median time past of the
            // block prior.
            nMinTime = std::max(nMinTime, nCoinTime + (int64_t)((txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) - 1);
        } else {
            nMinHeight = std::max(nMinHeight, nCoinHeight + (int)(txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) - 1);
        }
    }

    return std::make_pair(nMinHeight, nMinTime);
}

static bool EvaluateSequenceLocks(const CBlockIndex& block, std::pair<int, int64_t> lockPair)
{
    assert(block.pprev);
    int64_t nBlockTime = block.pprev->GetMedianTimePast();
    if (lockPair.first >= block.nHeight || lockPair.second >= nBlockTime)
        return false;

    return true;
}

bool SequenceLocks(const CTransaction &tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block)
{
    return EvaluateSequenceLocks(block, CalculateSequenceLocks(tx, flags, prevHeights, block));
}

bool TestLockPointValidity(const LockPoints* lp)
{
    AssertLockHeld(cs_main);
    assert(lp);
    // If there are relative lock times then the maxInputBlock will be set
    // If there are no relative lock times, the LockPoints don't depend on the chain
    if (lp->maxInputBlock) {
        // Check whether chainActive is an extension of the block at which the LockPoints
        // calculation was valid.  If not LockPoints are no longer valid
        if (!chainActive.Contains(lp->maxInputBlock)) {
            return false;
        }
    }

    // LockPoints still valid
    return true;
}

bool CheckSequenceLocks(const CTxMemPool& pool, const CTransaction &tx, int flags, LockPoints *lp, bool useExistingLockPoints)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(pool.cs);

    CBlockIndex *tip = chainActive.Tip();
    CBlockIndex index;
    index.pprev = tip;
    // CheckSequenceLocks() uses chainActive.Height()+1 to evaluate
    // height based locks because when SequenceLocks() is called within
    // ConnectBlock(), the height of the block *being*
    // evaluated is what is used.
    // Thus if we want to know if a transaction can be part of the
    // *next* block, we need to use one more than chainActive.Height()
    index.nHeight = tip->nHeight + 1;

    std::pair<int, int64_t> lockPair;
    if (useExistingLockPoints) {
        assert(lp);
        lockPair.first = lp->height;
        lockPair.second = lp->time;
    }
    else {
        // pcoinsTip contains the UTXO set for chainActive.Tip()
        CCoinsViewMemPool viewMemPool(pcoinsTip, pool);
        std::vector<int> prevheights;
        prevheights.resize(tx.vin.size());
        for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
            const CTxIn& txin = tx.vin[txinIndex];
            Coin coin;
            if (!viewMemPool.GetCoin(txin.prevout, coin)) {
                return error("%s: Missing input", __func__);
            }
            if (coin.nHeight == MEMPOOL_HEIGHT) {
                // Assume all mempool transaction confirm in the next block
                prevheights[txinIndex] = tip->nHeight + 1;
            } else {
                prevheights[txinIndex] = coin.nHeight;
            }
        }
        lockPair = CalculateSequenceLocks(tx, flags, &prevheights, index);
        if (lp) {
            lp->height = lockPair.first;
            lp->time = lockPair.second;
            // Also store the hash of the block with the highest height of
            // all the blocks which have sequence locked prevouts.
            // This hash needs to still be on the chain
            // for these LockPoint calculations to be valid
            // Note: It is impossible to correctly calculate a maxInputBlock
            // if any of the sequence locked inputs depend on unconfirmed txs,
            // except in the special case where the relative lock time/height
            // is 0, which is equivalent to no sequence lock. Since we assume
            // input height of tip+1 for mempool txs and test the resulting
            // lockPair from CalculateSequenceLocks against tip+1.  We know
            // EvaluateSequenceLocks will fail if there was a non-zero sequence
            // lock on a mempool input, so we can use the return value of
            // CheckSequenceLocks to indicate the LockPoints validity
            int maxInputHeight = 0;
            BOOST_FOREACH(int height, prevheights) {
                // Can ignore mempool inputs since we'll fail if they had non-zero locks
                if (height != tip->nHeight+1) {
                    maxInputHeight = std::max(maxInputHeight, height);
                }
            }
            lp->maxInputBlock = tip->GetAncestor(maxInputHeight);
        }
    }
    return EvaluateSequenceLocks(index, lockPair);
}


unsigned int GetLegacySigOpCount(const CTransaction& tx)
{
    unsigned int nSigOps = 0;
    for (const auto& txin : tx.vin)
    {
        nSigOps += txin.scriptSig.GetSigOpCount(false);
    }
    for (const auto& txout : tx.vout)
    {
        nSigOps += txout.scriptPubKey.GetSigOpCount(false);
    }
    return nSigOps;
}

unsigned int GetP2SHSigOpCount(const CTransaction &tx, const CCoinsViewCache &inputs)
{
    if (tx.IsCoinBase() || tx.IsZerocoinSpend() || tx.IsSigmaSpend() || tx.IsLelantusJoinSplit())
        return 0;

    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const Coin& coin = inputs.AccessCoin(tx.vin[i].prevout);
        assert(!coin.IsSpent());
        const CTxOut &prevout = coin.out;
        if (prevout.scriptPubKey.IsPayToScriptHash())
            nSigOps += prevout.scriptPubKey.GetSigOpCount(tx.vin[i].scriptSig);
    }
    return nSigOps;
}

int64_t GetTransactionSigOpCost(const CTransaction &tx, const CCoinsViewCache &inputs, int flags)
{
    int64_t nSigOps = GetLegacySigOpCount(tx) * WITNESS_SCALE_FACTOR;

    if (tx.IsCoinBase() || tx.IsZerocoinSpend() || tx.IsSigmaSpend() || tx.IsZerocoinRemint() || tx.IsLelantusJoinSplit())
        return nSigOps;

    if (flags & SCRIPT_VERIFY_P2SH) {
        nSigOps += GetP2SHSigOpCount(tx, inputs) * WITNESS_SCALE_FACTOR;
    }

    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const CTxOut &prevout = inputs.AccessCoin(tx.vin[i].prevout).out;
        nSigOps += CountWitnessSigOps(tx.vin[i].scriptSig, prevout.scriptPubKey, &tx.vin[i].scriptWitness, flags);
    }
    return nSigOps;
}

bool GetUTXOCoin(const COutPoint& outpoint, Coin& coin)
{
    LOCK(cs_main);
    if (!pcoinsTip->GetCoin(outpoint, coin))
        return false;
    if (coin.IsSpent())
        return false;
    return true;
}

int GetUTXOHeight(const COutPoint& outpoint)
{
    // -1 means UTXO is yet unknown or already spent
    Coin coin;
    return GetUTXOCoin(outpoint, coin) ? coin.nHeight : -1;
}

int GetUTXOConfirmations(const COutPoint& outpoint)
{
    // -1 means UTXO is yet unknown or already spent
    LOCK(cs_main);
    int nPrevoutHeight = GetUTXOHeight(outpoint);
    return (nPrevoutHeight > -1 && chainActive.Tip()) ? chainActive.Height() - nPrevoutHeight + 1 : -1;
}

bool CheckTransaction(const CTransaction &tx, CValidationState &state, bool fCheckDuplicateInputs, uint256 hashTx,  bool isVerifyDB, int nHeight, bool isCheckWallet, bool fStatefulZerocoinCheck, sigma::CSigmaTxInfo *sigmaTxInfo, lelantus::CLelantusTxInfo* lelantusTxInfo)
{
    LogPrintf("CheckTransaction nHeight=%s, isVerifyDB=%s, isCheckWallet=%s, txHash=%s\n", nHeight, isVerifyDB, isCheckWallet, tx.GetHash().ToString());

    bool allowEmptyTxInOut = false;
    if (tx.nType == TRANSACTION_QUORUM_COMMITMENT) {
        allowEmptyTxInOut = true;
    }

    // Basic checks that don't depend on any context
    if (!allowEmptyTxInOut && tx.vin.empty())
        return state.DoS(10, false, REJECT_INVALID, "bad-txns-vin-empty");
    if (!allowEmptyTxInOut && tx.vout.empty())
        return state.DoS(10, false, REJECT_INVALID, "bad-txns-vout-empty");
    // Size limits (this doesn't take the witness into account, as that hasn't been checked for malleability)
    if (::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) > MAX_BLOCK_BASE_SIZE)
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-oversize");
    if (tx.vExtraPayload.size() > MAX_TX_EXTRA_PAYLOAD)
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-payload-oversize");

    // Check for negative or overflow output values
    CAmount nValueOut = 0;
    for (const auto& txout : tx.vout)
    {
        if (txout.nValue < 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vout-negative");
        if (txout.nValue > MAX_MONEY)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vout-toolarge");
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-txouttotal-toolarge");
    }

    // Check for duplicate inputs - note that this check is slow so we skip it in CheckBlock
    bool const check_di = nHeight != INT_MAX && nHeight > ::Params().GetConsensus().nStartDuplicationCheck;
    if (fCheckDuplicateInputs || check_di) {
        std::set<COutPoint> vInOutPoints;
        if (tx.IsSigmaSpend() || tx.IsLelantusJoinSplit()) {
            std::set<CScript> spendScripts;
            for (const auto& txin: tx.vin)
            {
                if (!spendScripts.insert(txin.scriptSig).second)
                    return state.DoS(100, false, REJECT_INVALID, "bad-txns-spend-inputs-duplicate");
            }
        }
        else {
            std::set<COutPoint> vInOutPoints;
            for (const auto& txin : tx.vin)
            {
                if (!vInOutPoints.insert(txin.prevout).second)
                    return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputs-duplicate");
            }
        }
    }

    if (tx.IsCoinBase())
    {
        size_t minCbSize = 2;
        if (tx.nType == TRANSACTION_COINBASE) {
            // With the introduction of CbTx, coinbase scripts are not required anymore to hold a valid block height
            minCbSize = 1;
        }
        if (tx.vin[0].scriptSig.size() < minCbSize || tx.vin[0].scriptSig.size() > 100)
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-length");
    }
    else
    {
        for (const auto& txin : tx.vin)
            if (txin.prevout.IsNull() && !(txin.scriptSig.IsZerocoinSpend()
                || txin.IsZerocoinRemint()
                || txin.IsLelantusJoinSplit() ))
                return state.DoS(10, false, REJECT_INVALID, "bad-txns-prevout-null");

        if (tx.IsZerocoinV3SigmaTransaction()) {
            if (!CheckSigmaTransaction(tx, state, hashTx, isVerifyDB, nHeight, isCheckWallet, fStatefulZerocoinCheck, sigmaTxInfo))
                return false;
        }

        if (tx.IsLelantusTransaction()) {
            if (!CheckLelantusTransaction(tx, state, hashTx, isVerifyDB, nHeight, isCheckWallet, fStatefulZerocoinCheck, sigmaTxInfo, lelantusTxInfo))
                return false;
        }

        auto params = ::Params().GetConsensus();
        if (tx.IsZerocoinSpend() || tx.IsZerocoinMint()) {
            if (!isVerifyDB && nHeight >= params.nDisableZerocoinStartBlock)
                return state.DoS(1, error("Zerocoin is disabled at this point"));
        }

        if (tx.IsZerocoinRemint()) {
            if (!isVerifyDB && (nHeight < params.nSigmaStartBlock || nHeight >= params.nSigmaStartBlock + params.nZerocoinToSigmaRemintWindowSize))
                // we allow transactions of remint type only during specific window
                return false;
        }
    }

    bool isInWhitelist = Params().GetConsensus().txidWhitelist.count(tx.GetHash()) > 0;
    if (nHeight >= ::Params().GetConsensus().nStartBlacklist && !isInWhitelist) {
        for (const auto& vin : tx.vin) {
            if (txid_blacklist.count(vin.prevout.hash.GetHex()) > 0) {
                    return state.DoS(100, error("Spending this tx is temporarily disabled"),
                                 REJECT_INVALID, "bad-txns-zerocoin");
            }
        }
    }

    return true;
}

bool ContextualCheckTransaction(const CTransaction& tx, CValidationState &state, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    int nHeight = pindexPrev == NULL ? 0 : pindexPrev->nHeight + 1;
    bool fDIP0003Active_context = nHeight >= consensusParams.DIP0003Height;

    if (fDIP0003Active_context) {
        // check version 3 transaction types
        if (tx.nVersion >= 3) {
            if (tx.nType != TRANSACTION_NORMAL &&
                tx.nType != TRANSACTION_PROVIDER_REGISTER &&
                tx.nType != TRANSACTION_PROVIDER_UPDATE_SERVICE &&
                tx.nType != TRANSACTION_PROVIDER_UPDATE_REGISTRAR &&
                tx.nType != TRANSACTION_PROVIDER_UPDATE_REVOKE &&
                tx.nType != TRANSACTION_COINBASE &&
                tx.nType != TRANSACTION_QUORUM_COMMITMENT &&
                tx.nType != TRANSACTION_SPORK) {
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-type");
            }
            if (tx.IsCoinBase() && tx.nType != TRANSACTION_COINBASE)
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-cb-type");
            if (tx.nType == TRANSACTION_SPORK &&
                    !(nHeight >= consensusParams.nEvoSporkStartBlock && nHeight < consensusParams.nEvoSporkStopBlock))
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-type");
        }
        else if (tx.nType != TRANSACTION_NORMAL) {
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-type");
        }
    }
    else {
        if (tx.nVersion >= 3)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-type");
    }

    return true;
}

void LimitMempoolSize(CTxMemPool &pool, size_t limit, unsigned long age) {
    int expired = pool.Expire(GetTime() - age);
    if (expired != 0)
        LogPrint("mempool", "Expired %i transactions from the memory pool\n", expired);

    std::vector<COutPoint> vNoSpendsRemaining;
    pool.TrimToSize(limit, &vNoSpendsRemaining);
    BOOST_FOREACH(const COutPoint& removed, vNoSpendsRemaining)
        pcoinsTip->Uncache(removed);
}

/** Convert CValidationState to a human-readable message for logging */
std::string FormatStateMessage(const CValidationState &state) {
    return strprintf("%s%s (code %i)",
                     state.GetRejectReason(),
                     state.GetDebugMessage().empty() ? "" : ", " + state.GetDebugMessage(),
                     state.GetRejectCode());
}

static bool IsCurrentForFeeEstimation()
{
    AssertLockHeld(cs_main);
    if (IsInitialBlockDownload())
        return false;
    if (chainActive.Tip()->GetBlockTime() < (GetTime() - MAX_FEE_ESTIMATION_TIP_AGE))
        return false;
    if (chainActive.Height() < pindexBestHeader->nHeight - 1)
        return false;
    return true;
}

bool AcceptToMemoryPoolWorker(CTxMemPool& pool, CValidationState& state, const CTransactionRef& ptx, bool fLimitFree,
                              bool* pfMissingInputs, int64_t nAcceptTime, std::list<CTransactionRef>* plTxnReplaced,
                              bool fOverrideMempoolLimit, const CAmount& nAbsurdFee, std::vector<COutPoint>& coins_to_uncache,
                              bool isCheckWalletTransaction, bool markFiroSpendTransactionSerial)
{
    bool fTestNet = Params().GetConsensus().IsTestnet();
    LogPrintf("AcceptToMemoryPoolWorker(), tx.IsSpend()=%s, fTestNet=%s\n", ptx->IsSigmaSpend() || ptx->IsLelantusJoinSplit(), fTestNet);

    const CTransaction& tx = *ptx;
    const uint256 hash = tx.GetHash();
    AssertLockHeld(cs_main);
    if (pfMissingInputs)
        *pfMissingInputs = false;

    const Consensus::Params& consensus = Params().GetConsensus();

    if (tx.IsSigmaMint() || tx.IsSigmaSpend()) {
        if (consensus.nStartSigmaBlacklist != INT_MAX && chainActive.Height() < consensus.nRestartSigmaWithBlacklistCheck)
            return state.DoS(100, error("Sigma is temporarily disabled"),
                             REJECT_INVALID, "bad-txns-zerocoin");
    }

    bool startLelantusRejectSigma = (chainActive.Height() >= consensus.nLelantusStartBlock);
    if (startLelantusRejectSigma) {
        if(tx.IsSigmaMint() || tx.IsSigmaSpend()) {
            return state.DoS(100, error("Sigma transactions no more allowed in mempool"),
                             REJECT_INVALID, "bad-txns-zerocoin");
        }
    } else {
        if(tx.IsLelantusTransaction()) {
            return state.DoS(100, error("Lelantus transactions are not allowed in mempool yet"),
                             REJECT_INVALID, "bad-txns-zerocoin");
        }
    }

    // V3 sigma spends.
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    std::vector<Scalar> zcSpendSerialsV3;
    std::vector<GroupElement> zcMintPubcoinsV3;

    //lelantus
    lelantus::CLelantusState *lelantusState = lelantus::CLelantusState::GetState();
    std::vector<Scalar> lelantusSpendSerials;
    std::vector<GroupElement> lelantusMintPubcoins;
    std::vector<uint64_t> lelantusAmounts;
    {
        LOCK(pool.cs);
        if (tx.IsSigmaSpend()) {
            BOOST_FOREACH(const CTxIn &txin, tx.vin)
            {
                Scalar zcSpendSerial = sigma::GetSigmaSpendSerialNumber(tx, txin);
                Scalar zero;

                if (zcSpendSerial == zero)
                    return state.Invalid(false, REJECT_INVALID, "txn-invalid-zerocoin-spend");
                if (!sigmaState->CanAddSpendToMempool(zcSpendSerial)) {
                    LogPrintf("AcceptToMemoryPool(): sigma serial number %s has been used\n", zcSpendSerial.tostring());
                    return state.Invalid(false, REJECT_CONFLICT, "txn-mempool-conflict");
                }
                zcSpendSerialsV3.push_back(zcSpendSerial);
            }
        }
        else if (tx.IsLelantusJoinSplit()) {
            if (tx.vin.size() > 1) {
                return state.Invalid(false, REJECT_CONFLICT, "txn-invalid-lelantus-joinsplit");
            }
            std::vector<Scalar> serials;
            try {
                serials = lelantus::GetLelantusJoinSplitSerialNumbers(tx, tx.vin[0]);
            }
            catch (CBadTxIn&) {
                return state.Invalid(false, REJECT_CONFLICT, "txn-invalid-lelantus-joinsplit");
            }
            for (const auto& serial : serials) {
                if (!serial.isMember() || serial.isZero())
                    return state.Invalid(false, REJECT_INVALID, "txn-invalid-lelantus-joinsplit-serial");
                if (lelantusState->IsUsedCoinSerial(serial) || pool.lelantusState.HasCoinSerial(serial) ||
                    !sigmaState->CanAddSpendToMempool(serial)) {
                    LogPrintf("AcceptToMemoryPool(): lelantus serial number %s has been used\n", serial.tostring());
                    return state.Invalid(false, REJECT_CONFLICT, "txn-mempool-conflict");
                }
                lelantusSpendSerials.push_back(serial);
            }
        }

        BOOST_FOREACH(const CTxOut &txout, tx.vout)
        {
            if (txout.scriptPubKey.IsSigmaMint()) {
                GroupElement pubCoinValue;
                try {
                    pubCoinValue = sigma::ParseSigmaMintScript(txout.scriptPubKey);
                } catch (std::invalid_argument&) {
                    return state.DoS(100, false, PUBCOIN_NOT_VALIDATE, "bad-txns-zerocoin");
                }
                if (!sigmaState->CanAddMintToMempool(pubCoinValue)) {
                    LogPrintf("AcceptToMemoryPool(): sigma mint with the same value %s is already in the mempool\n", pubCoinValue.tostring());
                    return state.Invalid(false, REJECT_CONFLICT, "txn-mempool-conflict");
                }
                zcMintPubcoinsV3.push_back(pubCoinValue);
            }

            if (txout.scriptPubKey.IsLelantusMint() || txout.scriptPubKey.IsLelantusJMint()) {
                GroupElement pubCoinValue;
                try {
                    lelantus::ParseLelantusMintScript(txout.scriptPubKey, pubCoinValue);
                } catch (std::invalid_argument&) {
                    return state.DoS(100, false, PUBCOIN_NOT_VALIDATE, "bad-txns-zerocoin");
                }
                if (lelantusState->HasCoin(pubCoinValue) || pool.lelantusState.HasMint(pubCoinValue)) {
                    LogPrintf("AcceptToMemoryPool(): lelantus mint with the same value %s is already in the mempool\n", pubCoinValue.tostring());
                    return state.Invalid(false, REJECT_CONFLICT, "txn-mempool-conflict");
                }
                lelantusMintPubcoins.push_back(pubCoinValue);
            }
        }
    }

    if (!CheckTransaction(tx, state, true, hash, false, INT_MAX, isCheckWalletTransaction)) {
        LogPrintf("CheckTransaction() failed!");
        return false; // state filled in by CheckTransaction
    }

    if (!ContextualCheckTransaction(tx, state, Params().GetConsensus(), chainActive.Tip()))
        return error("%s: ContextualCheckTransaction: %s, %s", __func__, hash.ToString(), FormatStateMessage(state));

    if (!pool.IsTransactionAllowed(tx, state)) {
        LogPrintf("AcceptToMemoryPool() can't accept transaction because of active mempool spork\n");
        return false;
    }

    if (tx.nVersion >= 3 && tx.nType == TRANSACTION_QUORUM_COMMITMENT) {
        // quorum commitment is not allowed outside of blocks
        return state.DoS(100, false, REJECT_INVALID, "qc-not-allowed");
    }

    // Coinbase is only valid in a block, not as a loose transaction
    if (tx.IsCoinBase())
        return state.DoS(100, false, REJECT_INVALID, "coinbase");

    // Reject transactions with witness before segregated witness activates (override with -prematurewitness)
    bool witnessEnabled = IsWitnessEnabled(chainActive.Tip(), Params().GetConsensus());
    if (!GetBoolArg("-prematurewitness",false) && tx.HasWitness() && !witnessEnabled) {
        return state.DoS(0, false, REJECT_NONSTANDARD, "no-witness-yet", true);
    }

    // Rather not work on nonstandard transactions (unless -testnet/-regtest)
    std::string reason;
    if (fRequireStandard && !IsStandardTx(tx, reason, witnessEnabled))
        return state.DoS(0, false, REJECT_NONSTANDARD, reason);

    // Only accept nLockTime-using transactions that can be mined in the next
    // block; we don't want our mempool filled up with transactions that can't
    // be mined yet.
    if (!CheckFinalTx(tx, STANDARD_LOCKTIME_VERIFY_FLAGS))
        return state.DoS(0, false, REJECT_NONSTANDARD, "non-final");

    // is it already in the memory pool?
    if (pool.exists(hash))
        return state.Invalid(false, REJECT_ALREADY_KNOWN, "txn-already-in-mempool");

    // Check for conflicts with in-memory transactions
    std::set<uint256> setConflicts;
    {
    LOCK(pool.cs); // protect pool.mapNextTx
    if (!tx.IsSigmaSpend() && !tx.IsLelantusJoinSplit()) {
        BOOST_FOREACH(const CTxIn &txin, tx.vin)
        {
            auto itConflicting = pool.mapNextTx.find(txin.prevout);
            if (itConflicting != pool.mapNextTx.end())
            {
                const CTransaction *ptxConflicting = itConflicting->second;
                if (!setConflicts.count(ptxConflicting->GetHash()))
                {
                    // Allow opt-out of transaction replacement by setting
                    // nSequence >= maxint-1 on all inputs.
                    //
                    // maxint-1 is picked to still allow use of nLockTime by
                    // non-replaceable transactions. All inputs rather than just one
                    // is for the sake of multi-party protocols, where we don't
                    // want a single party to be able to disable replacement.
                    //
                    // The opt-out ignores descendants as anyone relying on
                    // first-seen mempool behavior should be checking all
                    // unconfirmed ancestors anyway; doing otherwise is hopelessly
                    // insecure.
                    bool fReplacementOptOut = true;
                    if (fEnableReplacement)
                    {
                        BOOST_FOREACH(const CTxIn &_txin, ptxConflicting->vin)
                        {
                            if (_txin.nSequence < std::numeric_limits<unsigned int>::max()-1)
                            {
                                fReplacementOptOut = false;
                                break;
                            }
                        }
                        if (fReplacementOptOut)
                            return state.Invalid(false, REJECT_CONFLICT, "txn-mempool-conflict");

                        setConflicts.insert(ptxConflicting->GetHash());
                    }
                }
            }
        }
    }

    }

    {
        CCoinsView dummy;
        CCoinsViewCache view(&dummy);
        CAmount nValueIn = 0;
        LockPoints lp;
        {
        LOCK(pool.cs);
        CCoinsViewMemPool viewMemPool(pcoinsTip, pool);
        view.SetBackend(viewMemPool);

        // do we already have it?
        for (size_t out = 0; out < tx.vout.size(); out++) {
            COutPoint outpoint(hash, out);
            bool had_coin_in_cache = pcoinsTip->HaveCoinInCache(outpoint);
            if (view.HaveCoin(outpoint)) {
                if (!had_coin_in_cache) {
                    coins_to_uncache.push_back(outpoint);
                }
                return state.Invalid(false, REJECT_ALREADY_KNOWN, "txn-already-known");
            }
        }

        if (!tx.IsSigmaSpend() && !tx.IsLelantusJoinSplit()) {
            // do all inputs exist?
            BOOST_FOREACH(const CTxIn txin, tx.vin) {
                if (!pcoinsTip->HaveCoinInCache(txin.prevout)) {
                    coins_to_uncache.push_back(txin.prevout);
                }
                if (!view.HaveCoin(txin.prevout)) {
                    if (pfMissingInputs) {
                        *pfMissingInputs = true;
                    }
                    return false; // fMissingInputs and !state.IsInvalid() is used to detect this condition, don't set state.Invalid()
                }
            }

            // Bring the best block into scope
            view.GetBestBlock();

            nValueIn = view.GetValueIn(tx);

            // Only accept BIP68 sequence locked transactions that can be mined in the next
            // block; we don't want our mempool filled up with transactions that can't
            // be mined yet.
            // Must keep pool.cs for this unless we change CheckSequenceLocks to take a
            // CoinsViewCache instead of create its own
            //            if (!CheckSequenceLocks(tx, STANDARD_LOCKTIME_VERIFY_FLAGS, &lp))
            //                return state.DoS(0, false, REJECT_NONSTANDARD, "non-BIP68-final");
            //
        }
        else if (tx.IsSigmaSpend()) {
            nValueIn = sigma::GetSigmaSpendInput(tx);
        }

        // we have all inputs cached now, so switch back to dummy, so we don't need to keep lock on mempool
        view.SetBackend(dummy);
        } // LOCK

        {
            // Check for non-standard pay-to-script-hash in inputs
            if (fRequireStandard && !AreInputsStandard(tx, view))
                return state.Invalid(false, REJECT_NONSTANDARD, "bad-txns-nonstandard-inputs");

            // Check for non-standard witness in P2WSH
            if (tx.HasWitness() && fRequireStandard && !IsWitnessStandard(tx, view))
                return state.DoS(0, false, REJECT_NONSTANDARD, "bad-witness-nonstandard", true);

            int64_t nSigOpsCost = GetTransactionSigOpCost(tx, view, STANDARD_SCRIPT_VERIFY_FLAGS);

            CAmount nValueOut = tx.GetValueOut();
            CAmount nFees;
            if (!tx.IsLelantusJoinSplit()) {
                nFees = nValueIn - nValueOut;
            } else {
                try {
                    nFees = lelantus::ParseLelantusJoinSplit(tx.vin[0])->getFee();
                }
                catch (CBadTxIn&) {
                    return state.DoS(0, false, REJECT_INVALID, "unable to parse joinsplit");
                }
            }
            // nModifiedFees includes any fee deltas from PrioritiseTransaction
            CAmount nModifiedFees = nFees;
            double nPriorityDummy = 0;
            pool.ApplyDeltas(hash, nPriorityDummy, nModifiedFees);

            CAmount inChainInputValue = 0;
            bool fSpendsCoinbase = false;
            if (!tx.IsSigmaSpend() && !tx.IsLelantusJoinSplit()) {
                // Keep track of transactions that spend a coinbase, which we re-scan
                // during reorgs to ensure COINBASE_MATURITY is still met.
                BOOST_FOREACH(const CTxIn &txin, tx.vin) {
                    const Coin &coin = view.AccessCoin(txin.prevout);
                    if (coin.IsCoinBase()) {
                        fSpendsCoinbase = true;
                        break;
                    }
                }
            }

            CTxMemPoolEntry entry(ptx, nFees, nAcceptTime, chainActive.Height(),
                                inChainInputValue, fSpendsCoinbase, nSigOpsCost, lp);
            unsigned int nSize = entry.GetTxSize();

            // Check that the transaction doesn't have an excessive number of
            // sigops, making it impossible to mine. Since the coinbase transaction
            // itself can contain sigops MAX_STANDARD_TX_SIGOPS is less than
            // MAX_BLOCK_SIGOPS; we still consider this an invalid rather than
            // merely non-standard transaction.
            /*
            if (nSigOpsCost > MAX_STANDARD_TX_SIGOPS_COST)
                return state.DoS(0, false, REJECT_NONSTANDARD, "bad-txns-too-many-sigops", false,
                    strprintf("%d", nSigOpsCost));

            CAmount mempoolRejectFee = pool.GetMinFee(GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000).GetFee(nSize);
            if (mempoolRejectFee > 0 && nModifiedFees < mempoolRejectFee) {
                return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "mempool min fee not met", false, strprintf("%d < %d", nFees, mempoolRejectFee));
            } else if (GetBoolArg("-relaypriority", DEFAULT_RELAYPRIORITY) && nModifiedFees < ::minRelayTxFee.GetFee(nSize) && !AllowFree(entry.GetPriority(chainActive.Height() + 1))) {
                // Require that free transactions have sufficient priority to be mined in the next block.
                return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "insufficient priority");
            }
            */

            // Continuously rate-limit free (really, very-low-fee) transactions
            // This mitigates 'penny-flooding' -- sending thousands of free transactions just to
            // be annoying or make others' transactions take longer to confirm.
            if (fLimitFree && nModifiedFees < ::minRelayTxFee.GetFee(nSize))
            {
                static CCriticalSection csFreeLimiter;
                static double dFreeCount;
                static int64_t nLastTime;
                int64_t nNow = GetTime();

                LOCK(csFreeLimiter);

                // Use an exponentially decaying ~10-minute window:
                dFreeCount *= pow(1.0 - 1.0/600.0, (double)(nNow - nLastTime));
                nLastTime = nNow;
                // -limitfreerelay unit is thousand-bytes-per-minute
                // At default rate it would take over a month to fill 1GB
                if (dFreeCount + nSize >= GetArg("-limitfreerelay", DEFAULT_LIMITFREERELAY) * 10 * 1000)
                    return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "rate limited free transaction");
                LogPrint("mempool", "Rate limit dFreeCount: %g => %g\n", dFreeCount, dFreeCount+nSize);
                dFreeCount += nSize;
            }

            /*
            if (nAbsurdFee && nFees > nAbsurdFee)
                return state.Invalid(false,
                    REJECT_HIGHFEE, "absurdly-high-fee",
                    strprintf("%d > %d", nFees, nAbsurdFee));
            */

            if (nAbsurdFee && nFees > nAbsurdFee)
                return state.Invalid(false,
                    REJECT_HIGHFEE, "absurdly-high-fee",
                    strprintf("%d > %d", nFees, nAbsurdFee));

            // Calculate in-mempool ancestors, up to a limit.
            CTxMemPool::setEntries setAncestors;
            size_t nLimitAncestors = GetArg("-limitancestorcount", DEFAULT_ANCESTOR_LIMIT);
            size_t nLimitAncestorSize = GetArg("-limitancestorsize", DEFAULT_ANCESTOR_SIZE_LIMIT)*1000;
            size_t nLimitDescendants = GetArg("-limitdescendantcount", DEFAULT_DESCENDANT_LIMIT);
            size_t nLimitDescendantSize = GetArg("-limitdescendantsize", DEFAULT_DESCENDANT_SIZE_LIMIT)*1000;
            std::string errString;
            if (!pool.CalculateMemPoolAncestors(entry, setAncestors, nLimitAncestors, nLimitAncestorSize, nLimitDescendants, nLimitDescendantSize, errString)) {
                return state.DoS(0, false, REJECT_NONSTANDARD, "too-long-mempool-chain", false, errString);
            }

            // check special TXs after all the other checks. If we'd do this before the other checks, we might end up
            // DoS scoring a node for non-critical errors, e.g. duplicate keys because a TX is received that was already
            // mined
            if (!CheckSpecialTx(tx, chainActive.Tip(), state))
                return false;

            if (pool.existsProviderTxConflict(tx)) {
                return state.DoS(0, false, REJECT_DUPLICATE, "protx-dup");
            }

            // A transaction that spends outputs that would be replaced by it is invalid. Now
            // that we have the set of all ancestors we can detect this
            // pathological case by making sure setConflicts and setAncestors don't
            // intersect.
            BOOST_FOREACH(CTxMemPool::txiter ancestorIt, setAncestors)
            {
                const uint256 &hashAncestor = ancestorIt->GetTx().GetHash();
                if (setConflicts.count(hashAncestor))
                {
                    return state.DoS(10, false,
                                     REJECT_INVALID, "bad-txns-spends-conflicting-tx", false,
                                     strprintf("%s spends conflicting transaction %s",
                                               hash.ToString(),
                                               hashAncestor.ToString()));
                }
            }

            // Check if it's economically rational to mine this transaction rather
            // than the ones it replaces.
            CAmount nConflictingFees = 0;
            size_t nConflictingSize = 0;
            uint64_t nConflictingCount = 0;
            CTxMemPool::setEntries allConflicting;

            // If we don't hold the lock allConflicting might be incomplete; the
            // subsequent RemoveStaged() and addUnchecked() calls don't guarantee
            // mempool consistency for us.
            LOCK(pool.cs);
            const bool fReplacementTransaction = setConflicts.size();
            if (fReplacementTransaction)
            {
                CFeeRate newFeeRate(nModifiedFees, nSize);
                std::set<uint256> setConflictsParents;
                const int maxDescendantsToVisit = 100;
                CTxMemPool::setEntries setIterConflicting;
                BOOST_FOREACH(const uint256 &hashConflicting, setConflicts)
                {
                    CTxMemPool::txiter mi = pool.mapTx.find(hashConflicting);
                    if (mi == pool.mapTx.end())
                        continue;

                    // Save these to avoid repeated lookups
                    setIterConflicting.insert(mi);

                    // Don't allow the replacement to reduce the feerate of the
                    // mempool.
                    //
                    // We usually don't want to accept replacements with lower
                    // feerates than what they replaced as that would lower the
                    // feerate of the next block. Requiring that the feerate always
                    // be increased is also an easy-to-reason about way to prevent
                    // DoS attacks via replacements.
                    //
                    // The mining code doesn't (currently) take children into
                    // account (CPFP) so we only consider the feerates of
                    // transactions being directly replaced, not their indirect
                    // descendants. While that does mean high feerate children are
                    // ignored when deciding whether or not to replace, we do
                    // require the replacement to pay more overall fees too,
                    // mitigating most cases.
                    CFeeRate oldFeeRate(mi->GetModifiedFee(), mi->GetTxSize());
                    if (newFeeRate <= oldFeeRate)
                    {
                        return state.DoS(0, false,
                                        REJECT_INSUFFICIENTFEE, "insufficient fee", false,
                                        strprintf("rejecting replacement %s; new feerate %s <= old feerate %s",
                                                hash.ToString(),
                                                newFeeRate.ToString(),
                                                oldFeeRate.ToString()));
                    }

                    BOOST_FOREACH(const CTxIn &txin, mi->GetTx().vin)
                    {
                        setConflictsParents.insert(txin.prevout.hash);
                    }

                    nConflictingCount += mi->GetCountWithDescendants();
                }
                // This potentially overestimates the number of actual descendants
                // but we just want to be conservative to avoid doing too much
                // work.
                if (nConflictingCount <= maxDescendantsToVisit) {
                    // If not too many to replace, then calculate the set of
                    // transactions that would have to be evicted
                    BOOST_FOREACH(CTxMemPool::txiter it, setIterConflicting) {
                        pool.CalculateDescendants(it, allConflicting);
                    }
                    BOOST_FOREACH(CTxMemPool::txiter it, allConflicting) {
                        nConflictingFees += it->GetModifiedFee();
                        nConflictingSize += it->GetTxSize();
                    }
                } else {
                    return state.DoS(0, false,
                            REJECT_NONSTANDARD, "too many potential replacements", false,
                            strprintf("rejecting replacement %s; too many potential replacements (%d > %d)\n",
                                hash.ToString(),
                                nConflictingCount,
                                maxDescendantsToVisit));
                }

                for (unsigned int j = 0; j < tx.vin.size(); j++)
                {
                    // We don't want to accept replacements that require low
                    // feerate junk to be mined first. Ideally we'd keep track of
                    // the ancestor feerates and make the decision based on that,
                    // but for now requiring all new inputs to be confirmed works.
                    if (!setConflictsParents.count(tx.vin[j].prevout.hash))
                    {
                        // Rather than check the UTXO set - potentially expensive -
                        // it's cheaper to just check if the new input refers to a
                        // tx that's in the mempool.
                        if (pool.mapTx.find(tx.vin[j].prevout.hash) != pool.mapTx.end())
                            return state.DoS(0, false,
                                            REJECT_NONSTANDARD, "replacement-adds-unconfirmed", false,
                                            strprintf("replacement %s adds unconfirmed input, idx %d",
                                                    hash.ToString(), j));
                    }
                }

                // The replacement must pay greater fees than the transactions it
                // replaces - if we did the bandwidth used by those conflicting
                // transactions would not be paid for.
                if (nModifiedFees < nConflictingFees)
                {
                    return state.DoS(0, false,
                                    REJECT_INSUFFICIENTFEE, "insufficient fee", false,
                                    strprintf("rejecting replacement %s, less fees than conflicting txs; %s < %s",
                                            hash.ToString(), FormatMoney(nModifiedFees), FormatMoney(nConflictingFees)));
                }

                // Finally in addition to paying more fees than the conflicts the
                // new transaction must pay for its own bandwidth.
                CAmount nDeltaFees = nModifiedFees - nConflictingFees;
                if (nDeltaFees < ::minRelayTxFee.GetFee(nSize))
                {
                    return state.DoS(0, false,
                            REJECT_INSUFFICIENTFEE, "insufficient fee", false,
                            strprintf("rejecting replacement %s, not enough additional fees to relay; %s < %s",
                                    hash.ToString(),
                                    FormatMoney(nDeltaFees),
                                    FormatMoney(::minRelayTxFee.GetFee(nSize))));
                }
            }

            unsigned int scriptVerifyFlags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC;
            /*
            if (!Params().RequireStandard()) {
                scriptVerifyFlags = GetArg("-promiscuousmempoolflags", scriptVerifyFlags);
            }
            */

            // Check against previous transactions
            // This is done last to help prevent CPU exhaustion denial-of-service attacks.
            PrecomputedTransactionData txdata(tx);
            // don't check inputs for transactions in whitelist
            bool isInWhitelist = consensus.txidWhitelist.count(tx.GetHash()) > 0;
            if (!CheckInputs(tx, state, view, !isInWhitelist, scriptVerifyFlags, true, txdata)) {
                // SCRIPT_VERIFY_CLEANSTACK requires SCRIPT_VERIFY_WITNESS, so we
                // need to turn both off, and compare against just turning off CLEANSTACK
                // to see if the failure is specifically due to witness validation.
                /*
                CValidationState stateDummy; // Want reported failures to be from first CheckInputs
                if (!tx.HasWitness() && CheckInputs(tx, stateDummy, view, true, scriptVerifyFlags & ~(SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_CLEANSTACK), true, txdata) &&
                    !CheckInputs(tx, stateDummy, view, true, scriptVerifyFlags & ~SCRIPT_VERIFY_CLEANSTACK, true, txdata)) {
                    // Only the witness is missing, so the transaction itself may be fine.
                    state.SetCorruptionPossible();
                }
                */
                return false;
            }

            // Check again against just the consensus-critical mandatory script
            // verification flags, in case of bugs in the standard flags that cause
            // transactions to pass as valid when they're actually invalid. For
            // instance the STRICTENC flag was incorrectly allowing certain
            // CHECKSIG NOT scripts to pass, even though they were invalid.
            //
            // There is a similar check in CreateNewBlock() to prevent creating
            // invalid blocks, however allowing such transactions into the mempool
            // can be exploited as a DoS attack.
            /*
            if (!CheckInputs(tx, state, view, true, MANDATORY_SCRIPT_VERIFY_FLAGS, true, txdata))
            {
                return error("%s: BUG! PLEASE REPORT THIS! ConnectInputs failed against MANDATORY but not STANDARD flags %s, %s",
                    __func__, hash.ToString(), FormatStateMessage(state));
            }
            */

            // Remove conflicting transactions from the mempool
            BOOST_FOREACH(const CTxMemPool::txiter it, allConflicting)
            {
                LogPrint("mempool", "replacing tx %s with %s for %s BTC additional fees, %d delta bytes\n",
                         it->GetTx().GetHash().ToString(),
                         hash.ToString(),
                         FormatMoney(nModifiedFees - nConflictingFees),
                         (int)nSize - (int)nConflictingSize);
                if (plTxnReplaced)
                    plTxnReplaced->push_back(it->GetSharedTx());
            }
            pool.RemoveStaged(allConflicting, false);

            // This transaction should only count for fee estimation if it isn't a
            // BIP 125 replacement transaction (may not be widely supported), the
            // node is not behind, and the transaction is not dependent on any other
            // transactions in the mempool.
            bool validForFeeEstimation = !fReplacementTransaction && IsCurrentForFeeEstimation() && pool.HasNoInputsOf(tx);

            // Store transaction in memory
            pool.addUnchecked(hash, entry, setAncestors, validForFeeEstimation);

            // Add memory address index
            if (fAddressIndex) {
                pool.addAddressIndex(entry, view);
            }

            // Add memory spent index
            if (fSpentIndex) {
                pool.addSpentIndex(entry, view);
            }

            // trim mempool and check if tx was trimmed
            if (!fOverrideMempoolLimit) {
                LimitMempoolSize(pool, GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000, GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60);
                if (!pool.exists(hash))
                    return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "mempool full");
            }
        }
    }

    if (tx.IsSigmaSpend()) {
        if(markFiroSpendTransactionSerial)
            sigmaState->AddSpendToMempool(zcSpendSerialsV3, hash);
        LogPrintf("Updating mint tracker state from Mempool..");
#ifdef ENABLE_WALLET
        if (!GetBoolArg("-disablewallet", false) && pwalletMain->zwallet) {
            LogPrintf("Updating spend state from Mempool..");
            pwalletMain->zwallet->GetTracker().UpdateSpendStateFromMempool(zcSpendSerialsV3);
        }
#endif
    }

    if (tx.IsLelantusJoinSplit()) {
        if(markFiroSpendTransactionSerial) {
            for (const auto &spendSerial: lelantusSpendSerials)
                pool.lelantusState.AddSpendToMempool(spendSerial, hash);
        }
        LogPrintf("Updating mint tracker state from Mempool..");
#ifdef ENABLE_WALLET
        if (!GetBoolArg("-disablewallet", false) && pwalletMain->zwallet) {
            LogPrintf("Updating spend state from Mempool..");
            pwalletMain->zwallet->GetTracker().UpdateJoinSplitStateFromMempool(lelantusSpendSerials);
            pwalletMain->zwallet->GetTracker().UpdateSpendStateFromMempool(lelantusSpendSerials);
        }
#endif
    }

    if(markFiroSpendTransactionSerial) {
        sigmaState->AddMintsToMempool(zcMintPubcoinsV3);
        for (const auto &pubCoin: lelantusMintPubcoins)
            pool.lelantusState.AddMintToMempool(pubCoin);
    }


#ifdef ENABLE_WALLET
    if(tx.IsSigmaMint() && !GetBoolArg("-disablewallet", false) && pwalletMain->zwallet) {
        LogPrintf("Updating mint state from Mempool..");
        pwalletMain->zwallet->GetTracker().UpdateMintStateFromMempool(zcMintPubcoinsV3);
    }

    if(tx.IsLelantusMint() && !GetBoolArg("-disablewallet", false) && pwalletMain->zwallet) {
        LogPrintf("Updating mint state from Mempool..");
        BOOST_FOREACH(const CTxOut &txout, tx.vout)
        {
            if (txout.scriptPubKey.IsLelantusMint() || txout.scriptPubKey.IsLelantusJMint()) {
                GroupElement pubCoinValue;
                uint64_t amount = 0;
                try {
                    if (txout.scriptPubKey.IsLelantusMint()) {
                        lelantus::ParseLelantusMintScript(txout.scriptPubKey, pubCoinValue);
                        amount = txout.nValue;
                    } else {
                        std::vector<unsigned char> encryptedValue;
                        lelantus::ParseLelantusJMintScript(txout.scriptPubKey, pubCoinValue, encryptedValue);
                        if(!pwalletMain->DecryptMintAmount(encryptedValue, pubCoinValue, amount))
                            amount = 0;
                    }
                } catch (std::invalid_argument&) {
                    return state.DoS(100, false, PUBCOIN_NOT_VALIDATE, "bad-txns-zerocoin");
                }
                lelantusAmounts.push_back(amount);
            }
        }
        pwalletMain->zwallet->GetTracker().UpdateLelantusMintStateFromMempool(lelantusMintPubcoins, lelantusAmounts);
    }
#endif
    GetMainSignals().SyncTransaction(tx, NULL, CMainSignals::SYNC_TRANSACTION_NOT_IN_BLOCK);

    LogPrintf("AcceptToMemoryPoolWorker -> OK\n");

    return true;
}

bool AcceptToMemoryPoolWithTime(CTxMemPool& pool, CValidationState &state, const CTransactionRef &tx, bool fLimitFree,
                        bool* pfMissingInputs, int64_t nAcceptTime, std::list<CTransactionRef>* plTxnReplaced,
                        bool fOverrideMempoolLimit, const CAmount nAbsurdFee,
                        bool isCheckWalletTransaction, bool markFiroSpendTransactionSerial)
{
    LogPrintf("AcceptToMemoryPool(), transaction: %s\n", tx->GetHash().ToString());
    std::vector<COutPoint> coins_to_uncache;
    bool res = AcceptToMemoryPoolWorker(pool, state, tx, fLimitFree, pfMissingInputs, nAcceptTime, plTxnReplaced, fOverrideMempoolLimit, nAbsurdFee, coins_to_uncache, isCheckWalletTransaction, markFiroSpendTransactionSerial);
    if (!res) {
        BOOST_FOREACH(const COutPoint& hashTx, coins_to_uncache)
            pcoinsTip->Uncache(hashTx);
    }
    // After we've (potentially) uncached entries, ensure our coins cache is still within its size limits
    CValidationState stateDummy;
    FlushStateToDisk(stateDummy, FLUSH_STATE_PERIODIC);
    return res;
}

bool AcceptToMemoryPool(CTxMemPool& pool, CValidationState &state, const CTransactionRef &tx, bool fLimitFree,
                        bool* pfMissingInputs, std::list<CTransactionRef>* plTxnReplaced,
                        bool fOverrideMempoolLimit, const CAmount nAbsurdFee,
                        bool isCheckWalletTransaction, bool markFiroSpendTransactionSerial)
{
    return AcceptToMemoryPoolWithTime(pool, state, tx, fLimitFree, pfMissingInputs, GetTime(), plTxnReplaced, fOverrideMempoolLimit, nAbsurdFee, isCheckWalletTransaction, markFiroSpendTransactionSerial);
}


bool AcceptToMemoryPool(CTxPoolAggregate& poolAggregate, CValidationState &state, const CTransactionRef &tx, bool fLimitFree,
                        bool* pfMissingInputs, std::list<CTransactionRef>* plTxnReplaced,
                        bool fOverrideMempoolLimit, const CAmount nAbsurdFee, bool isCheckWalletTransaction, bool markFiroSpendTransactionSerial) {
    bool res = AcceptToMemoryPool(mempool, state, tx, fLimitFree, pfMissingInputs, plTxnReplaced, fOverrideMempoolLimit, nAbsurdFee, isCheckWalletTransaction, markFiroSpendTransactionSerial);
    AcceptToMemoryPool(txpools.getStemTxPool(), state, tx, fLimitFree, pfMissingInputs, plTxnReplaced, fOverrideMempoolLimit, nAbsurdFee, isCheckWalletTransaction, false);
    return res;
}


/** Return transaction in txOut, and if it was found inside a block, its hash is placed in hashBlock */
bool GetTransaction(const uint256 &hash, CTransactionRef &txOut, const Consensus::Params& consensusParams, uint256 &hashBlock, bool fAllowSlow)
{
    CBlockIndex *pindexSlow = NULL;

    LOCK(cs_main);

    CTransactionRef ptx = mempool.get(hash);
    if (ptx)
    {
        txOut = ptx;
        return true;
    }

    if (fTxIndex) {
        CDiskTxPos postx;
        if (pblocktree->ReadTxIndex(hash, postx)) {
            CAutoFile file(OpenBlockFile(postx, true), SER_DISK, CLIENT_VERSION);
            if (file.IsNull())
                return error("%s: OpenBlockFile failed", __func__);
            CBlockHeader header;
            try {
                file >> header;
                fseek(file.Get(), postx.nTxOffset, SEEK_CUR);
                file >> txOut;
            } catch (const std::exception& e) {
                return error("%s: Deserialize or I/O error - %s", __func__, e.what());
            }
            hashBlock = header.GetHash();
            if (txOut->GetHash() != hash)
                return error("%s: txid mismatch", __func__);
            return true;
        }
    }

    if (fAllowSlow) { // use coin database to locate block that contains transaction, and scan it
        const Coin& coin = AccessByTxid(*pcoinsTip, hash);
        if (!coin.IsSpent()) pindexSlow = chainActive[coin.nHeight];
    }

    if (pindexSlow) {
        CBlock block;
        if (ReadBlockFromDisk(block, pindexSlow, consensusParams)) {
            for (const auto& tx : block.vtx) {
                if (tx->GetHash() == hash) {
                    txOut = tx;
                    hashBlock = pindexSlow->GetBlockHash();
                    return true;
                }
            }
        }
    }

    return false;
}

bool GetTimestampIndex(const unsigned int &high, const unsigned int &low, std::vector<uint256> &hashes)
{
    if (!fTimestampIndex)
        return error("Timestamp index not enabled");

    if (!pblocktree->ReadTimestampIndex(high, low, hashes))
        return error("Unable to get hashes for timestamps");

    return true;
}


bool GetSpentIndex(CSpentIndexKey &key, CSpentIndexValue &value)
{
    if (!fSpentIndex)
        return false;

    if (mempool.getSpentIndex(key, value))
        return true;

    if (!pblocktree->ReadSpentIndex(key, value))
        return false;

    return true;
}

bool GetAddressIndex(uint160 addressHash, AddressType type,
                     std::vector<std::pair<CAddressIndexKey, CAmount> > &addressIndex, int start, int end)
{
    if (!fAddressIndex)
        return error("address index not enabled");

    if (!pblocktree->ReadAddressIndex(addressHash, type, addressIndex, start, end))
        return error("unable to get txids for address");

    return true;
}

bool GetAddressUnspent(uint160 addressHash, AddressType type,
                       std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > &unspentOutputs)
{
    if (!fAddressIndex)
        return error("address index not enabled");

    if (!pblocktree->ReadAddressUnspentIndex(addressHash, type, unspentOutputs))
        return error("unable to get txids for address");

    return true;
}



//////////////////////////////////////////////////////////////////////////////
//
// CBlock and CBlockIndex
//

bool WriteBlockToDisk(const CBlock& block, CDiskBlockPos& pos, const CMessageHeader::MessageStartChars& messageStart)
{
    // Open history file to append
    CAutoFile fileout(OpenBlockFile(pos), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("WriteBlockToDisk: OpenBlockFile failed");

    // Write index header
    unsigned int nSize = GetSerializeSize(fileout, block);
    fileout << FLATDATA(messageStart) << nSize;

    // Write block
    long fileOutPos = ftell(fileout.Get());
    if (fileOutPos < 0)
        return error("WriteBlockToDisk: ftell failed");
    pos.nPos = (unsigned int)fileOutPos;
    fileout << block;

    return true;
}

bool ReadBlockFromDisk(CBlock& block, const CDiskBlockPos& pos, int nHeight, const Consensus::Params& consensusParams)
{
    block.SetNull();

    // Open history file to read
    CAutoFile filein(OpenBlockFile(pos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return error("ReadBlockFromDisk: OpenBlockFile failed for %s", pos.ToString());

    // Read block
    try {
        filein >> block;
    }
    catch (const std::exception &e) {
        return error("%s: Deserialize or I/O error - %s at %s", __func__, e.what(), pos.ToString());
    }

    // Firo - MTP
    if (!CheckMerkleTreeProof(block, consensusParams)){
    	return error("ReadBlockFromDisk: CheckMerkleTreeProof: Errors in block header at %s", pos.ToString());
    }

    // Check the header
    if (!CheckProofOfWork(block.GetPoWHash(nHeight), block.nBits, consensusParams))
        return error("ReadBlockFromDisk: CheckProofOfWork: Errors in block header at %s", pos.ToString());

    return true;
}

bool ReadBlockFromDisk(CBlock &block, const CBlockIndex *pindex, const Consensus::Params &consensusParams) {
    if (!ReadBlockFromDisk(block, pindex->GetBlockPos(), pindex->nHeight, consensusParams))
        return false;

    if (block.GetHash() != pindex->GetBlockHash()) {
        return error("ReadBlockFromDisk(CBlock&, CBlockIndex*): GetHash() doesn't match index for %s at %s",
                     pindex->ToString(), pindex->GetBlockPos().ToString());
    }
    return true;
}

bool ReadBlockHeaderFromDisk(CBlock &block, const CDiskBlockPos &pos) {
    CAutoFile filein(OpenBlockFile(pos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return error("ReadBlockFromDisk: OpenBlockFile failed for %s", pos.ToString());

    try {
        block.SerializationOp(filein, CBlockHeader::CReadBlockHeader());
    }
    catch (const std::exception &e) {
        return error("%s: Deserialize or I/O error - %s at %s", __func__, e.what(), pos.ToString());
    }

    return true;
}

CAmount GetBlockSubsidyWithMTPFlag(int nHeight, const Consensus::Params &consensusParams, bool fMTP) {
    // Genesis block is 0 coin
    if (nHeight == 0)
        return 0;

    // Subsidy is cut in half after nSubsidyHalvingFirst block, then every nSubsidyHalvingInterval blocks.
    // After block nSubsidyHalvingStopBlock there will be no subsidy at all
    if (nHeight >= consensusParams.nSubsidyHalvingStopBlock)
        return 0;
    int halvings = nHeight < consensusParams.nSubsidyHalvingFirst ? 0 : (nHeight - consensusParams.nSubsidyHalvingFirst) / consensusParams.nSubsidyHalvingInterval + 1;
    // Force block reward to zero when right shift is undefined.
    if (halvings >= 64)
        return 0;

    CAmount nSubsidy = 50 * COIN;
    nSubsidy >>= halvings;

    if (nHeight > 0 && fMTP)
        nSubsidy /= consensusParams.nMTPRewardReduction;

    return nSubsidy;
}

CAmount GetBlockSubsidy(int nHeight, const Consensus::Params &consensusParams, int nTime) {
    return GetBlockSubsidyWithMTPFlag(nHeight, consensusParams, nTime >= (int)consensusParams.nMTPSwitchTime);
}

CAmount GetMasternodePayment(int nHeight, CAmount blockValue)
{
    const Consensus::Params &params = Params().GetConsensus();
    if (nHeight >= params.nSubsidyHalvingFirst)
        return blockValue*params.stage2ZnodeShare/100;
    else
        return blockValue*3/10; // 30%
}

bool IsInitialBlockDownload() {
//    const CChainParams &chainParams = Params();
    // Once this function has returned false, it must remain false.
    static std::atomic<bool> latchToFalse{false};
    // Optimization: pre-test latch before taking the lock.
    if (latchToFalse.load(std::memory_order_relaxed))
        return false;
    LOCK(cs_main);
    if (latchToFalse.load(std::memory_order_relaxed))
        return false;
    if (fImporting || fReindex)
        return true;
    if (chainActive.Tip() == NULL)
        return true;
//    if (chainActive.Tip()->nChainWork < UintToArith256(chainParams.GetConsensus().nMinimumChainWork))
//        return true;
    if (chainActive.Tip()->GetBlockTime() < (GetTime() - nMaxTipAge))
        return true;
    latchToFalse.store(true, std::memory_order_relaxed);
    return false;
}

CBlockIndex *pindexBestForkTip = NULL, *pindexBestForkBase = NULL;

void AlertNotify(const std::string& strMessage)
{
    uiInterface.NotifyAlertChanged();
    std::string strCmd = GetArg("-alertnotify", "");
    if (strCmd.empty()) return;

    // Alert text should be plain ascii coming from a trusted source, but to
    // be safe we first strip anything not in safeChars, then add single quotes around
    // the whole string before passing it to the shell:
    std::string singleQuote("'");
    std::string safeStatus = SanitizeString(strMessage);
    safeStatus = singleQuote+safeStatus+singleQuote;
    boost::replace_all(strCmd, "%s", safeStatus);

    boost::thread t(runCommand, strCmd); // thread runs free
}

void CheckForkWarningConditions()
{
    AssertLockHeld(cs_main);
    // Before we get past initial download, we cannot reliably alert about forks
    // (we assume we don't get stuck on a fork before finishing our initial sync)
    if (IsInitialBlockDownload())
        return;

    // If our best fork is no longer within 72 blocks (+/- 12 hours if no one mines it)
    // of our head, drop it
    if (pindexBestForkTip && chainActive.Height() - pindexBestForkTip->nHeight >= 72)
        pindexBestForkTip = NULL;

    if (pindexBestForkTip || (pindexBestInvalid && pindexBestInvalid->nChainWork > chainActive.Tip()->nChainWork + (GetBlockProof(*chainActive.Tip()) * 6)))
    {
        if (!GetfLargeWorkForkFound() && pindexBestForkBase)
        {
            std::string warning = std::string("'Warning: Large-work fork detected, forking after block ") +
                pindexBestForkBase->phashBlock->ToString() + std::string("'");
            AlertNotify(warning);
        }
        if (pindexBestForkTip && pindexBestForkBase)
        {
            LogPrintf("%s: Warning: Large valid fork found\n  forking the chain at height %d (%s)\n  lasting to height %d (%s).\nChain state database corruption likely.\n", __func__,
                   pindexBestForkBase->nHeight, pindexBestForkBase->phashBlock->ToString(),
                   pindexBestForkTip->nHeight, pindexBestForkTip->phashBlock->ToString());
            SetfLargeWorkForkFound(true);
        }
        else
        {
            LogPrintf("%s: Warning: Found invalid chain at least ~6 blocks longer than our best chain.\nChain state database corruption likely.\n", __func__);
            SetfLargeWorkInvalidChainFound(true);
        }
    }
    else
    {
        SetfLargeWorkForkFound(false);
        SetfLargeWorkInvalidChainFound(false);
    }
}

void CheckForkWarningConditionsOnNewFork(CBlockIndex* pindexNewForkTip)
{
    AssertLockHeld(cs_main);
    // If we are on a fork that is sufficiently large, set a warning flag
    CBlockIndex* pfork = pindexNewForkTip;
    CBlockIndex* plonger = chainActive.Tip();
    while (pfork && pfork != plonger)
    {
        while (plonger && plonger->nHeight > pfork->nHeight)
            plonger = plonger->pprev;
        if (pfork == plonger)
            break;
        pfork = pfork->pprev;
    }

    // We define a condition where we should warn the user about as a fork of at least 7 blocks
    // with a tip within 72 blocks (+/- 12 hours if no one mines it) of ours
    // We use 7 blocks rather arbitrarily as it represents just under 10% of sustained network
    // hash rate operating on the fork.
    // or a chain that is entirely longer than ours and invalid (note that this should be detected by both)
    // We define it this way because it allows us to only store the highest fork tip (+ base) which meets
    // the 7-block condition and from this always have the most-likely-to-cause-warning fork
    if (pfork && (!pindexBestForkTip || (pindexBestForkTip && pindexNewForkTip->nHeight > pindexBestForkTip->nHeight)) &&
            pindexNewForkTip->nChainWork - pfork->nChainWork > (GetBlockProof(*pfork) * 7) &&
            chainActive.Height() - pindexNewForkTip->nHeight < 72)
    {
        pindexBestForkTip = pindexNewForkTip;
        pindexBestForkBase = pfork;
    }

    CheckForkWarningConditions();
}

void static InvalidChainFound(CBlockIndex* pindexNew)
{
    if (!pindexBestInvalid || pindexNew->nChainWork > pindexBestInvalid->nChainWork)
        pindexBestInvalid = pindexNew;

    LogPrintf("%s: invalid block=%s  height=%d  log2_work=%.8g  date=%s\n", __func__,
      pindexNew->GetBlockHash().ToString(), pindexNew->nHeight,
      log(pindexNew->nChainWork.getdouble())/log(2.0), DateTimeStrFormat("%Y-%m-%d %H:%M:%S",
      pindexNew->GetBlockTime()));
    CBlockIndex *tip = chainActive.Tip();
    assert (tip);
    LogPrintf("%s:  current best=%s  height=%d  log2_work=%.8g  date=%s\n", __func__,
      tip->GetBlockHash().ToString(), chainActive.Height(), log(tip->nChainWork.getdouble())/log(2.0),
      DateTimeStrFormat("%Y-%m-%d %H:%M:%S", tip->GetBlockTime()));
    CheckForkWarningConditions();
}

void static InvalidBlockFound(CBlockIndex *pindex, const CValidationState &state) {
    if (!state.CorruptionPossible()) {
        pindex->nStatus |= BLOCK_FAILED_VALID;
        setDirtyBlockIndex.insert(pindex);
        setBlockIndexCandidates.erase(pindex);
        InvalidChainFound(pindex);
    }
}

void UpdateCoins(const CTransaction& tx, CCoinsViewCache& inputs, CTxUndo &txundo, int nHeight)
{
    // mark inputs spent
    if (!tx.IsCoinBase() && !tx.IsZerocoinSpend() && !tx.IsSigmaSpend() && !tx.IsZerocoinRemint() && !tx.IsLelantusJoinSplit()) {
        txundo.vprevout.reserve(tx.vin.size());
        BOOST_FOREACH(const CTxIn &txin, tx.vin) {
            txundo.vprevout.emplace_back();
            inputs.SpendCoin(txin.prevout, &txundo.vprevout.back());
        }
    }
    // add outputs
    AddCoins(inputs, tx, nHeight);
}

void UpdateCoins(const CTransaction& tx, CCoinsViewCache& inputs, int nHeight)
{
    CTxUndo txundo;
    UpdateCoins(tx, inputs, txundo, nHeight);
}

bool CScriptCheck::operator()() {
    const CScript &scriptSig = ptxTo->vin[nIn].scriptSig;
    const CScriptWitness *witness = &ptxTo->vin[nIn].scriptWitness;
    if (!VerifyScript(scriptSig, scriptPubKey, witness, nFlags, CachingTransactionSignatureChecker(ptxTo, nIn, amount, cacheStore, *txdata), &error)) {
        return false;
    }
    return true;
}

int GetSpendHeight(const CCoinsViewCache& inputs)
{
    LOCK(cs_main);
    CBlockIndex* pindexPrev = mapBlockIndex.find(inputs.GetBestBlock())->second;
    return pindexPrev->nHeight + 1;
}

namespace Consensus {
bool CheckTxInputs(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& inputs, int nSpendHeight)
{
        // This doesn't trigger the DoS code on purpose; if it did, it would make it easier
        // for an attacker to attempt to split the network.
        if (!inputs.HaveInputs(tx))
            return state.Invalid(false, 0, "", "Inputs unavailable");

        CAmount nValueIn = 0;
        CAmount nFees = 0;
        for (unsigned int i = 0; i < tx.vin.size(); i++)
        {
            const COutPoint &prevout = tx.vin[i].prevout;
            const Coin &coin = inputs.AccessCoin(prevout);
            assert(!coin.IsSpent());

            // If prev is coinbase, check that it's matured
            if (coin.IsCoinBase()) {
                if (nSpendHeight - coin.nHeight < COINBASE_MATURITY)
                    return state.Invalid(false,
                        REJECT_INVALID, "bad-txns-premature-spend-of-coinbase",
                        strprintf("tried to spend coinbase at depth %d", nSpendHeight - coin.nHeight));
            }

            // Check for negative or overflow input values
            nValueIn += coin.out.nValue;
            if (!MoneyRange(coin.out.nValue) || !MoneyRange(nValueIn))
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputvalues-outofrange");

        }

        CAmount nTxFee;
        if(!tx.IsLelantusJoinSplit()) {
            // at Lelantus JoinSplit we check balance inside cryptographic proof verification
            if (nValueIn < tx.GetValueOut())
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-in-belowout", false,
                        strprintf("value in (%s) < value out (%s)", FormatMoney(nValueIn), FormatMoney(tx.GetValueOut())));
            // Tally transaction fees
            nTxFee = nValueIn - tx.GetValueOut();
        } else {
            try {
                nTxFee = lelantus::ParseLelantusJoinSplit(tx.vin[0])->getFee();
            }
            catch (CBadTxIn&) {
                return state.DoS(0, false, REJECT_INVALID, "unable to parse joinsplit");
            }
        }
        if (nTxFee < 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-fee-negative");
        nFees += nTxFee;
        if (!MoneyRange(nFees))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-fee-outofrange");
    return true;
}
}// namespace Consensus

bool CheckZerocoinFoundersInputs(const CTransaction &tx, CValidationState &state, const Consensus::Params &params, int nHeight, bool fMTP) {
    // Check for founders inputs
    if ((nHeight > params.nCheckBugFixedAtBlock) && (nHeight < params.nSubsidyHalvingFirst)) {
        // Reduce everything by a factor of two when MTP is in place
        int reductionFactor = fMTP ? params.nMTPRewardReduction : 1;

        bool found_1 = false;
        bool found_2 = false;
        bool found_3 = false;
        bool found_4 = false;
        bool found_5 = false;
        int total_payment_tx = 0; // no more than 1 output for payment
        CScript FOUNDER_1_SCRIPT;
        CScript FOUNDER_2_SCRIPT;
        CScript FOUNDER_3_SCRIPT;
        CScript FOUNDER_4_SCRIPT;
        CScript FOUNDER_5_SCRIPT;
        if (nHeight < params.nZnodePaymentsStartBlock) {
            if (params.IsMain() && GetAdjustedTime() > nStartRewardTime) {
                FOUNDER_1_SCRIPT = GetScriptForDestination(CBitcoinAddress("aCAgTPgtYcA4EysU4UKC86EQd5cTtHtCcr").Get());
                if (nHeight < 14000) {
                    FOUNDER_2_SCRIPT = GetScriptForDestination(
                            CBitcoinAddress("aLrg41sXbXZc5MyEj7dts8upZKSAtJmRDR").Get());
                } else {
                    FOUNDER_2_SCRIPT = GetScriptForDestination(
                            CBitcoinAddress("aHu897ivzmeFuLNB6956X6gyGeVNHUBRgD").Get());
                }
                FOUNDER_3_SCRIPT = GetScriptForDestination(CBitcoinAddress("aQ18FBVFtnueucZKeVg4srhmzbpAeb1KoN").Get());
                FOUNDER_4_SCRIPT = GetScriptForDestination(CBitcoinAddress("a1HwTdCmQV3NspP2QqCGpehoFpi8NY4Zg3").Get());
                FOUNDER_5_SCRIPT = GetScriptForDestination(CBitcoinAddress("a1kCCGddf5pMXSipLVD9hBG2MGGVNaJ15U").Get());
            } else if (params.IsMain() && GetAdjustedTime() <= nStartRewardTime) {
                return state.DoS(100, false, REJECT_TRANSACTION_TOO_EARLY,
                                 "CTransaction::CheckTransaction() : transaction is too early");
            } else {
                FOUNDER_1_SCRIPT = GetScriptForDestination(CBitcoinAddress("TDk19wPKYq91i18qmY6U9FeTdTxwPeSveo").Get());
                FOUNDER_2_SCRIPT = GetScriptForDestination(CBitcoinAddress("TWZZcDGkNixTAMtRBqzZkkMHbq1G6vUTk5").Get());
                FOUNDER_3_SCRIPT = GetScriptForDestination(CBitcoinAddress("TRZTFdNCKCKbLMQV8cZDkQN9Vwuuq4gDzT").Get());
                FOUNDER_4_SCRIPT = GetScriptForDestination(CBitcoinAddress("TG2ruj59E5b1u9G3F7HQVs6pCcVDBxrQve").Get());
                FOUNDER_5_SCRIPT = GetScriptForDestination(CBitcoinAddress("TCsTzQZKVn4fao8jDmB9zQBk9YQNEZ3XfS").Get());
            }

            BOOST_FOREACH(const CTxOut &output, tx.vout) {
                if (output.scriptPubKey == FOUNDER_1_SCRIPT && output.nValue == (int64_t)(2 * COIN)/reductionFactor) {
                    found_1 = true;
                }
                if (output.scriptPubKey == FOUNDER_2_SCRIPT && output.nValue == (int64_t)(2 * COIN)/reductionFactor) {
                    found_2 = true;
                }
                if (output.scriptPubKey == FOUNDER_3_SCRIPT && output.nValue == (int64_t)(2 * COIN)/reductionFactor) {
                    found_3 = true;
                }
                if (output.scriptPubKey == FOUNDER_4_SCRIPT && output.nValue == (int64_t)(2 * COIN)/reductionFactor) {
                    found_4 = true;
                }
                if (output.scriptPubKey == FOUNDER_5_SCRIPT && output.nValue == (int64_t)(2 * COIN)/reductionFactor) {
                    found_5 = true;
                }
            }
        } else {

            if (params.IsMain() && GetAdjustedTime() > nStartRewardTime) {
                FOUNDER_1_SCRIPT = GetScriptForDestination(CBitcoinAddress("aCAgTPgtYcA4EysU4UKC86EQd5cTtHtCcr").Get());
                if (nHeight < 14000) {
                    FOUNDER_2_SCRIPT = GetScriptForDestination(
                            CBitcoinAddress("aLrg41sXbXZc5MyEj7dts8upZKSAtJmRDR").Get());
                } else {
                    FOUNDER_2_SCRIPT = GetScriptForDestination(
                            CBitcoinAddress("aHu897ivzmeFuLNB6956X6gyGeVNHUBRgD").Get());
                }
                FOUNDER_3_SCRIPT = GetScriptForDestination(CBitcoinAddress("aQ18FBVFtnueucZKeVg4srhmzbpAeb1KoN").Get());
                FOUNDER_4_SCRIPT = GetScriptForDestination(CBitcoinAddress("a1HwTdCmQV3NspP2QqCGpehoFpi8NY4Zg3").Get());
                FOUNDER_5_SCRIPT = GetScriptForDestination(CBitcoinAddress("a1kCCGddf5pMXSipLVD9hBG2MGGVNaJ15U").Get());
            } else if (params.IsMain() && GetAdjustedTime() <= nStartRewardTime) {
                return state.DoS(100, false, REJECT_TRANSACTION_TOO_EARLY,
                                 "CTransaction::CheckTransaction() : transaction is too early");
            } else {
                FOUNDER_1_SCRIPT = GetScriptForDestination(CBitcoinAddress("TDk19wPKYq91i18qmY6U9FeTdTxwPeSveo").Get());
                FOUNDER_2_SCRIPT = GetScriptForDestination(CBitcoinAddress("TWZZcDGkNixTAMtRBqzZkkMHbq1G6vUTk5").Get());
                FOUNDER_3_SCRIPT = GetScriptForDestination(CBitcoinAddress("TRZTFdNCKCKbLMQV8cZDkQN9Vwuuq4gDzT").Get());
                FOUNDER_4_SCRIPT = GetScriptForDestination(CBitcoinAddress("TG2ruj59E5b1u9G3F7HQVs6pCcVDBxrQve").Get());
                FOUNDER_5_SCRIPT = GetScriptForDestination(CBitcoinAddress("TCsTzQZKVn4fao8jDmB9zQBk9YQNEZ3XfS").Get());
            }

            CAmount znodePayment = GetZnodePayment(params, fMTP);
            BOOST_FOREACH(const CTxOut &output, tx.vout) {
                if (output.scriptPubKey == FOUNDER_1_SCRIPT && output.nValue == (int64_t)(1 * COIN)/reductionFactor) {
                    found_1 = true;
                    continue;
                }
                if (output.scriptPubKey == FOUNDER_2_SCRIPT && output.nValue == (int64_t)(1 * COIN)/reductionFactor) {
                    found_2 = true;
                    continue;
                }
                if (output.scriptPubKey == FOUNDER_3_SCRIPT && output.nValue == (int64_t)(1 * COIN)/reductionFactor) {
                    found_3 = true;
                    continue;
                }
                if (output.scriptPubKey == FOUNDER_4_SCRIPT && output.nValue == (int64_t)(3 * COIN)/reductionFactor) {
                    found_4 = true;
                    continue;
                }
                if (output.scriptPubKey == FOUNDER_5_SCRIPT && output.nValue == (int64_t)(1 * COIN)/reductionFactor) {
                    found_5 = true;
                    continue;
                }
                if (znodePayment == output.nValue) {
                    total_payment_tx = total_payment_tx + 1;
                }
            }
        }

        if (!(found_1 && found_2 && found_3 && found_4 && found_5)) {
            return state.DoS(100, false, REJECT_FOUNDER_REWARD_MISSING,
                             "CTransaction::CheckTransaction() : founders reward missing");
        }
    }

    return true;
}

bool CheckInputs(const CTransaction& tx, CValidationState &state, const CCoinsViewCache &inputs, bool fScriptChecks, unsigned int flags, bool cacheStore, PrecomputedTransactionData& txdata, std::vector<CScriptCheck> *pvChecks)
{
    if (!tx.IsCoinBase() && !tx.IsZerocoinSpend() && !tx.IsSigmaSpend() && !tx.IsZerocoinRemint() && !tx.IsLelantusJoinSplit())
    {
        if (!Consensus::CheckTxInputs(tx, state, inputs, GetSpendHeight(inputs)))
            return false;

        if (pvChecks)
            pvChecks->reserve(tx.vin.size());

        // The first loop above does all the inexpensive checks.
        // Only if ALL inputs pass do we perform expensive ECDSA signature checks.
        // Helps prevent CPU exhaustion attacks.

        // Skip script verification when connecting blocks under the
        // assumedvalid block. Assuming the assumedvalid block is valid this
        // is safe because block merkle hashes are still computed and checked,
        // Of course, if an assumed valid block is invalid due to false scriptSigs
        // this optimization would allow an invalid chain to be accepted.
        if (fScriptChecks) {
            for (unsigned int i = 0; i < tx.vin.size(); i++) {
                const COutPoint &prevout = tx.vin[i].prevout;
                const Coin& coin = inputs.AccessCoin(prevout);
                assert(!coin.IsSpent());

                // We very carefully only pass in things to CScriptCheck which
                // are clearly committed to by tx' witness hash. This provides
                // a sanity check that our caching is not introducing consensus
                // failures through additional data in, eg, the coins being
                // spent being checked as a part of CScriptCheck.
                const CScript& scriptPubKey = coin.out.scriptPubKey;
                const CAmount amount = coin.out.nValue;

                // Verify signature
                CScriptCheck check(scriptPubKey, amount, tx, i, flags, cacheStore, &txdata);
                if (pvChecks) {
                    pvChecks->push_back(CScriptCheck());
                    check.swap(pvChecks->back());
                } else if (!check()) {
                    if (flags & SCRIPT_VERIFY_STRICTENC) {
                        // Check whether the failure was caused by a
                        // non-mandatory script verification check, such as
                        // non-standard DER encodings or non-null dummy
                        // arguments; if so, don't trigger DoS protection to
                        // avoid splitting the network between upgraded and
                        // non-upgraded nodes.
                        CScriptCheck check2(scriptPubKey, amount, tx, i,
                                flags & ~STANDARD_NOT_MANDATORY_VERIFY_FLAGS, cacheStore, &txdata);
                        if (check2())
                            return state.Invalid(false, REJECT_NONSTANDARD, strprintf("non-mandatory-script-verify-flag (%s)", ScriptErrorString(check.GetScriptError())));
                    }
                    // Failures of other flags indicate a transaction that is
                    // invalid in new blocks, e.g. a invalid P2SH. We DoS ban
                    // such nodes as they are not following the protocol. That
                    // said during an upgrade careful thought should be taken
                    // as to the correct behavior - we may want to continue
                    // peering with non-upgraded nodes even after soft-fork
                    // super-majority signaling has occurred.
                    return state.DoS(100,false, REJECT_INVALID, strprintf("mandatory-script-verify-flag-failed (%s)", ScriptErrorString(check.GetScriptError())));
                }
            }
        }
    } else if (tx.IsSigmaSpend()) {
        // Total sum of inputs of transaction.
        CAmount totalInputValue = 0;

        BOOST_FOREACH(const CTxIn &txin, tx.vin) {
            if(!txin.scriptSig.IsSigmaSpend()) {
                return state.DoS(
                    100, false,
                    REJECT_MALFORMED,
                    "CheckSpendFiroTransaction: can't mix zerocoin spend input with regular ones");
            }
            CDataStream serializedCoinSpend((const char *)&*(txin.scriptSig.begin() + 1),
                                            (const char *)&*txin.scriptSig.end(),
                                            SER_NETWORK, PROTOCOL_VERSION);
            sigma::CoinSpend newSpend(sigma::Params::get_default(), serializedCoinSpend);
            uint64_t denom = newSpend.getIntDenomination();
            totalInputValue += denom;
        }
        if (totalInputValue < tx.GetValueOut()) {
            return state.DoS(
                100,
                error("Spend transaction outputs larger than the inputs."));
        }
    } else if (tx.IsLelantusJoinSplit()) {
        if(tx.vin.size() > 1 || !tx.vin[0].scriptSig.IsLelantusJoinSplit()) {
            return state.DoS(
                    100, false,
                    REJECT_MALFORMED,
                    " Can't mix Lelantus joinsplit input with regular ones or have more than one input");
        }
    }

    return true;
}

namespace {

bool UndoWriteToDisk(const CBlockUndo& blockundo, CDiskBlockPos& pos, const uint256& hashBlock, const CMessageHeader::MessageStartChars& messageStart)
{
    // Open history file to append
    CAutoFile fileout(OpenUndoFile(pos), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("%s: OpenUndoFile failed", __func__);

    // Write index header
    unsigned int nSize = GetSerializeSize(fileout, blockundo);
    fileout << FLATDATA(messageStart) << nSize;

    // Write undo data
    long fileOutPos = ftell(fileout.Get());
    if (fileOutPos < 0)
        return error("%s: ftell failed", __func__);
    pos.nPos = (unsigned int)fileOutPos;
    fileout << blockundo;

    // calculate & write checksum
    CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);
    hasher << hashBlock;
    hasher << blockundo;
    fileout << hasher.GetHash();

    return true;
}

bool UndoReadFromDisk(CBlockUndo& blockundo, const CDiskBlockPos& pos, const uint256& hashBlock)
{
    // Open history file to read
    CAutoFile filein(OpenUndoFile(pos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return error("%s: OpenUndoFile failed", __func__);

    // Read block
    uint256 hashChecksum;
    CHashVerifier<CAutoFile> verifier(&filein); // We need a CHashVerifier as reserializing may lose data
    try {
        verifier << hashBlock;
        verifier >> blockundo;
        filein >> hashChecksum;
    }
    catch (const std::exception& e) {
        return error("%s: Deserialize or I/O error - %s", __func__, e.what());
    }

    // Verify checksum
    if (hashChecksum != verifier.GetHash())
        return error("%s: Checksum mismatch", __func__);

    return true;
}

} // anon namespace

/** Abort with a message */
bool AbortNode(const std::string& strMessage, const std::string& userMessage)
{
    SetMiscWarning(strMessage);
    LogPrintf("*** %s\n", strMessage);
    uiInterface.ThreadSafeMessageBox(
        userMessage.empty() ? _("Error: A fatal internal error occurred, see debug.log for details") : userMessage,
        "", CClientUIInterface::MSG_ERROR);
    StartShutdown();
    return false;
}

bool AbortNode(CValidationState& state, const std::string& strMessage, const std::string& userMessage /*=""*/)
{
    AbortNode(strMessage, userMessage);
    return state.Error(strMessage);
}

enum DisconnectResult
{
    DISCONNECT_OK,      // All good.
    DISCONNECT_UNCLEAN, // Rolled back, but UTXO set was inconsistent with block.
    DISCONNECT_FAILED   // Something else went wrong.
};

/**
 * Restore the UTXO in a Coin at a given COutPoint
 * @param undo The Coin to be restored.
 * @param view The coins view to which to apply the changes.
 * @param out The out point that corresponds to the tx input.
 * @return A DisconnectResult as an int
 */
int ApplyTxInUndo(Coin&& undo, CCoinsViewCache& view, const COutPoint& out)
{
    bool fClean = true;

    if (view.HaveCoin(out)) fClean = false; // overwriting transaction output

    if (undo.nHeight == 0) {
        // Missing undo metadata (height and coinbase). Older versions included this
        // information only in undo records for the last spend of a transactions'
        // outputs. This implies that it must be present for some other output of the same tx.
        const Coin& alternate = AccessByTxid(view, out.hash);
        if (!alternate.IsSpent()) {
            undo.nHeight = alternate.nHeight;
            undo.fCoinBase = alternate.fCoinBase;
        } else {
            return DISCONNECT_FAILED; // adding output for transaction without known metadata
        }
    }
    view.AddCoin(out, std::move(undo), undo.fCoinBase);

    return fClean ? DISCONNECT_OK : DISCONNECT_UNCLEAN;
}

/** Undo the effects of this block (with given index) on the UTXO set represented by coins.
 *  When UNCLEAN or FAILED is returned, view is left in an indeterminate state. */
static DisconnectResult DisconnectBlock(const CBlock& block, CValidationState& state, const CBlockIndex* pindex, CCoinsViewCache& view, bool *pfClean = nullptr)
{
    assert(pindex->GetBlockHash() == view.GetBestBlock());

    bool fDIP0003Active = pindex->nHeight >= Params().GetConsensus().DIP0003Height;
    bool fHasBestBlock = evoDb->VerifyBestBlock(pindex->GetBlockHash());

    if (fDIP0003Active && !fHasBestBlock) {
        // Nodes that upgraded after DIP3 activation will have to reindex to ensure evodb consistency
        AbortNode("Found EvoDB inconsistency, you must reindex to continue");
        return DISCONNECT_FAILED;
    }

    if (pfClean)
        *pfClean = false;
    bool fClean = true;

    CBlockUndo blockUndo;
    CDiskBlockPos pos = pindex->GetUndoPos();

    if (pos.IsNull()) {
        error("DisconnectBlock(): no undo data available");
        return DISCONNECT_FAILED;
    }
    if (!UndoReadFromDisk(blockUndo, pos, pindex->pprev->GetBlockHash())) {
        error("DisconnectBlock(): failure reading undo data");
        return DISCONNECT_FAILED;
    }

    if (blockUndo.vtxundo.size() + 1 != block.vtx.size()) {
        error("DisconnectBlock(): block and undo data inconsistent");
        return DISCONNECT_FAILED;
    }

    CDbIndexHelper dbIndexHelper(fAddressIndex, fSpentIndex);

    CAmount nFees = 0;

    if (!UndoSpecialTxsInBlock(block, pindex)) {
        return DISCONNECT_FAILED;
    }

    // undo transactions in reverse order
    for (int i = block.vtx.size() - 1; i >= 0; i--) {
        const CTransaction &tx = *(block.vtx[i]);
        uint256 hash = tx.GetHash();

        dbIndexHelper.DisconnectTransactionOutputs(tx, pindex->nHeight, i, view);

        // Check that all outputs are available and match the outputs in the block itself
        // exactly.
        for (size_t o = 0; o < tx.vout.size(); o++) {
            if (!tx.vout[o].scriptPubKey.IsUnspendable()) {
                COutPoint out(hash, o);
                Coin coin;
                view.SpendCoin(out, &coin);
                if (tx.vout[o] != coin.out) {
                    fClean = false; // transaction output mismatch
                }
            }
        }

        // restore inputs
        if (!tx.IsCoinBase() && !tx.HasNoRegularInputs()) { // not coinbases
            CTxUndo &txundo = blockUndo.vtxundo[i-1];
            if (txundo.vprevout.size() != tx.vin.size()) {
                error("DisconnectBlock(): transaction and undo data inconsistent");
                return DISCONNECT_FAILED;
            }
            for (unsigned int j = tx.vin.size(); j-- > 0;) {
                const COutPoint &out = tx.vin[j].prevout;
                if (Params().ApplyUndoForTxout(pindex->nHeight, tx.GetHash(), j)) {
                    int res = ApplyTxInUndo(std::move(txundo.vprevout[j]), view, out);
                    if (res == DISCONNECT_FAILED) return DISCONNECT_FAILED;
                    fClean = fClean && res != DISCONNECT_UNCLEAN;
                }
            }
            // At this point, all of txundo.vprevout should have been moved out.
        }

        if(tx.IsSigmaSpend())
            nFees += sigma::GetSigmaSpendInput(tx) - tx.GetValueOut();
        else if (tx.IsLelantusJoinSplit()) {
            nFees += lelantus::ParseLelantusJoinSplit(tx.vin[0])->getFee();
        }

        dbIndexHelper.DisconnectTransactionInputs(tx, pindex->nHeight, i, view);
    }

    // move best block pointer to prevout block
    view.SetBestBlock(pindex->pprev->GetBlockHash());

    //The pfClean flag is specified only when called from CVerifyDB::VerifyDB.
    //When called from there, no real disconnect happens.
    if(!pfClean) {
        if (fAddressIndex) {
            if (!pblocktree->EraseAddressIndex(dbIndexHelper.getAddressIndex())) {
                AbortNode(state, "Failed to delete address index");
                error("Failed to delete address index");
                return DISCONNECT_FAILED;
            }
            if (!pblocktree->UpdateAddressUnspentIndex(dbIndexHelper.getAddressUnspentIndex())) {
                AbortNode(state, "Failed to write address unspent index");
                error("Failed to write address unspent index");
                return DISCONNECT_FAILED;
            }
            if (!pblocktree->AddTotalSupply(-(block.vtx[0]->GetValueOut() - nFees))) {
                AbortNode(state, "Failed to write total supply");
                error("Failed to write total supply");
                return DISCONNECT_FAILED;
            }
        }
    }

    /*
    // make sure the flag is reset in case of a chain reorg
    // (we reused the DIP3 deployment)
    instantsend.isAutoLockBip9Active = pindex->nHeight >= Params().GetConsensus().DIP0003Height;
    */

    evoDb->WriteBestBlock(pindex->pprev->GetBlockHash());

    if(Params().SkipUndoForBlock(pindex->nHeight)) {
        fClean = true;
    }

    if (pfClean)
        *pfClean = fClean;

    return fClean ? DISCONNECT_OK : DISCONNECT_UNCLEAN;
}

void static FlushBlockFile(bool fFinalize = false)
{
    LOCK(cs_LastBlockFile);

    CDiskBlockPos posOld(nLastBlockFile, 0);

    FILE *fileOld = OpenBlockFile(posOld);
    if (fileOld) {
        if (fFinalize)
            TruncateFile(fileOld, vinfoBlockFile[nLastBlockFile].nSize);
        FileCommit(fileOld);
        fclose(fileOld);
    }

    fileOld = OpenUndoFile(posOld);
    if (fileOld) {
        if (fFinalize)
            TruncateFile(fileOld, vinfoBlockFile[nLastBlockFile].nUndoSize);
        FileCommit(fileOld);
        fclose(fileOld);
    }
}

bool FindUndoPos(CValidationState &state, int nFile, CDiskBlockPos &pos, unsigned int nAddSize);

static CCheckQueue<CScriptCheck> scriptcheckqueue(128);

void ThreadScriptCheck() {
    RenameThread("bitcoin-scriptch");
    scriptcheckqueue.Thread();
}

// Protected by cs_main
VersionBitsCache versionbitscache;

int32_t ComputeBlockVersion(const CBlockIndex* pindexPrev, const Consensus::Params& params)
{
    LOCK(cs_main);
    int32_t nVersion = VERSIONBITS_TOP_BITS;

    for (int i = 0; i < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; i++) {
        ThresholdState state = VersionBitsState(pindexPrev, params, (Consensus::DeploymentPos)i, versionbitscache);
        if (state == THRESHOLD_LOCKED_IN || state == THRESHOLD_STARTED) {
            nVersion |= VersionBitsMask(params, (Consensus::DeploymentPos)i);
        }
    }

    return nVersion;
}

bool GetBlockHash(uint256 &hashRet, int nBlockHeight) {
    LOCK(cs_main);
    if (chainActive.Tip() == NULL) return false;
    if (nBlockHeight < -1 || nBlockHeight > chainActive.Height()) return false;
    if (nBlockHeight == -1) nBlockHeight = chainActive.Height();
    hashRet = chainActive[nBlockHeight]->GetBlockHash();
    return true;
}

/**
 * Threshold condition checker that triggers when unknown versionbits are seen on the network.
 */
class WarningBitsConditionChecker : public AbstractThresholdConditionChecker
{
private:
    int bit;

public:
    WarningBitsConditionChecker(int bitIn) : bit(bitIn) {}

    int64_t BeginTime(const Consensus::Params& params) const { return 0; }
    int64_t EndTime(const Consensus::Params& params) const { return std::numeric_limits<int64_t>::max(); }
    int Period(const Consensus::Params& params) const { return params.nMinerConfirmationWindow; }
    int Threshold(const Consensus::Params& params) const { return params.nRuleChangeActivationThreshold; }

    bool Condition(const CBlockIndex* pindex, const Consensus::Params& params) const
    {
        return ((pindex->nVersion & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS) &&
               ((pindex->nVersion >> bit) & 1) != 0 &&
               ((ComputeBlockVersion(pindex->pprev, params) >> bit) & 1) == 0;
    }
};

// Protected by cs_main
static ThresholdConditionCache warningcache[VERSIONBITS_NUM_BITS];

static int64_t nTimeCheck = 0;
static int64_t nTimeForks = 0;
static int64_t nTimeVerify = 0;
static int64_t nTimeConnect = 0;
static int64_t nTimeIndex = 0;
static int64_t nTimeCallbacks = 0;
static int64_t nTimeTotal = 0;

bool ConnectBlock(const CBlock& block, CValidationState& state, CBlockIndex* pindex,
                  CCoinsViewCache& view, const CChainParams& chainparams, bool fJustCheck)
{
    AssertLockHeld(cs_main);

    int64_t nTimeStart = GetTimeMicros();
    //btzc: update nHeight, isVerifyDB
    // Check it again in case a previous version let a bad block in
    LogPrintf("ConnectBlock nHeight=%s, hash=%s\n", pindex->nHeight, block.GetHash().ToString());
    if (!CheckBlock(block, state, chainparams.GetConsensus(), !fJustCheck, !fJustCheck, pindex->nHeight, false)) {
        LogPrintf("--> failed\n");
        return error("%s: Consensus::CheckBlock: %s", __func__, FormatStateMessage(state));
    }

    // verify that the view's current state corresponds to the previous block
    uint256 hashPrevBlock = pindex->pprev == NULL ? uint256() : pindex->pprev->GetBlockHash();
    assert(hashPrevBlock == view.GetBestBlock());

    if (pindex->pprev) {
        bool fDIP0003Active = pindex->nHeight >= chainparams.GetConsensus().DIP0003Height;
        bool fHasBestBlock = evoDb->VerifyBestBlock(pindex->pprev->GetBlockHash());

        if (fDIP0003Active && !fHasBestBlock) {
            // Nodes that upgraded after DIP3 activation will have to reindex to ensure evodb consistency
            return AbortNode(state, "Found EvoDB inconsistency, you must reindex to continue");
        }
    }

    // Special case for the genesis block, skipping connection of its transactions
    // (its coinbase is unspendable)
    if (block.GetHash() == chainparams.GetConsensus().hashGenesisBlock) {
        if (!fJustCheck)
            view.SetBestBlock(pindex->GetBlockHash());
        return true;
    }

    bool fScriptChecks = true;
    if (!hashAssumeValid.IsNull()) {
        // We've been configured with the hash of a block which has been externally verified to have a valid history.
        // A suitable default value is included with the software and updated from time to time.  Because validity
        //  relative to a piece of software is an objective fact these defaults can be easily reviewed.
        // This setting doesn't force the selection of any particular chain but makes validating some faster by
        //  effectively caching the result of part of the verification.
        BlockMap::const_iterator  it = mapBlockIndex.find(hashAssumeValid);
        if (it != mapBlockIndex.end()) {
            if (it->second->GetAncestor(pindex->nHeight) == pindex &&
                pindexBestHeader->GetAncestor(pindex->nHeight) == pindex &&
                pindexBestHeader->nChainWork >= UintToArith256(chainparams.GetConsensus().nMinimumChainWork)) {
                // This block is a member of the assumed verified chain and an ancestor of the best header.
                // The equivalent time check discourages hashpower from extorting the network via DOS attack
                //  into accepting an invalid block through telling users they must manually set assumevalid.
                //  Requiring a software change or burying the invalid block, regardless of the setting, makes
                //  it hard to hide the implication of the demand.  This also avoids having release candidates
                //  that are hardly doing any signature verification at all in testing without having to
                //  artificially set the default assumed verified block further back.
                // The test against nMinimumChainWork prevents the skipping when denied access to any chain at
                //  least as good as the expected chain.
                fScriptChecks = (GetBlockProofEquivalentTime(*pindexBestHeader, *pindex, *pindexBestHeader, chainparams.GetConsensus()) <= 60 * 60 * 24 * 7 * 2);
            }
        }
    }

    int64_t nTime1 = GetTimeMicros(); nTimeCheck += nTime1 - nTimeStart;
    LogPrint("bench", "    - Sanity checks: %.2fms [%.2fs]\n", 0.001 * (nTime1 - nTimeStart), nTimeCheck * 0.000001);

    // Do not allow blocks that contain transactions which 'overwrite' older transactions,
    // unless those are already completely spent.
    // If such overwrites are allowed, coinbases and transactions depending upon those
    // can be duplicated to remove the ability to spend the first instance -- even after
    // being sent to another address.
    // See BIP30 and http://r6.ca/blog/20120206T005236Z.html for more information.
    // This logic is not necessary for memory pool transactions, as AcceptToMemoryPool
    // already refuses previously-known transaction ids entirely.
    // This rule was originally applied to all blocks with a timestamp after March 15, 2012, 0:00 UTC.
    // Now that the whole chain is irreversibly beyond that time it is applied to all blocks except the
    // two in the chain that violate it. This prevents exploiting the issue against nodes during their
    // initial block download.
    /*
    bool fEnforceBIP30 = (!pindex->phashBlock) || // Enforce on CreateNewBlock invocations which don't have a hash.
                          !((pindex->nHeight==91842 && pindex->GetBlockHash() == uint256S("0x00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec")) ||
                           (pindex->nHeight==91880 && pindex->GetBlockHash() == uint256S("0x00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721")));
    */

    // Once BIP34 activated it was not possible to create new duplicate coinbases and thus other than starting
    // with the 2 existing duplicate coinbase pairs, not possible to create overwriting txs.  But by the
    // time BIP34 activated, in each of the existing pairs the duplicate coinbase had overwritten the first
    // before the first had been spent.  Since those coinbases are sufficiently buried its no longer possible to create further
    // duplicate transactions descending from the known pairs either.
    // If we're on the known chain at height greater than where BIP34 activated, we can save the db accesses needed for the BIP30 check.
    /*
    CBlockIndex *pindexBIP34height = pindex->pprev->GetAncestor(chainparams.GetConsensus().BIP34Height);
    //Only continue to enforce if we're below BIP34 activation height or the block hash at that height doesn't correspond.
    fEnforceBIP30 = fEnforceBIP30 && (!pindexBIP34height || !(pindexBIP34height->GetBlockHash() == chainparams.GetConsensus().BIP34Hash));
    */

    bool fEnforceBIP30 = true;
    if (fEnforceBIP30) {
        for (const auto& tx : block.vtx) {
            for (size_t o = 0; o < tx->vout.size(); o++) {
                if (view.HaveCoin(COutPoint(tx->GetHash(), o))) {
                    return state.DoS(100, error("ConnectBlock(): tried to overwrite transaction"),
                                     REJECT_INVALID, "bad-txns-BIP30");
                }
            }
        }
    }

    // BIP16 didn't become active until Apr 1 2012
    int64_t nBIP16SwitchTime = 1349049600;
    bool fStrictPayToScriptHash = (pindex->GetBlockTime() >= nBIP16SwitchTime);

    unsigned int flags = fStrictPayToScriptHash ? SCRIPT_VERIFY_P2SH : SCRIPT_VERIFY_NONE;

    // Start enforcing the DERSIG (BIP66) rule
    if (pindex->nHeight >= chainparams.GetConsensus().BIP66Height) {
        flags |= SCRIPT_VERIFY_DERSIG;
    }

    // Start enforcing CHECKLOCKTIMEVERIFY (BIP65) rule
    if (pindex->nHeight >= chainparams.GetConsensus().BIP65Height) {
        flags |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
    }

    // Start enforcing BIP68 (sequence locks) and BIP112 (CHECKSEQUENCEVERIFY) using versionbits logic.
    int nLockTimeFlags = 0;
    if (VersionBitsState(pindex->pprev, chainparams.GetConsensus(), Consensus::DEPLOYMENT_CSV, versionbitscache) == THRESHOLD_ACTIVE) {
        flags |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
        nLockTimeFlags |= LOCKTIME_VERIFY_SEQUENCE;
    }

    // Start enforcing WITNESS rules using versionbits logic.
    if (IsWitnessEnabled(pindex->pprev, chainparams.GetConsensus())) {
        flags |= SCRIPT_VERIFY_WITNESS;
        flags |= SCRIPT_VERIFY_NULLDUMMY;
    }

    int64_t nTime2 = GetTimeMicros(); nTimeForks += nTime2 - nTime1;
    LogPrint("bench", "    - Fork checks: %.2fms [%.2fs]\n", 0.001 * (nTime2 - nTime1), nTimeForks * 0.000001);

    CBlockUndo blockundo;

    CCheckQueueControl<CScriptCheck> control(fScriptChecks && nScriptCheckThreads ? &scriptcheckqueue : NULL);

    std::vector<int> prevheights;
    CAmount nFees = 0;
    int nInputs = 0;
    int64_t nSigOpsCost = 0;
    CDiskTxPos pos(pindex->GetBlockPos(), GetSizeOfCompactSize(block.vtx.size()));
    std::vector<std::pair<uint256, CDiskTxPos> > vPos;
    vPos.reserve(block.vtx.size());
    blockundo.vtxundo.reserve(block.vtx.size() - 1);
    CDbIndexHelper dbIndexHelper(fAddressIndex, fSpentIndex);

    std::vector<PrecomputedTransactionData> txdata;
    txdata.reserve(block.vtx.size()); // Required so that pointers to individual PrecomputedTransactionData don't get invalidated

    std::set<uint256> txIds;
    bool isMainNet = chainparams.GetConsensus().IsMain();
    // batch verify Lelantus/Sigma if block is older than a day, that means we are syncing or reindexing
    BatchProofContainer* batchProofContainer = BatchProofContainer::get_instance();
    batchProofContainer->fCollectProofs = ((GetSystemTimeInSeconds() - pindex->GetBlockTime()) > 86400) && GetBoolArg("-batching", true);
    batchProofContainer->init();

    block.sigmaTxInfo = std::make_shared<sigma::CSigmaTxInfo>();
    block.lelantusTxInfo = std::make_shared<lelantus::CLelantusTxInfo>();

    for (unsigned int i = 0; i < block.vtx.size(); i++)
    {
        const CTransaction &tx = *(block.vtx[i]);

        uint256 txHash = tx.GetHash();
        bool hasDuplicateInTheSameBlock = txIds.count(txHash) > 0;
        if (hasDuplicateInTheSameBlock && (!isMainNet || pindex->nHeight >= HF_ZNODE_HEIGHT))
            return state.DoS(100, error("ConnectBlock(): duplicate transactions in the same block"),
                             REJECT_INVALID, "bad-txns-duplicatetxid");
        txIds.insert(txHash);

        nInputs += tx.vin.size();

        if(tx.IsLelantusJoinSplit() && tx.vin.size() > 1)
            return state.DoS(100, error("ConnectBlock(): invalid joinsplit tx"),
                             REJECT_INVALID, "bad-txns-input-invalid");


        if (!tx.IsCoinBase() && !tx.IsZerocoinSpend() && !tx.IsSigmaSpend() && !tx.IsZerocoinRemint() && !tx.IsLelantusJoinSplit())
        {
            if (!view.HaveInputs(tx))
                return state.DoS(100, error("ConnectBlock(): inputs missing/spent"),
                                 REJECT_INVALID, "bad-txns-inputs-missingorspent");

            // Check that transaction is BIP68 final
            // BIP68 lock checks (as opposed to nLockTime checks) must
            // be in ConnectBlock because they require the UTXO set
            prevheights.resize(tx.vin.size());
            for (size_t j = 0; j < tx.vin.size(); j++) {
                prevheights[j] = view.AccessCoin(tx.vin[j].prevout).nHeight;
            }

            if (!SequenceLocks(tx, nLockTimeFlags, &prevheights, *pindex)) {
                return state.DoS(100, error("%s: contains a non-BIP68-final transaction", __func__),
                                 REJECT_INVALID, "bad-txns-nonfinal");
            }
        }

        if (tx.IsZerocoinSpend()
        || tx.IsZerocoinMint()
        || tx.IsSigmaSpend()
        || tx.IsSigmaMint()
        || tx.IsZerocoinRemint()
        || tx.IsLelantusMint()
        || tx.IsLelantusJoinSplit()) {
            if( tx.IsSigmaSpend())
                nFees += sigma::GetSigmaSpendInput(tx) - tx.GetValueOut();

            if(tx.IsLelantusJoinSplit()) {
                try {
                    nFees += lelantus::ParseLelantusJoinSplit(tx.vin[0])->getFee();
                }
                catch (CBadTxIn&) {
                    return state.DoS(0, false, REJECT_INVALID, "unable to parse joinsplit");
                }
            }

            // Check transaction against signa/lelantus state
            if (!CheckTransaction(tx, state, false, txHash, false, pindex->nHeight, false, true, block.sigmaTxInfo.get(), block.lelantusTxInfo.get()))
                return state.DoS(100, error("stateful zerocoin check failed"),
                                 REJECT_INVALID, "bad-txns-zerocoin");
        }

        if (!fJustCheck)
            dbIndexHelper.ConnectTransaction(tx, pindex->nHeight, i, view);

        // GetTransactionSigOpCost counts 3 types of sigops:
        // * legacy (always)
        // * p2sh (when P2SH enabled in flags and excludes coinbase)
        // * witness (when witness enabled in flags and excludes coinbase)
        nSigOpsCost += GetTransactionSigOpCost(tx, view, flags);
        if (nSigOpsCost > MAX_BLOCK_SIGOPS_COST)
            return state.DoS(100, error("ConnectBlock(): too many sigops"),
                             REJECT_INVALID, "bad-blk-sigops");

        txdata.emplace_back(tx);
        if (!tx.IsCoinBase() && !tx.IsZerocoinSpend() && !tx.IsSigmaSpend() && !tx.IsZerocoinRemint() && !tx.IsLelantusJoinSplit())
        {
            nFees += view.GetValueIn(tx)-tx.GetValueOut();

            std::vector<CScriptCheck> vChecks;
            bool fCacheResults = fJustCheck; /* Don't cache results if we're actually connecting blocks (still consult the cache, though) */
            bool isInWhitelist = chainparams.GetConsensus().txidWhitelist.count(tx.GetHash()) > 0;
            if (!CheckInputs(tx, state, view, fScriptChecks && !isInWhitelist, flags, fCacheResults, txdata[i], nScriptCheckThreads ? &vChecks : NULL))
                return error("ConnectBlock(): CheckInputs on %s failed with %s",
                    tx.GetHash().ToString(), FormatStateMessage(state));
            control.Add(vChecks);
        }

        CTxUndo undoDummy;
        if (i > 0) {
            blockundo.vtxundo.push_back(CTxUndo());
        }
        // Historically there were duplicate transactions in the block, they were allowed until block 66550
        // Don't update coins for such a transaction
        if (!hasDuplicateInTheSameBlock)
            UpdateCoins(tx, view, i == 0 ? undoDummy : blockundo.vtxundo.back(), pindex->nHeight);

        vPos.push_back(std::make_pair(tx.GetHash(), pos));
        pos.nTxOffset += ::GetSerializeSize(tx, SER_DISK, CLIENT_VERSION);

    }

    block.sigmaTxInfo->Complete();
    block.lelantusTxInfo->Complete();

    int64_t nTime3 = GetTimeMicros(); nTimeConnect += nTime3 - nTime2;
    LogPrint("bench", "      - Connect %u transactions: %.2fms (%.3fms/tx, %.3fms/txin) [%.2fs]\n", (unsigned)block.vtx.size(), 0.001 * (nTime3 - nTime2), 0.001 * (nTime3 - nTime2) / block.vtx.size(), nInputs <= 1 ? 0 : 0.001 * (nTime3 - nTime2) / (nInputs-1), nTimeConnect * 0.000001);

    if (!control.Wait())
        return state.DoS(100, false);
    int64_t nTime4 = GetTimeMicros(); nTimeVerify += nTime4 - nTime2;
    LogPrint("bench", "    - Verify %u txins: %.2fms (%.3fms/txin) [%.2fs]\n", nInputs - 1, 0.001 * (nTime4 - nTime2), nInputs <= 1 ? 0 : 0.001 * (nTime4 - nTime2) / (nInputs-1), nTimeVerify * 0.000001);

    //btzc: Add time to check
    CAmount blockSubsidy = GetBlockSubsidy(pindex->nHeight, chainparams.GetConsensus(), pindex->nTime);
    CAmount blockReward = nFees + blockSubsidy;
    if (block.vtx[0]->GetValueOut() > blockReward)
        return state.DoS(100,
                         error("ConnectBlock(): coinbase pays too much (actual=%d vs limit=%d)",
                               block.vtx[0]->GetValueOut(), blockReward),
                               REJECT_INVALID, "bad-cb-amount");

    std::string strError = "";
    if (!IsBlockValueValid(block, pindex->nHeight, blockReward, strError)) {
        return state.DoS(0, error("ConnectBlock(EVOZNODES): %s", strError), REJECT_INVALID, "bad-cb-amount");
    }

    if (!IsBlockPayeeValid(*block.vtx[0], pindex->nHeight, blockSubsidy)) {
        mapRejectedBlocks.insert(std::make_pair(block.GetHash(), GetTime()));
        return state.DoS(0, error("ConnectBlock(EVPZNODES): couldn't find evo znode payments"),
                                REJECT_INVALID, "bad-cb-payee");
    }

    if (!ProcessSpecialTxsInBlock(block, pindex, state, fJustCheck, fScriptChecks)) {
        return error("ConnectBlock(): ProcessSpecialTxsInBlock for block %s at height %i failed with %s",
                    pindex->GetBlockHash().ToString(), pindex->nHeight, FormatStateMessage(state));
    }
    // END ZNODE

    if (!fJustCheck)
        MTPState::GetMTPState()->SetLastBlock(pindex, chainparams.GetConsensus());

    // evo spork handling
    // back up spork state if fJustCheck is true
    auto sporkSetBackup = pindex->activeDisablingSporks;
    CSporkManager *sporkManager = CSporkManager::GetSporkManager();

    if (pindex->nHeight >= chainparams.GetConsensus().nEvoSporkStartBlock &&
                pindex->nHeight < chainparams.GetConsensus().nEvoSporkStopBlock) {
        if (!sporkManager->BlockConnected(block, pindex)) {
            pindex->activeDisablingSporks = sporkSetBackup;
            return false;
        }

        // check if transaction is allowed under spork rules
        for (CTransactionRef tx: block.vtx) {
            if (!sporkManager->IsTransactionAllowed(*tx, pindex->activeDisablingSporks, state))
                return false;
        }
    }

    if (!sigma::ConnectBlockSigma(state, chainparams, pindex, &block, fJustCheck) ||
        !lelantus::ConnectBlockLelantus(state, chainparams, pindex, &block, fJustCheck))
        return false;

    if (!sporkManager->IsBlockAllowed(block, pindex, state))
        return false;

    if (fJustCheck) {
        // roll back spork set if needed
        pindex->activeDisablingSporks = sporkSetBackup;
        return true;
    }

    // Write undo information to disk
    if (pindex->GetUndoPos().IsNull() || !pindex->IsValid(BLOCK_VALID_SCRIPTS))
    {
        if (pindex->GetUndoPos().IsNull()) {
            CDiskBlockPos _pos;
            if (!FindUndoPos(state, pindex->nFile, _pos, ::GetSerializeSize(blockundo, SER_DISK, CLIENT_VERSION) + 40))
                return error("ConnectBlock(): FindUndoPos failed");
            if (!UndoWriteToDisk(blockundo, _pos, pindex->pprev->GetBlockHash(), chainparams.MessageStart()))
                return AbortNode(state, "Failed to write undo data");

            // update nUndoPos in block index
            pindex->nUndoPos = _pos.nPos;
            pindex->nStatus |= BLOCK_HAVE_UNDO;
        }

        pindex->RaiseValidity(BLOCK_VALID_SCRIPTS);
        setDirtyBlockIndex.insert(pindex);
    }

    if (fTxIndex)
        if (!pblocktree->WriteTxIndex(vPos))
            return AbortNode(state, "Failed to write transaction index");
    if (fAddressIndex) {
        if (!pblocktree->WriteAddressIndex(dbIndexHelper.getAddressIndex()))
            return AbortNode(state, "Failed to write address index");

        if (!pblocktree->UpdateAddressUnspentIndex(dbIndexHelper.getAddressUnspentIndex()))
            return AbortNode(state, "Failed to write address unspent index");

        if (!pblocktree->AddTotalSupply(block.vtx[0]->GetValueOut() - nFees))
            return AbortNode(state, "Failed to write total supply");
    }

    if (fSpentIndex)
        if (!pblocktree->UpdateSpentIndex(dbIndexHelper.getSpentIndex()))
            return AbortNode(state, "Failed to write transaction index");


    if (fTimestampIndex)
        if (!pblocktree->WriteTimestampIndex(CTimestampIndexKey(pindex->nTime, pindex->GetBlockHash())))
            return AbortNode(state, "Failed to write timestamp index");

    // add this block to the view's block chain
    view.SetBestBlock(pindex->GetBlockHash());

    // do batch verification if remains a day or collect proofs
    batchProofContainer->finalize();

    int64_t nTime5 = GetTimeMicros(); nTimeIndex += nTime5 - nTime4;
    LogPrint("bench", "    - Index writing: %.2fms [%.2fs]\n", 0.001 * (nTime5 - nTime4), nTimeIndex * 0.000001);

    // Watch for changes to the previous coinbase transaction.
    static uint256 hashPrevBestCoinBase;
    GetMainSignals().UpdatedTransaction(hashPrevBestCoinBase);
    hashPrevBestCoinBase = block.vtx[0]->GetHash();

    evoDb->WriteBestBlock(pindex->GetBlockHash());

    int64_t nTime6 = GetTimeMicros(); nTimeCallbacks += nTime6 - nTime5;
    LogPrint("bench", "    - Callbacks: %.2fms [%.2fs]\n", 0.001 * (nTime6 - nTime5), nTimeCallbacks * 0.000001);

    return true;
}

/**
 * Erase all of sigma/lelantus transactions conflicting with given block from the mempool
 */
void static RemoveConflictingPrivacyTransactionsFromMempool(const CBlock &block) {
    LOCK(mempool.cs);

    // Erase conflicting sigma/lelantus txs from the mempool
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    lelantus::CLelantusState *lelantusState = lelantus::CLelantusState::GetState();
    BOOST_FOREACH(CTransactionRef tx, block.vtx) {
        if (tx->IsSigmaSpend()) {
            BOOST_FOREACH(const CTxIn &txin, tx->vin)
            {
                Scalar zcSpendSerial = sigma::GetSigmaSpendSerialNumber(*tx, txin);
                uint256 thisTxHash = tx->GetHash();
                uint256 conflictingTxHash = sigmaState->GetMempoolConflictingTxHash(zcSpendSerial);
                if (!conflictingTxHash.IsNull() && conflictingTxHash != thisTxHash) {
                    std::list<CTransaction> removed;
                    auto pTx = mempool.get(conflictingTxHash);
                    if (pTx)
                        mempool.removeRecursive(*pTx);
                    LogPrintf("ConnectBlock: removed conflicting sigma/lelantus spend tx %s from the mempool\n",
                                conflictingTxHash.ToString());
                }

                // In any case we need to remove serial from mempool set
                sigmaState->RemoveSpendFromMempool(zcSpendSerial);
            }
        }
        else if (tx->IsLelantusJoinSplit()) {
           std::vector<Scalar> serials;
           try {
               serials = lelantus::GetLelantusJoinSplitSerialNumbers(*tx, tx->vin[0]);
           } catch (CBadTxIn&) {
               // nothing
           }

           uint256 thisTxHash = tx->GetHash();
            uint256 conflictingTxHash;
           for(const auto& serial : serials) {
                conflictingTxHash = lelantusState->GetMempoolConflictingTxHash(serial);
                if(!conflictingTxHash.IsNull())
                    break;
           }
           if (!conflictingTxHash.IsNull() && conflictingTxHash != thisTxHash) {
               std::list<CTransaction> removed;
               auto pTx = mempool.get(conflictingTxHash);
               if (pTx)
                   mempool.removeRecursive(*pTx);
                LogPrintf("ConnectBlock: removed conflicting lelantus joinsplit tx %s from the mempool\n",
                           conflictingTxHash.ToString());
           }

           // In any case we need to remove serial from mempool set
           lelantusState->RemoveSpendFromMempool(serials);
        }
        BOOST_FOREACH(const CTxOut &txout, tx->vout)
        {
            if (txout.scriptPubKey.IsSigmaMint()) {
                GroupElement pubCoinValue;
                try {
                    pubCoinValue = sigma::ParseSigmaMintScript(txout.scriptPubKey);
                } catch (std::invalid_argument&) {
                    // nothing
                }
                sigmaState->RemoveMintFromMempool(pubCoinValue);
            }
            if (txout.scriptPubKey.IsLelantusMint() || txout.scriptPubKey.IsLelantusJMint()) {
                GroupElement pubCoinValue;
                try {
                    lelantus::ParseLelantusMintScript(txout.scriptPubKey, pubCoinValue);
                } catch (std::invalid_argument&) {
                    // nothing
                }
                lelantusState->RemoveMintFromMempool(pubCoinValue);
            }
        }
    }
}

/**
 * Update the on-disk chain state.
 * The caches and indexes are flushed depending on the mode we're called with
 * if they're too large, if it's been a while since the last write,
 * or always and in all cases if we're in prune mode and are deleting files.
 */
bool static FlushStateToDisk(CValidationState &state, FlushStateMode mode, int nManualPruneHeight) {
    int64_t nMempoolUsage = mempool.DynamicMemoryUsage();
    const CChainParams& chainparams = Params();
    LOCK2(cs_main, cs_LastBlockFile);
    static int64_t nLastWrite = 0;
    static int64_t nLastFlush = 0;
    static int64_t nLastSetChain = 0;
    std::set<int> setFilesToPrune;
    bool fFlushForPrune = false;
    try {
    if (fPruneMode && (fCheckForPruning || nManualPruneHeight > 0) && !fReindex) {
        if (nManualPruneHeight > 0) {
            FindFilesToPruneManual(setFilesToPrune, nManualPruneHeight);
        } else {
            FindFilesToPrune(setFilesToPrune, chainparams.PruneAfterHeight());
            fCheckForPruning = false;
        }
        if (!setFilesToPrune.empty()) {
            fFlushForPrune = true;
            if (!fHavePruned) {
                pblocktree->WriteFlag("prunedblockfiles", true);
                fHavePruned = true;
            }
        }
    }
    int64_t nNow = GetTimeMicros();
    // Avoid writing/flushing immediately after startup.
    if (nLastWrite == 0) {
        nLastWrite = nNow;
    }
    if (nLastFlush == 0) {
        nLastFlush = nNow;
    }
    if (nLastSetChain == 0) {
        nLastSetChain = nNow;
    }
    int64_t nMempoolSizeMax = GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000;
    int64_t cacheSize = pcoinsTip->DynamicMemoryUsage() * DB_PEAK_USAGE_FACTOR;
    cacheSize += evoDb->GetMemoryUsage() * EVO_DB_USAGE_FACTOR * DB_PEAK_USAGE_FACTOR;
    int64_t nTotalSpace = nCoinCacheUsage + std::max<int64_t>(nMempoolSizeMax - nMempoolUsage, 0);
    // The cache is large and we're within 10% and 10 MiB of the limit, but we have time now (not in the middle of a block processing).
    bool fCacheLarge = mode == FLUSH_STATE_PERIODIC && cacheSize > std::max((9 * nTotalSpace) / 10, nTotalSpace - MAX_BLOCK_COINSDB_USAGE * 1024 * 1024);
    // The cache is over the limit, we have to write now.
    bool fCacheCritical = mode == FLUSH_STATE_IF_NEEDED && cacheSize > nTotalSpace;
    // It's been a while since we wrote the block index to disk. Do this frequently, so we don't need to redownload after a crash.
    bool fPeriodicWrite = mode == FLUSH_STATE_PERIODIC && nNow > nLastWrite + (int64_t)DATABASE_WRITE_INTERVAL * 1000000;
    // It's been very long since we flushed the cache. Do this infrequently, to optimize cache usage.
    bool fPeriodicFlush = mode == FLUSH_STATE_PERIODIC && nNow > nLastFlush + (int64_t)DATABASE_FLUSH_INTERVAL * 1000000;
    // Combine all conditions that result in a full cache flush.
    bool fDoFullFlush = (mode == FLUSH_STATE_ALWAYS) || fCacheLarge || fCacheCritical || fPeriodicFlush || fFlushForPrune;
    // Write blocks and block index to disk.
    if (fDoFullFlush || fPeriodicWrite) {
        // Depend on nMinDiskSpace to ensure we can write block index
        if (!CheckDiskSpace(0))
            return state.Error("out of disk space");
        // First make sure all block and undo data is flushed to disk.
        FlushBlockFile();
        // Then update all block file information (which may refer to block and undo files).
        {
            std::vector<std::pair<int, const CBlockFileInfo*> > vFiles;
            vFiles.reserve(setDirtyFileInfo.size());
            for (std::set<int>::iterator it = setDirtyFileInfo.begin(); it != setDirtyFileInfo.end(); ) {
                vFiles.push_back(std::make_pair(*it, &vinfoBlockFile[*it]));
                setDirtyFileInfo.erase(it++);
            }
            std::vector<const CBlockIndex*> vBlocks;
            vBlocks.reserve(setDirtyBlockIndex.size());
            for (std::set<CBlockIndex*>::iterator it = setDirtyBlockIndex.begin(); it != setDirtyBlockIndex.end(); ) {
                vBlocks.push_back(*it);
                setDirtyBlockIndex.erase(it++);
            }
            if (!pblocktree->WriteBatchSync(vFiles, nLastBlockFile, vBlocks)) {
                return AbortNode(state, "Failed to write to block index database");
            }
        }
        // Finally remove any pruned files
        if (fFlushForPrune)
            UnlinkPrunedFiles(setFilesToPrune);
        nLastWrite = nNow;
    }
    // Flush best chain related state. This can only be done if the blocks / block index write was also done.
    if (fDoFullFlush) {
        // Typical Coin structures on disk are around 48 bytes in size.
        // Pushing a new one to the database can cause it to be written
        // twice (once in the log, and once in the tables). This is already
        // an overestimation, as most will delete an existing entry or
        // overwrite one. Still, use a conservative safety factor of 2.
        if (!CheckDiskSpace(48 * 2 * 2 * pcoinsTip->GetCacheSize()))
            return state.Error("out of disk space");
        // Flush the chainstate (which may refer to block index entries).
        if (!pcoinsTip->Flush())
            return AbortNode(state, "Failed to write to coin database");
        if (!evoDb->CommitRootTransaction()) {
            return AbortNode(state, "Failed to commit EvoDB");
        }
        nLastFlush = nNow;
    }
    if (fDoFullFlush || ((mode == FLUSH_STATE_ALWAYS || mode == FLUSH_STATE_PERIODIC) && nNow > nLastSetChain + (int64_t)DATABASE_WRITE_INTERVAL * 1000000)) {
        // Update best block in wallet (so we can detect restored wallets).
        GetMainSignals().SetBestChain(chainActive.GetLocator());
        nLastSetChain = nNow;
    }
    } catch (const std::runtime_error& e) {
        return AbortNode(state, std::string("System error while flushing: ") + e.what());
    }
    return true;
}

void FlushStateToDisk() {
    CValidationState state;
    FlushStateToDisk(state, FLUSH_STATE_ALWAYS);
}

void PruneAndFlush() {
    CValidationState state;
    fCheckForPruning = true;
    FlushStateToDisk(state, FLUSH_STATE_NONE);
}

/** Update chainActive and related internal data structures. */
void static UpdateTip(CBlockIndex *pindexNew, const CChainParams &chainParams) {
    LogPrintf("UpdateTip() pindexNew.nHeight=%s\n", pindexNew->nHeight);
    chainActive.SetTip(pindexNew);

    // New best block
    txpools.AddTransactionsUpdated(1);

    cvBlockChange.notify_all();
    static bool fWarned = false;
    std::vector<std::string> warningMessages;
    if (!IsInitialBlockDownload())
    {
        int nUpgraded = 0;
        const CBlockIndex* pindex = chainActive.Tip();
        for (int bit = 0; bit < VERSIONBITS_NUM_BITS; bit++) {
            // Bit 12 (MTP) has different rules, do not produce any warning on it
            if (bit == 12)
                continue;

            WarningBitsConditionChecker checker(bit);
            ThresholdState state = checker.GetStateFor(pindex, chainParams.GetConsensus(), warningcache[bit]);
            if (state == THRESHOLD_ACTIVE || state == THRESHOLD_LOCKED_IN) {
                if (state == THRESHOLD_ACTIVE) {
                    std::string strWarning = strprintf(_("Warning: unknown new rules activated (versionbit %i)"), bit);
                    SetMiscWarning(strWarning);
                    if (!fWarned) {
                        AlertNotify(strWarning);
                        fWarned = true;
                    }
                } else {
                    warningMessages.push_back(strprintf("unknown new rules are about to activate (versionbit %i)", bit));
                }
            }
        }
        // Check the version of the last 100 blocks to see if we need to upgrade:
        for (int i = 0; i < 100 && pindex != NULL; i++)
        {
//            int32_t nExpectedVersion = ComputeBlockVersion(pindex->pprev, chainParams.GetConsensus());
            if ((pindex->nVersion & 0xff) > CBlock::CURRENT_VERSION)
                ++nUpgraded;
            pindex = pindex->pprev;
        }
        if (nUpgraded > 0)
            warningMessages.push_back(strprintf("%d of last 100 blocks have unexpected version", nUpgraded));
        if (nUpgraded > 100/2)
        {
            std::string strWarning = _("Warning: Unknown block versions being mined! It's possible unknown rules are in effect");
            // notify GetWarnings(), called by Qt and the JSON-RPC code to warn the user:
            SetMiscWarning(strWarning);
            if (!fWarned) {
                AlertNotify(strWarning);
                fWarned = true;
            }
        }
    }
    LogPrintf("%s: new best=%s height=%d version=0x%08x log2_work=%.8g tx=%lu date='%s' progress=%f cache=%.1fMiB(%utxo)", __func__,
      chainActive.Tip()->GetBlockHash().ToString(), chainActive.Height(), chainActive.Tip()->nVersion,
      log(chainActive.Tip()->nChainWork.getdouble())/log(2.0), (unsigned long)chainActive.Tip()->nChainTx,
      DateTimeStrFormat("%Y-%m-%d %H:%M:%S", chainActive.Tip()->GetBlockTime()),
      GuessVerificationProgress(chainParams.TxData(), chainActive.Tip()), pcoinsTip->DynamicMemoryUsage() * (1.0 / (1<<20)), pcoinsTip->GetCacheSize());
    if (!warningMessages.empty())
        LogPrintf(" warning='%s'", boost::algorithm::join(warningMessages, ", "));
    LogPrintf("\n");

}

/** Disconnect chainActive's tip. You probably want to call mempool.removeForReorg and manually re-limit mempool size after this, with cs_main held. */
bool static DisconnectTip(CValidationState& state, const CChainParams& chainparams, bool fBare = false)
{
    LogPrintf("DisconnectTip()\n");
    CBlockIndex *pindexDelete = chainActive.Tip();
    assert(pindexDelete);
    // Read block from disk.
    CBlock block;
    if (!ReadBlockFromDisk(block, pindexDelete, chainparams.GetConsensus()))
        return AbortNode(state, "Failed to read block");


    // retrieve all mints
    block.sigmaTxInfo = std::make_shared<sigma::CSigmaTxInfo>();
    block.lelantusTxInfo = std::make_shared<lelantus::CLelantusTxInfo>();

    std::unordered_map<Scalar, int> lelantusSerialsToRemove;
    sigma::spend_info_container sigmaSerialsToRemove;

    for (CTransactionRef tx : block.vtx) {
        CheckTransaction(*tx, state, false, tx->GetHash(), false, pindexDelete->pprev->nHeight,
            false, false, block.sigmaTxInfo.get(), block.lelantusTxInfo.get());
        if(GetBoolArg("-batching", true)) {
            if (tx->IsLelantusJoinSplit()) {
                const CTxIn &txin = tx->vin[0];
                std::unique_ptr<lelantus::JoinSplit> joinsplit;

                try {
                    joinsplit = lelantus::ParseLelantusJoinSplit(txin);
                }
                catch (CBadTxIn &) {
                    continue;
                }

                const std::vector<uint32_t> &ids = joinsplit->getCoinGroupIds();
                const std::vector<Scalar>& serials = joinsplit->getCoinSerialNumbers();

                if (serials.size() != ids.size()) {
                    continue;
                }

                for (size_t i = 0; i < serials.size(); i++) {
                    lelantusSerialsToRemove.insert(std::make_pair(serials[i], ids[i]));
                }
            } else if (tx->IsSigmaSpend()) {
                for (const CTxIn &txin : tx->vin) {
                    std::unique_ptr<sigma::CoinSpend> spend;
                    uint32_t coinGroupId;

                    try {
                        std::tie(spend, coinGroupId) = sigma::ParseSigmaSpend(txin);
                    }
                    catch (CBadTxIn &) {
                        continue;
                    }

                    Scalar serial = spend->getCoinSerialNumber();
                    sigmaSerialsToRemove.insert(std::make_pair(
                            serial, sigma::CSpendCoinInfo::make(spend->getDenomination(), coinGroupId)));
                }
            }
        }
    }

    // Apply the block atomically to the chain state.
    int64_t nStart = GetTimeMicros();
    {
        auto dbTx = evoDb->BeginTransaction();

        CCoinsViewCache view(pcoinsTip);
        if (DisconnectBlock(block, state, pindexDelete, view) != DISCONNECT_OK)
            return error("DisconnectTip(): DisconnectBlock %s failed", pindexDelete->GetBlockHash().ToString());
        bool flushed = view.Flush();
        assert(flushed);
        dbTx->Commit();
    }
    LogPrint("bench", "- Disconnect block: %.2fms\n", (GetTimeMicros() - nStart) * 0.001);

	sigma::DisconnectTipSigma(block, pindexDelete);
    lelantus::DisconnectTipLelantus(block, pindexDelete);

    BatchProofContainer* batchProofContainer = BatchProofContainer::get_instance();
    if (sigmaSerialsToRemove.size() > 0) {
        batchProofContainer->removeSigma(sigmaSerialsToRemove);
    }

    if (lelantusSerialsToRemove.size() > 0) {
        batchProofContainer->removeLelantus(lelantusSerialsToRemove);
    }

    // Roll back MTP state
    MTPState::GetMTPState()->SetLastBlock(pindexDelete->pprev, chainparams.GetConsensus());

    // Write the chain state to disk, if necessary.
    if (!FlushStateToDisk(state, FLUSH_STATE_IF_NEEDED))
        return false;

    if (!fBare) {
        // Resurrect mempool transactions from the disconnected block.
        std::vector<uint256> vHashUpdate;
        for (const auto& it : block.vtx) {
            const CTransaction& tx = *it;
            // ignore validation errors in resurrected transactions
            CValidationState stateDummy;
            CValidationState dandelionStateDummy;
            // Changes to mempool should also be made to Dandelion stempool.
            if (!tx.IsCoinBase()) {
                AcceptToMemoryPool(
                    txpools.getStemTxPool(),
                    dandelionStateDummy,
                    MakeTransactionRef(tx),
                    false, /* fLimitFree */
                    NULL, /* pfMissingInputs */
                    NULL,
                    false, /* fOverrideMempoolLimit */
                    0, /* nAbsurdFee */
                    false, /* isCheckWalletTransaction */
                    false /* markFiroSpendTransactionSerial */
                );
            }
            if (tx.IsCoinBase() || !AcceptToMemoryPool(mempool, stateDummy, MakeTransactionRef(tx), false, NULL)) {
                txpools.removeRecursive(tx);
            } else if (mempool.exists(tx.GetHash())) {
                vHashUpdate.push_back(tx.GetHash());
            }
        }
        // AcceptToMemoryPool/addUnchecked all assume that new mempool entries have
        // no in-mempool children, which is generally not true when adding
        // previously-confirmed transactions back to the mempool.
        // UpdateTransactionsFromBlock finds descendants of any transactions in this
        // block that were added back and cleans up the mempool state.
        txpools.UpdateTransactionsFromBlock(vHashUpdate);
    }
    // Update chainActive and related variables.
    UpdateTip(pindexDelete->pprev, chainparams);

#ifdef ENABLE_WALLET
    // update mint/spend wallet
    if (!GetBoolArg("-disablewallet", false) && pwalletMain->zwallet) {
        if (block.sigmaTxInfo->spentSerials.size() > 0) {
            pwalletMain->zwallet->GetTracker().UpdateSpendStateFromBlock(block.sigmaTxInfo->spentSerials);
        }

        if (block.sigmaTxInfo->mints.size() > 0) {
            pwalletMain->zwallet->GetTracker().UpdateMintStateFromBlock(block.sigmaTxInfo->mints);
        }

        if (block.lelantusTxInfo->spentSerials.size() > 0) {
            pwalletMain->zwallet->GetTracker().UpdateSpendStateFromBlock(block.lelantusTxInfo->spentSerials);
        }

        if (block.lelantusTxInfo->mints.size() > 0) {
            pwalletMain->zwallet->GetTracker().UpdateMintStateFromBlock(block.lelantusTxInfo->mints);
        }
    }
#endif

#ifdef ENABLE_ELYSIUM
    //! Elysium: begin block disconnect notification
    auto fElysium = isElysiumEnabled();

    if (fElysium) {
        LogPrint("handler", "Elysium handler: block disconnect begin [height: %d, reindex: %d]\n", GetHeight(), (int)fReindex);
        elysium_handler_disc_begin(GetHeight(), pindexDelete);
    }
#endif

    // Let wallets know transactions went from 1-confirmed to
    // 0-confirmed or conflicted:
    for (const auto& tx : block.vtx) {
        GetMainSignals().SyncTransaction(*tx, pindexDelete->pprev, CMainSignals::SYNC_TRANSACTION_NOT_IN_BLOCK);
    }

#ifdef ENABLE_ELYSIUM
    //! Elysium: end of block disconnect notification
    if (fElysium) {
        LogPrint("handler", "Elysium handler: block disconnect end [height: %d, reindex: %d]\n", GetHeight(), (int)fReindex);
        elysium_handler_disc_end(GetHeight(), pindexDelete);
    }
#endif

    return true;
}

static int64_t nTimeReadFromDisk = 0;
static int64_t nTimeConnectTotal = 0;
static int64_t nTimeFlush = 0;
static int64_t nTimeChainState = 0;
static int64_t nTimePostConnect = 0;

/**
 * Used to track blocks whose transactions were applied to the UTXO state as a
 * part of a single ActivateBestChainStep call.
 */
struct ConnectTrace {
    std::vector<std::pair<CBlockIndex*, std::shared_ptr<const CBlock> > > blocksConnected;
};

/**
 * Connect a new block to chainActive. pblock is either NULL or a pointer to a CBlock
 * corresponding to pindexNew, to bypass loading it again from disk.
 *
 * The block is always added to connectTrace (either after loading from disk or by copying
 * pblock) - if that is not intended, care must be taken to remove the last entry in
 * blocksConnected in case of failure.
 */
bool static ConnectTip(CValidationState& state, const CChainParams& chainparams, CBlockIndex* pindexNew, const std::shared_ptr<const CBlock>& pblock, ConnectTrace& connectTrace)
{
    LogPrintf("ConnectTip() nHeight=%s\n", pindexNew->nHeight);
    assert(pindexNew->pprev == chainActive.Tip());
    // Read block from disk.
    int64_t nTime1 = GetTimeMicros();
    if (!pblock) {
        std::shared_ptr<CBlock> pblockNew = std::make_shared<CBlock>();
        connectTrace.blocksConnected.emplace_back(pindexNew, pblockNew);
        if (!ReadBlockFromDisk(*pblockNew, pindexNew, chainparams.GetConsensus()))
            return AbortNode(state, "Failed to read block");
    } else {
        connectTrace.blocksConnected.emplace_back(pindexNew, pblock);
    }
    const CBlock& blockConnecting = *connectTrace.blocksConnected.back().second;
    // Apply the block atomically to the chain state.
    int64_t nTime2 = GetTimeMicros(); nTimeReadFromDisk += nTime2 - nTime1;
    int64_t nTime3;
    // LogPrint("bench", "  - Load block from disk: %.2fms [%.2fs]\n", (nTime2 - nTime1) * 0.001, nTimeReadFromDisk * 0.000001);
    {
        auto dbTx = evoDb->BeginTransaction();

        CCoinsViewCache view(pcoinsTip);
        bool rv = ConnectBlock(blockConnecting, state, pindexNew, view, chainparams);
        if (rv)
            RemoveConflictingPrivacyTransactionsFromMempool(blockConnecting);
        GetMainSignals().BlockChecked(blockConnecting, state);
        if (!rv) {
            if (state.IsInvalid())
                InvalidBlockFound(pindexNew, state);
            return error("ConnectTip(): ConnectBlock %s failed", pindexNew->GetBlockHash().ToString());
        }
        nTime3 = GetTimeMicros(); nTimeConnectTotal += nTime3 - nTime2;
        LogPrint("bench", "  - Connect total: %.2fms [%.2fs]\n", (nTime3 - nTime2) * 0.001, nTimeConnectTotal * 0.000001);
        bool flushed = view.Flush();
        assert(flushed);
        dbTx->Commit();
    }
    int64_t nTime4 = GetTimeMicros(); nTimeFlush += nTime4 - nTime3;
    LogPrint("bench", "  - Flush: %.2fms [%.2fs]\n", (nTime4 - nTime3) * 0.001, nTimeFlush * 0.000001);
    // Write the chain state to disk, if necessary.
    if (!FlushStateToDisk(state, FLUSH_STATE_IF_NEEDED))
        return false;
    int64_t nTime5 = GetTimeMicros(); nTimeChainState += nTime5 - nTime4;
    LogPrint("bench", "  - Writing chainstate: %.2fms [%.2fs]\n", (nTime5 - nTime4) * 0.001, nTimeChainState * 0.000001);

#ifdef ENABLE_ELYSIUM
    bool fElysium = isElysiumEnabled();

    //! Elysium: transaction position within the block
    unsigned int nTxIdx = 0;
    //! Elysium: number of meta transactions found
    unsigned int nNumMetaTxs = 0;

    //! Elysium: begin block connect notification
    if (fElysium) {
        LogPrint("handler", "Elysium handler: block connect begin [height: %d]\n", GetHeight());
        elysium_handler_block_begin(GetHeight(), pindexNew);
    }
#endif

    // Remove conflicting transactions from the mempool.;
    txpools.removeForBlock(blockConnecting.vtx, pindexNew->nHeight);

    // Update chainActive & related variables.
    UpdateTip(pindexNew, chainparams);

#ifdef ENABLE_ELYSIUM
        //! Elysium: new confirmed transaction notification
    if (fElysium) {
        BOOST_FOREACH(CTransactionRef tx, blockConnecting.vtx) {
                LogPrint("handler", "Elysium handler: new confirmed transaction [height: %d, idx: %u]\n", GetHeight(), nTxIdx);
                if (elysium_handler_tx(*tx, GetHeight(), nTxIdx++, pindexNew)) ++nNumMetaTxs;
            }
    }
#endif

#ifdef ENABLE_WALLET
    // Sync with HDMint wallet

    if (!GetBoolArg("-disablewallet", false) && pwalletMain->zwallet && blockConnecting.sigmaTxInfo) {
        LogPrintf("Checking if block contains wallet mints..\n");
        if (blockConnecting.sigmaTxInfo->spentSerials.size() > 0) {
            LogPrintf("HDmint: UpdateSpendStateFromBlock. [height: %d]\n", GetHeight());
            pwalletMain->zwallet->GetTracker().UpdateSpendStateFromBlock(blockConnecting.sigmaTxInfo->spentSerials);
        }

        if (blockConnecting.sigmaTxInfo->mints.size() > 0) {
            LogPrintf("HDmint: UpdateMintStateFromBlock. [height: %d]\n", GetHeight());
            pwalletMain->zwallet->GetTracker().UpdateMintStateFromBlock(blockConnecting.sigmaTxInfo->mints);
        }

        if (blockConnecting.lelantusTxInfo->spentSerials.size() > 0) {
            LogPrintf("HDmint: UpdateSpendStateFromBlock. [height: %d]\n", GetHeight());
            pwalletMain->zwallet->GetTracker().UpdateSpendStateFromBlock(blockConnecting.lelantusTxInfo->spentSerials);
        }

        if (blockConnecting.lelantusTxInfo->mints.size() > 0) {
            LogPrintf("HDmint: UpdateSpendStateFromBlock. [height: %d]\n", GetHeight());
            pwalletMain->zwallet->GetTracker().UpdateMintStateFromBlock(blockConnecting.lelantusTxInfo->mints);
        }
    }
#endif

#ifdef ENABLE_ELYSIUM
    //! Elysium: end of block connect notification
    if (fElysium) {        
        elysium_handler_block_end(GetHeight(), pindexNew, nNumMetaTxs);
		LogPrint("handler", "Elysium handler: block connect end [new height: %d, found: %u txs]\n", GetHeight(), nNumMetaTxs);
    }
#endif

    int64_t nTime6 = GetTimeMicros(); nTimePostConnect += nTime6 - nTime5; nTimeTotal += nTime6 - nTime1;
    LogPrint("bench", "  - Connect postprocess: %.2fms [%.2fs]\n", (nTime6 - nTime5) * 0.001, nTimePostConnect * 0.000001);
    LogPrint("bench", "- Connect block: %.2fms [%.2fs]\n", (nTime6 - nTime1) * 0.001, nTimeTotal * 0.000001);
    return true;
}

int GetInputAge(const CTxIn &txin) {
    CCoinsView viewDummy;
    CCoinsViewCache view(&viewDummy);
    {
        LOCK(mempool.cs);
        CCoinsViewMemPool viewMempool(pcoinsTip, mempool);
        view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view

        const Coin &coin = view.AccessCoin(txin.prevout);

        if (!coin.IsSpent()) {
            if (coin.nHeight < 0) return 0;
            return chainActive.Height() - coin.nHeight + 1;
        } else {
            return -1;
        }
    }
}

CAmount GetZnodePayment(const Consensus::Params &params, bool fMTP) {
//    CAmount ret = blockValue * 30/100 ; // start at 30%
//    int nMNPIBlock = Params().GetConsensus().nZnodePaymentsStartBlock;
////    int nMNPIBlock = Params().GetConsensus().nZnodePaymentsIncreaseBlock;
//    int nMNPIPeriod = Params().GetConsensus().nZnodePaymentsIncreasePeriod;
//
//    // mainnet:
//    if (nHeight > nMNPIBlock) ret += blockValue / 20; // 158000 - 25.0% - 2014-10-24
//    if (nHeight > nMNPIBlock + (nMNPIPeriod * 1)) ret += blockValue / 20; // 175280 - 30.0% - 2014-11-25
//    if (nHeight > nMNPIBlock + (nMNPIPeriod * 2)) ret += blockValue / 20; // 192560 - 35.0% - 2014-12-26
//    if (nHeight > nMNPIBlock + (nMNPIPeriod * 3)) ret += blockValue / 40; // 209840 - 37.5% - 2015-01-26
//    if (nHeight > nMNPIBlock + (nMNPIPeriod * 4)) ret += blockValue / 40; // 227120 - 40.0% - 2015-02-27
//    if (nHeight > nMNPIBlock + (nMNPIPeriod * 5)) ret += blockValue / 40; // 244400 - 42.5% - 2015-03-30
//    if (nHeight > nMNPIBlock + (nMNPIPeriod * 6)) ret += blockValue / 40; // 261680 - 45.0% - 2015-05-01
//    if (nHeight > nMNPIBlock + (nMNPIPeriod * 7)) ret += blockValue / 40; // 278960 - 47.5% - 2015-06-01
//    if (nHeight > nMNPIBlock + (nMNPIPeriod * 9)) ret += blockValue / 40; // 313520 - 50.0% - 2015-08-03
    CAmount coin = fMTP ? COIN/params.nMTPRewardReduction : COIN;
    CAmount ret = 15 * coin; //15 or 7.5 FIRO

    return ret;
}

bool DisconnectBlocks(int blocks) {
    LOCK(cs_main);

    CValidationState state;
    const CChainParams &chainparams = Params();

    LogPrintf("DisconnectBlocks -- Got command to replay %d blocks\n", blocks);
    for (int i = 0; i < blocks; i++) {
        if (!DisconnectTip(state, chainparams) || !state.IsValid()) {
            return false;
        }
    }

    return true;
}

void ReprocessBlocks(int nBlocks) {
    LOCK(cs_main);

    std::map<uint256, int64_t>::iterator it = mapRejectedBlocks.begin();
    while (it != mapRejectedBlocks.end()) {
        //use a window twice as large as is usual for the nBlocks we want to reset
        if ((*it).second > GetTime() - (nBlocks * 60 * 5)) {
            BlockMap::iterator mi = mapBlockIndex.find((*it).first);
            if (mi != mapBlockIndex.end() && (*mi).second) {

                CBlockIndex *pindex = (*mi).second;
                LogPrintf("ReprocessBlocks -- %s\n", (*it).first.ToString());

                ResetBlockFailureFlags(pindex);            }
        }
        ++it;
    }

    DisconnectBlocks(nBlocks);

    CValidationState state;
    ActivateBestChain(state, Params());
}


/**
 * Return the tip of the chain with the most work in it, that isn't
 * known to be invalid (it's however far from certain to be valid).
 */
static CBlockIndex* FindMostWorkChain() {
    do {
        CBlockIndex *pindexNew = NULL;

        // Find the best candidate header.
        {
            std::set<CBlockIndex*, CBlockIndexWorkComparator>::reverse_iterator it = setBlockIndexCandidates.rbegin();
            if (it == setBlockIndexCandidates.rend())
                return NULL;
            pindexNew = *it;
        }

        // Check whether all blocks on the path between the currently active chain and the candidate are valid.
        // Just going until the active chain is an optimization, as we know all blocks in it are valid already.
        CBlockIndex *pindexTest = pindexNew;
        bool fInvalidAncestor = false;
        while (pindexTest && !chainActive.Contains(pindexTest)) {
            assert(pindexTest->nChainTx || pindexTest->nHeight == 0);

            // Pruned nodes may have entries in setBlockIndexCandidates for
            // which block files have been deleted.  Remove those as candidates
            // for the most work chain if we come across them; we can't switch
            // to a chain unless we have all the non-active-chain parent blocks.
            bool fFailedChain = pindexTest->nStatus & BLOCK_FAILED_MASK;
            bool fMissingData = !(pindexTest->nStatus & BLOCK_HAVE_DATA);
            if (fFailedChain || fMissingData) {
                // Candidate chain is not usable (either invalid or missing data)
                if (fFailedChain && (pindexBestInvalid == NULL || pindexNew->nChainWork > pindexBestInvalid->nChainWork))
                    pindexBestInvalid = pindexNew;
                CBlockIndex *pindexFailed = pindexNew;
                // Remove the entire chain from the set.
                while (pindexTest != pindexFailed) {
                    if (fFailedChain) {
                        pindexFailed->nStatus |= BLOCK_FAILED_CHILD;
                    } else if (fMissingData) {
                        // If we're missing data, then add back to mapBlocksUnlinked,
                        // so that if the block arrives in the future we can try adding
                        // to setBlockIndexCandidates again.
                        mapBlocksUnlinked.insert(std::make_pair(pindexFailed->pprev, pindexFailed));
                    }
                    setBlockIndexCandidates.erase(pindexFailed);
                    pindexFailed = pindexFailed->pprev;
                }
                setBlockIndexCandidates.erase(pindexTest);
                fInvalidAncestor = true;
                break;
            }
            pindexTest = pindexTest->pprev;
        }
        if (!fInvalidAncestor)
            return pindexNew;
    } while(true);
}

/** Delete all entries in setBlockIndexCandidates that are worse than the current tip. */
static void PruneBlockIndexCandidates() {
    // Note that we can't delete the current block itself, as we may need to return to it later in case a
    // reorganization to a better block fails.
    std::set<CBlockIndex*, CBlockIndexWorkComparator>::iterator it = setBlockIndexCandidates.begin();
    while (it != setBlockIndexCandidates.end() && setBlockIndexCandidates.value_comp()(*it, chainActive.Tip())) {
        setBlockIndexCandidates.erase(it++);
    }
    // Either the current tip or a successor of it we're working towards is left in setBlockIndexCandidates.
    assert(!setBlockIndexCandidates.empty());
}

/**
 * Try to make some progress towards making pindexMostWork the active block.
 * pblock is either NULL or a pointer to a CBlock corresponding to pindexMostWork.
 */
static bool ActivateBestChainStep(CValidationState& state, const CChainParams& chainparams, CBlockIndex* pindexMostWork, const std::shared_ptr<const CBlock>& pblock, bool& fInvalidFound, ConnectTrace& connectTrace)
{
    LogPrintf("ActivateBestChainStep()\n");
    AssertLockHeld(cs_main);
    const CBlockIndex *pindexOldTip = chainActive.Tip();
    const CBlockIndex *pindexFork = chainActive.FindFork(pindexMostWork);

    // Disconnect active blocks which are no longer in the best chain.
    bool fBlocksDisconnected = false;
    while (chainActive.Tip() && chainActive.Tip() != pindexFork) {
        if (!DisconnectTip(state, chainparams))
            return false;
        fBlocksDisconnected = true;
    }

    // Build list of new blocks to connect.
    std::vector<CBlockIndex*> vpindexToConnect;
    bool fContinue = true;
    int nHeight = pindexFork ? pindexFork->nHeight : -1;
    while (fContinue && nHeight != pindexMostWork->nHeight) {
        // Don't iterate the entire list of potential improvements toward the best tip, as we likely only need
        // a few blocks along the way.
        int nTargetHeight = std::min(nHeight + 32, pindexMostWork->nHeight);
        vpindexToConnect.clear();
        vpindexToConnect.reserve(nTargetHeight - nHeight);
        CBlockIndex *pindexIter = pindexMostWork->GetAncestor(nTargetHeight);
        while (pindexIter && pindexIter->nHeight != nHeight) {
            vpindexToConnect.push_back(pindexIter);
            pindexIter = pindexIter->pprev;
        }
        nHeight = nTargetHeight;

        // Connect new blocks.
        BOOST_REVERSE_FOREACH(CBlockIndex *pindexConnect, vpindexToConnect) {
            if (!ConnectTip(state, chainparams, pindexConnect, pindexConnect == pindexMostWork ? pblock : std::shared_ptr<const CBlock>(), connectTrace)) {
                if (state.IsInvalid()) {
                    // The block violates a consensus rule.
                    if (!state.CorruptionPossible())
                        InvalidChainFound(vpindexToConnect.back());
                    state = CValidationState();
                    fInvalidFound = true;
                    fContinue = false;
                    // If we didn't actually connect the block, don't notify listeners about it
                    connectTrace.blocksConnected.pop_back();
                    break;
                } else {
                    // A system error occurred (disk space, database error, ...).
                    return false;
                }
            } else {
                PruneBlockIndexCandidates();
                if (!pindexOldTip || chainActive.Tip()->nChainWork > pindexOldTip->nChainWork) {
                    // We're in a better position than we were. Return temporarily to release the lock.
                    fContinue = false;
                    break;
                }
            }
        }
    }

    if (fBlocksDisconnected) {
        txpools.removeForReorg(
            pcoinsTip,
            chainActive.Tip()->nHeight + 1,
            STANDARD_LOCKTIME_VERIFY_FLAGS);

        LimitMempoolSize(mempool,
                         GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000,
                         GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60);

	    // Changes to mempool should also be made to Dandelion stempool
        LimitMempoolSize(txpools.getStemTxPool(),
                         GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000,
                         GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60);
    }
    txpools.check(pcoinsTip);

    // Callbacks/notifications for a new best chain.
    if (fInvalidFound)
        CheckForkWarningConditionsOnNewFork(vpindexToConnect.back());
    else
        CheckForkWarningConditions();
    return true;
}

static void NotifyHeaderTip() {
    bool fNotify = false;
    bool fInitialBlockDownload = false;
    static CBlockIndex* pindexHeaderOld = NULL;
    CBlockIndex* pindexHeader = NULL;
    {
        LOCK(cs_main);
        pindexHeader = pindexBestHeader;

        if (pindexHeader != pindexHeaderOld) {
            fNotify = true;
            fInitialBlockDownload = IsInitialBlockDownload();
            pindexHeaderOld = pindexHeader;
        }
    }
    // Send block tip changed notifications without cs_main
    if (fNotify) {
        uiInterface.NotifyHeaderTip(fInitialBlockDownload, pindexHeader);
        GetMainSignals().NotifyHeaderTip(pindexHeader, fInitialBlockDownload);
    }
}

/**
 * Make the best chain active, in multiple steps. The result is either failure
 * or an activated best chain. pblock is either NULL or a pointer to a block
 * that is already loaded (to avoid loading it again from disk).
 */
bool ActivateBestChain(CValidationState &state, const CChainParams& chainparams, std::shared_ptr<const CBlock> pblock) {
    // Note that while we're often called here from ProcessNewBlock, this is
    // far from a guarantee. Things in the P2P/RPC will often end up calling
    // us in the middle of ProcessNewBlock - do not assume pblock is set
    // sanely for performance or correctness!

    CBlockIndex *pindexMostWork = NULL;
    CBlockIndex *pindexNewTip = NULL;
    do {
        boost::this_thread::interruption_point();
        if (ShutdownRequested())
            break;

        const CBlockIndex *pindexFork;
        ConnectTrace connectTrace;
        bool fInitialDownload;
        {
            LOCK(cs_main);
            { // TODO: Tempoarily ensure that mempool removals are notified before
              // connected transactions.  This shouldn't matter, but the abandoned
              // state of transactions in our wallet is currently cleared when we
              // receive another notification and there is a race condition where
              // notification of a connected conflict might cause an outside process
              // to abandon a transaction and then have it inadvertantly cleared by
              // the notification that the conflicted transaction was evicted.
            MemPoolConflictRemovalTracker mrt(mempool);
            CBlockIndex *pindexOldTip = chainActive.Tip();
            if (pindexMostWork == NULL) {
                pindexMostWork = FindMostWorkChain();
                if (!fReindex && !IsInitialBlockDownload() &&
                        pindexMostWork != NULL &&
                        pindexMostWork != chainActive.Tip() &&
                        chainActive.Height() >= chainparams.GetConsensus().nMaxReorgDepthEnforcementBlock &&
                        chainActive.Height() < chainparams.GetConsensus().DIP0008Height + 100 &&
                        !GetBoolArg("-allowdeepreorg", false)) {
                    const CBlockIndex *pindexFork = chainActive.FindFork(pindexMostWork);
                    assert(pindexFork != NULL);
                    if (chainActive.Tip() != pindexFork &&
                            pindexFork->nHeight < chainActive.Height() - chainparams.GetConsensus().nMaxReorgDepth) {
                        LogPrintf("Deep reorg of %d blocks blocked (most work block = %s, fork block = %s)\n",
                                pindexMostWork->nHeight - pindexFork->nHeight,
                                pindexMostWork->GetBlockHash().ToString(),
                                pindexFork->GetBlockHash().ToString());
                        // mark block on wrong chain as invalid
                        InvalidateBlock(state, chainparams, pindexMostWork->GetAncestor(pindexFork->nHeight+1));
                        return state.Error("Reorg depth exceeds maximum allowed value");
                    }
                }
            }

            // Whether we have anything to do at all.
            if (pindexMostWork == NULL || pindexMostWork == chainActive.Tip())
                return true;

            bool fInvalidFound = false;
            std::shared_ptr<const CBlock> nullBlockPtr;
            if (!ActivateBestChainStep(state, chainparams, pindexMostWork, pblock && pblock->GetHash() == pindexMostWork->GetBlockHash() ? pblock : nullBlockPtr, fInvalidFound, connectTrace))
                return false;

            if (fInvalidFound) {
                // Wipe cache, we may need another branch now.
                pindexMostWork = NULL;
            }
            pindexNewTip = chainActive.Tip();
            pindexFork = chainActive.FindFork(pindexOldTip);
            fInitialDownload = IsInitialBlockDownload();

            // throw all transactions though the signal-interface

            } // MemPoolConflictRemovalTracker destroyed and conflict evictions are notified

            // Transactions in the connnected block are notified
            for (const auto& pair : connectTrace.blocksConnected) {
                assert(pair.second);
                const CBlock& block = *(pair.second);
                for (unsigned int i = 0; i < block.vtx.size(); i++)
                    GetMainSignals().SyncTransaction(*block.vtx[i], pair.first, i);
            }
        }
        // When we reach this point, we switched to a new tip (stored in pindexNewTip).

        // Notifications/callbacks that can run without cs_main

        // Notify external listeners about the new tip.
        GetMainSignals().UpdatedBlockTip(pindexNewTip, pindexFork, fInitialDownload);

        // Always notify the UI if a new block tip was connected
        if (pindexFork != pindexNewTip) {
            uiInterface.NotifyBlockTip(fInitialDownload, pindexNewTip);
        }
    } while (pindexNewTip != pindexMostWork);
    CheckBlockIndex(chainparams.GetConsensus());

    // Write changes periodically to disk, after relay.
    if (!FlushStateToDisk(state, FLUSH_STATE_PERIODIC)) {
        return false;
    }

    return true;
}


bool PreciousBlock(CValidationState& state, const CChainParams& params, CBlockIndex *pindex)
{
    {
        LOCK(cs_main);
        if (pindex->nChainWork < chainActive.Tip()->nChainWork) {
            // Nothing to do, this block is not at the tip.
            return true;
        }
        if (chainActive.Tip()->nChainWork > nLastPreciousChainwork) {
            // The chain has been extended since the last call, reset the counter.
            nBlockReverseSequenceId = -1;
        }
        nLastPreciousChainwork = chainActive.Tip()->nChainWork;
        setBlockIndexCandidates.erase(pindex);
        pindex->nSequenceId = nBlockReverseSequenceId;
        if (nBlockReverseSequenceId > std::numeric_limits<int32_t>::min()) {
            // We can't keep reducing the counter if somebody really wants to
            // call preciousblock 2**31-1 times on the same set of tips...
            nBlockReverseSequenceId--;
        }
        if (pindex->IsValid(BLOCK_VALID_TRANSACTIONS) && pindex->nChainTx) {
            setBlockIndexCandidates.insert(pindex);
            PruneBlockIndexCandidates();
        }
    }

    return ActivateBestChain(state, params);
}

bool InvalidateBlock(CValidationState& state, const CChainParams& chainparams, CBlockIndex *pindex)
{
    AssertLockHeld(cs_main);

    // Mark the block itself as invalid.
    pindex->nStatus |= BLOCK_FAILED_VALID;
    setDirtyBlockIndex.insert(pindex);
    setBlockIndexCandidates.erase(pindex);

    while (chainActive.Contains(pindex)) {
        CBlockIndex *pindexWalk = chainActive.Tip();
        pindexWalk->nStatus |= BLOCK_FAILED_CHILD;
        setDirtyBlockIndex.insert(pindexWalk);
        setBlockIndexCandidates.erase(pindexWalk);
        // ActivateBestChain considers blocks already in chainActive
        // unconditionally valid already, so force disconnect away from it.
        if (!DisconnectTip(state, chainparams)) {
            txpools.removeForReorg(pcoinsTip, chainActive.Tip()->nHeight + 1, STANDARD_LOCKTIME_VERIFY_FLAGS);
            return false;
        }
    }

    LimitMempoolSize(mempool, GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000, GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60);

    // Changes to mempool should also be made to Dandelion stempool
    LimitMempoolSize(txpools.getStemTxPool(), GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000, GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60);

    // The resulting new best tip may not be in setBlockIndexCandidates anymore, so
    // add it again.
    BlockMap::iterator it = mapBlockIndex.begin();
    while (it != mapBlockIndex.end()) {
        if (it->second->IsValid(BLOCK_VALID_TRANSACTIONS) && it->second->nChainTx && !setBlockIndexCandidates.value_comp()(it->second, chainActive.Tip())) {
            setBlockIndexCandidates.insert(it->second);
        }
        it++;
    }

    InvalidChainFound(pindex);
    txpools.removeForReorg(pcoinsTip, chainActive.Tip()->nHeight + 1, STANDARD_LOCKTIME_VERIFY_FLAGS);
    GetMainSignals().UpdatedBlockTip(chainActive.Tip(), NULL, IsInitialBlockDownload());
    uiInterface.NotifyBlockTip(IsInitialBlockDownload(), pindex->pprev);
    return true;
}

bool ResetBlockFailureFlags(CBlockIndex *pindex) {
    AssertLockHeld(cs_main);

    int nHeight = pindex->nHeight;

    // Remove the invalidity flag from this block and all its descendants.
    BlockMap::iterator it = mapBlockIndex.begin();
    while (it != mapBlockIndex.end()) {
        if (!it->second->IsValid() && it->second->GetAncestor(nHeight) == pindex) {
            it->second->nStatus &= ~BLOCK_FAILED_MASK;
            setDirtyBlockIndex.insert(it->second);
            if (it->second->IsValid(BLOCK_VALID_TRANSACTIONS) && it->second->nChainTx && setBlockIndexCandidates.value_comp()(chainActive.Tip(), it->second)) {
                setBlockIndexCandidates.insert(it->second);
            }
            if (it->second == pindexBestInvalid) {
                // Reset invalid block marker if it was pointing to one of those.
                pindexBestInvalid = NULL;
            }
        }
        it++;
    }

    // Remove the invalidity flag from all ancestors too.
    while (pindex != NULL) {
        if (pindex->nStatus & BLOCK_FAILED_MASK) {
            pindex->nStatus &= ~BLOCK_FAILED_MASK;
            setDirtyBlockIndex.insert(pindex);
        }
        pindex = pindex->pprev;
    }
    return true;
}

CBlockIndex* AddToBlockIndex(const CBlockHeader& block)
{
    // Check for duplicate
    uint256 hash = block.GetHash();
    BlockMap::iterator it = mapBlockIndex.find(hash);
    if (it != mapBlockIndex.end())
        return it->second;

    // Construct new block index object
    CBlockIndex* pindexNew = new CBlockIndex(block);
    assert(pindexNew);
    // We assign the sequence id to blocks only when the full data is available,
    // to avoid miners withholding blocks but broadcasting headers, to get a
    // competitive advantage.
    pindexNew->nSequenceId = 0;
    BlockMap::iterator mi = mapBlockIndex.insert(std::make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);
    BlockMap::iterator miPrev = mapBlockIndex.find(block.hashPrevBlock);
    if (miPrev != mapBlockIndex.end())
    {
        pindexNew->pprev = (*miPrev).second;
        pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
        pindexNew->BuildSkip();
    }
    pindexNew->nTimeMax = (pindexNew->pprev ? std::max(pindexNew->pprev->nTimeMax, pindexNew->nTime) : pindexNew->nTime);
    pindexNew->nChainWork = (pindexNew->pprev ? pindexNew->pprev->nChainWork : 0) + GetBlockProof(*pindexNew);
    pindexNew->RaiseValidity(BLOCK_VALID_TREE);
    if (pindexBestHeader == NULL || pindexBestHeader->nChainWork < pindexNew->nChainWork)
        pindexBestHeader = pindexNew;

    setDirtyBlockIndex.insert(pindexNew);

    // track prevBlockHash -> pindex (multimap)
    if (pindexNew->pprev) {
        mapPrevBlockIndex.emplace(pindexNew->pprev->GetBlockHash(), pindexNew);
    }

    return pindexNew;
}

/** Mark a block as having its data received and checked (up to BLOCK_VALID_TRANSACTIONS). */
bool ReceivedBlockTransactions(const CBlock &block, CValidationState& state, CBlockIndex *pindexNew, const CDiskBlockPos& pos)
{
    pindexNew->nTx = block.vtx.size();
    pindexNew->nChainTx = 0;
    pindexNew->nFile = pos.nFile;
    pindexNew->nDataPos = pos.nPos;
    pindexNew->nUndoPos = 0;
    pindexNew->nStatus |= BLOCK_HAVE_DATA;
    if (IsWitnessEnabled(pindexNew->pprev, Params().GetConsensus())) {
        pindexNew->nStatus |= BLOCK_OPT_WITNESS;
    }
    pindexNew->RaiseValidity(BLOCK_VALID_TRANSACTIONS);
    setDirtyBlockIndex.insert(pindexNew);

    if (pindexNew->pprev == NULL || pindexNew->pprev->nChainTx) {
        // If pindexNew is the genesis block or all parents are BLOCK_VALID_TRANSACTIONS.
        std::deque<CBlockIndex*> queue;
        queue.push_back(pindexNew);

        // Recursively process any descendant blocks that now may be eligible to be connected.
        while (!queue.empty()) {
            CBlockIndex *pindex = queue.front();
            queue.pop_front();
            pindex->nChainTx = (pindex->pprev ? pindex->pprev->nChainTx : 0) + pindex->nTx;
            {
                LOCK(cs_nBlockSequenceId);
                pindex->nSequenceId = nBlockSequenceId++;
            }
            if (chainActive.Tip() == NULL || !setBlockIndexCandidates.value_comp()(pindex, chainActive.Tip())) {
                setBlockIndexCandidates.insert(pindex);
            }
            std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, std::multimap<CBlockIndex*, CBlockIndex*>::iterator> range = mapBlocksUnlinked.equal_range(pindex);
            while (range.first != range.second) {
                std::multimap<CBlockIndex*, CBlockIndex*>::iterator it = range.first;
                queue.push_back(it->second);
                range.first++;
                mapBlocksUnlinked.erase(it);
            }
        }
    } else {
        if (pindexNew->pprev && pindexNew->pprev->IsValid(BLOCK_VALID_TREE)) {
            mapBlocksUnlinked.insert(std::make_pair(pindexNew->pprev, pindexNew));
        }
    }

    return true;
}

bool FindBlockPos(CValidationState &state, CDiskBlockPos &pos, unsigned int nAddSize, unsigned int nHeight, uint64_t nTime, bool fKnown = false)
{
    LOCK(cs_LastBlockFile);

    unsigned int nFile = fKnown ? pos.nFile : nLastBlockFile;
    if (vinfoBlockFile.size() <= nFile) {
        vinfoBlockFile.resize(nFile + 1);
    }

    if (!fKnown) {
        while (vinfoBlockFile[nFile].nSize + nAddSize >= MAX_BLOCKFILE_SIZE) {
            nFile++;
            if (vinfoBlockFile.size() <= nFile) {
                vinfoBlockFile.resize(nFile + 1);
            }
        }
        pos.nFile = nFile;
        pos.nPos = vinfoBlockFile[nFile].nSize;
    }

    if ((int)nFile != nLastBlockFile) {
        if (!fKnown) {
            LogPrintf("Leaving block file %i: %s\n", nLastBlockFile, vinfoBlockFile[nLastBlockFile].ToString());
        }
        FlushBlockFile(!fKnown);
        nLastBlockFile = nFile;
    }

    vinfoBlockFile[nFile].AddBlock(nHeight, nTime);
    if (fKnown)
        vinfoBlockFile[nFile].nSize = std::max(pos.nPos + nAddSize, vinfoBlockFile[nFile].nSize);
    else
        vinfoBlockFile[nFile].nSize += nAddSize;

    if (!fKnown) {
        unsigned int nOldChunks = (pos.nPos + BLOCKFILE_CHUNK_SIZE - 1) / BLOCKFILE_CHUNK_SIZE;
        unsigned int nNewChunks = (vinfoBlockFile[nFile].nSize + BLOCKFILE_CHUNK_SIZE - 1) / BLOCKFILE_CHUNK_SIZE;
        if (nNewChunks > nOldChunks) {
            if (fPruneMode)
                fCheckForPruning = true;
            if (CheckDiskSpace(nNewChunks * BLOCKFILE_CHUNK_SIZE - pos.nPos)) {
                FILE *file = OpenBlockFile(pos);
                if (file) {
                    LogPrintf("Pre-allocating up to position 0x%x in blk%05u.dat\n", nNewChunks * BLOCKFILE_CHUNK_SIZE, pos.nFile);
                    AllocateFileRange(file, pos.nPos, nNewChunks * BLOCKFILE_CHUNK_SIZE - pos.nPos);
                    fclose(file);
                }
            }
            else
                return state.Error("out of disk space");
        }
    }

    setDirtyFileInfo.insert(nFile);
    return true;
}

bool FindUndoPos(CValidationState &state, int nFile, CDiskBlockPos &pos, unsigned int nAddSize)
{
    pos.nFile = nFile;

    LOCK(cs_LastBlockFile);

    unsigned int nNewSize;
    pos.nPos = vinfoBlockFile[nFile].nUndoSize;
    nNewSize = vinfoBlockFile[nFile].nUndoSize += nAddSize;
    setDirtyFileInfo.insert(nFile);

    unsigned int nOldChunks = (pos.nPos + UNDOFILE_CHUNK_SIZE - 1) / UNDOFILE_CHUNK_SIZE;
    unsigned int nNewChunks = (nNewSize + UNDOFILE_CHUNK_SIZE - 1) / UNDOFILE_CHUNK_SIZE;
    if (nNewChunks > nOldChunks) {
        if (fPruneMode)
            fCheckForPruning = true;
        if (CheckDiskSpace(nNewChunks * UNDOFILE_CHUNK_SIZE - pos.nPos)) {
            FILE *file = OpenUndoFile(pos);
            if (file) {
                LogPrintf("Pre-allocating up to position 0x%x in rev%05u.dat\n", nNewChunks * UNDOFILE_CHUNK_SIZE, pos.nFile);
                AllocateFileRange(file, pos.nPos, nNewChunks * UNDOFILE_CHUNK_SIZE - pos.nPos);
                fclose(file);
            }
        }
        else
            return state.Error("out of disk space");
    }

    return true;
}

//btzc: code from vertcoin, add
bool CheckBlockHeader(const CBlockHeader& block, CValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW)
{
    int nHeight = GetNHeight(block);
    // set nHeight to INT_MAX if block is not found in index and it's not genesis block
    if (nHeight == 0 && !block.hashPrevBlock.IsNull())
        nHeight = INT_MAX;
    if (fCheckPOW && !CheckProofOfWork(block.GetPoWHash(nHeight), block.nBits, consensusParams))
        return state.DoS(50, false, REJECT_INVALID, "high-hash", false, "proof of work failed");
    return true;
}

bool CheckBlock(const CBlock& block, CValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW, bool fCheckMerkleRoot, int nHeight, bool isVerifyDB) {
    // CheckBlock not only checks the block, but also fills up lelantusTxInfo and sigmaTxInfo.
    if (!block.sigmaTxInfo)
        block.sigmaTxInfo = std::make_shared<sigma::CSigmaTxInfo>();
    if (!block.lelantusTxInfo)
        block.lelantusTxInfo = std::make_shared<lelantus::CLelantusTxInfo>();

    LogPrintf("CheckBlock() nHeight=%s, blockHash= %s, isVerifyDB = %s\n", nHeight, block.GetHash().ToString(), isVerifyDB);

    // These are checks that are independent of context.

    if (block.fChecked)
        return true;

    // Check that the header is valid (particularly PoW).  This is mostly
    // redundant with the call in AcceptBlockHeader.
    if (!CheckBlockHeader(block, state, consensusParams, fCheckPOW)) {
        LogPrintf("CheckBlock - CheckBlockHeader -> failed!\n");
        return false;
    }

    // Check the merkle root.
    if (fCheckMerkleRoot) {
        bool mutated;
        uint256 hashMerkleRoot2 = BlockMerkleRoot(block, &mutated);
        if (block.hashMerkleRoot != hashMerkleRoot2)
            return state.DoS(100, false, REJECT_INVALID, "bad-txnmrklroot", true, "hashMerkleRoot mismatch");

        // Check for merkle tree malleability (CVE-2012-2459): repeating sequences
        // of transactions in a block without affecting the merkle root of a block,
        // while still invalidating it.
        if (mutated)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-duplicate", true, "duplicate transaction");

        // Firo - MTP
        if (block.IsMTP() && !CheckMerkleTreeProof(block, consensusParams))
            return state.DoS(100, false, REJECT_INVALID, "bad-diffbits", false, "incorrect proof of work");
    }

    // All potential-corruption validation must be done before we do any
    // transaction validation, as otherwise we may mark the header as invalid
    // because we receive the wrong transactions for it.
    // Note that witness malleability is checked in ContextualCheckBlock, so no
    // checks that use witness data may be performed here.
    // Size limits
    if (block.vtx.empty() || block.vtx.size() > MAX_BLOCK_BASE_SIZE || ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION) > MAX_BLOCK_BASE_SIZE)
        return state.DoS(100, false, REJECT_INVALID, "bad-blk-length", false, "size limits failed");

    // First transaction must be coinbase, the rest must not be
    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase())
        return state.DoS(100, false, REJECT_INVALID, "bad-cb-missing", false, "first tx is not coinbase");
    for (unsigned int i = 1; i < block.vtx.size(); i++)
        if (block.vtx[i]->IsCoinBase())
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-multiple", false, "more than one coinbase");

    // Check transactions
    if (nHeight == INT_MAX)
        nHeight = GetNHeight(block.GetBlockHeader());

    for (CTransactionRef tx : block.vtx) {
        if (nHeight >= consensusParams.nStartSigmaBlacklist && nHeight < consensusParams.nRestartSigmaWithBlacklistCheck && (tx->IsSigmaMint() || tx->IsSigmaSpend())) {
            return state.DoS(100, error("Sigma is temporarily disabled"), REJECT_INVALID, "bad-txns-zerocoin");
        }
        // We don't check transactions against sigma/lelantus state here, we'll check it again later in ConnectBlock
        if (!CheckTransaction(*tx, state, false, tx->GetHash(), isVerifyDB, nHeight, false, false, NULL, NULL))
            return state.Invalid(false, state.GetRejectCode(), state.GetRejectReason(),
                                strprintf("Transaction check failed (tx hash %s) %s", tx->GetHash().ToString(), state.GetDebugMessage()));

    }
    unsigned int nSigOps = 0;
    for (const auto& tx : block.vtx)
    {
        nSigOps += GetLegacySigOpCount(*tx);
    }
    if (nSigOps * WITNESS_SCALE_FACTOR > MAX_BLOCK_SIGOPS_COST)
        return state.DoS(100, false, REJECT_INVALID, "bad-blk-sigops", false, "out-of-bounds SigOpCount");

    if (fCheckPOW && fCheckMerkleRoot)
        block.fChecked = true;

    if (!sigma::CheckSigmaBlock(state, block))
        return false;

    if (!lelantus::CheckLelantusBlock(state, block))
        return false;

    return true;
}

static bool CheckIndexAgainstCheckpoint(const CBlockIndex* pindexPrev, CValidationState& state, const CChainParams& chainparams, const uint256& hash)
{
    if (*pindexPrev->phashBlock == chainparams.GetConsensus().hashGenesisBlock)
        return true;

    int nHeight = pindexPrev->nHeight+1;
    // Don't accept any forks from the main chain prior to last checkpoint
    CBlockIndex* pcheckpoint = Checkpoints::GetLastCheckpoint(chainparams.Checkpoints());
    if (pcheckpoint && nHeight < pcheckpoint->nHeight)
        return state.DoS(100, error("%s: forked chain older than last checkpoint (height %d)", __func__, nHeight));

    return true;
}

bool IsWitnessEnabled(const CBlockIndex* pindexPrev, const Consensus::Params& params)
{
    // TODO: enable witness at some point of time
    return false;

    /*
    LOCK(cs_main);
    return (VersionBitsState(pindexPrev, params, Consensus::DEPLOYMENT_SEGWIT, versionbitscache) == THRESHOLD_ACTIVE);
    */
}

// Compute at which vout of the block's coinbase transaction the witness
// commitment occurs, or -1 if not found.
static int GetWitnessCommitmentIndex(const CBlock& block)
{
    int commitpos = -1;
    if (!block.vtx.empty()) {
        for (size_t o = 0; o < block.vtx[0]->vout.size(); o++) {
            if (block.vtx[0]->vout[o].scriptPubKey.size() >= 38 && block.vtx[0]->vout[o].scriptPubKey[0] == OP_RETURN && block.vtx[0]->vout[o].scriptPubKey[1] == 0x24 && block.vtx[0]->vout[o].scriptPubKey[2] == 0xaa && block.vtx[0]->vout[o].scriptPubKey[3] == 0x21 && block.vtx[0]->vout[o].scriptPubKey[4] == 0xa9 && block.vtx[0]->vout[o].scriptPubKey[5] == 0xed) {
                commitpos = o;
            }
        }
    }
    return commitpos;
}

void UpdateUncommittedBlockStructures(CBlock& block, const CBlockIndex* pindexPrev, const Consensus::Params& consensusParams)
{
    int commitpos = GetWitnessCommitmentIndex(block);
    static const std::vector<unsigned char> nonce(32, 0x00);
    if (commitpos != -1 && IsWitnessEnabled(pindexPrev, consensusParams) && !block.vtx[0]->HasWitness()) {
        CMutableTransaction tx(*block.vtx[0]);
        tx.vin[0].scriptWitness.stack.resize(1);
        tx.vin[0].scriptWitness.stack[0] = nonce;
        block.vtx[0] = MakeTransactionRef(std::move(tx));
    }
}

std::vector<unsigned char> GenerateCoinbaseCommitment(CBlock& block, const CBlockIndex* pindexPrev, const Consensus::Params& consensusParams)
{
    std::vector<unsigned char> commitment;
    int commitpos = GetWitnessCommitmentIndex(block);
    std::vector<unsigned char> ret(32, 0x00);
    if (consensusParams.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout != 0) {
        if (commitpos == -1) {
            uint256 witnessroot = BlockWitnessMerkleRoot(block, NULL);
            CHash256().Write(witnessroot.begin(), 32).Write(&ret[0], 32).Finalize(witnessroot.begin());
            CTxOut out;
            out.nValue = 0;
            out.scriptPubKey.resize(38);
            out.scriptPubKey[0] = OP_RETURN;
            out.scriptPubKey[1] = 0x24;
            out.scriptPubKey[2] = 0xaa;
            out.scriptPubKey[3] = 0x21;
            out.scriptPubKey[4] = 0xa9;
            out.scriptPubKey[5] = 0xed;
            memcpy(&out.scriptPubKey[6], witnessroot.begin(), 32);
            commitment = std::vector<unsigned char>(out.scriptPubKey.begin(), out.scriptPubKey.end());
            CMutableTransaction tx(*block.vtx[0]);
            tx.vout.push_back(out);
            block.vtx[0] = MakeTransactionRef(std::move(tx));
        }
    }
    UpdateUncommittedBlockStructures(block, pindexPrev, consensusParams);
    return commitment;
}

bool ContextualCheckBlockHeader(const CBlockHeader& block, CValidationState& state, const Consensus::Params& consensusParams, CBlockIndex * const pindexPrev, int64_t nAdjustedTime)
{
	// Firo - MTP
    bool fBlockHasMTP = (block.nVersion & 4096) != 0 || (pindexPrev && consensusParams.nMTPSwitchTime == 0);

    if (block.IsMTP() != fBlockHasMTP)
		return state.Invalid(false, REJECT_OBSOLETE, strprintf("bad-version(0x%08x)", block.nVersion),strprintf("rejected nVersion=0x%08x block", block.nVersion));

	// Check proof of work
    if (block.nBits != GetNextWorkRequired(pindexPrev, &block, consensusParams))
        return state.DoS(100, false, REJECT_INVALID, "bad-diffbits", false, "incorrect proof of work");

    // Check timestamp against prev
    if (block.GetBlockTime() <= pindexPrev->GetMedianTimePast())
        return state.Invalid(false, REJECT_INVALID, "time-too-old", "block's timestamp is too early");

    // Check timestamp
    if (block.GetBlockTime() > nAdjustedTime + 2 * 60 * 60)
        return state.Invalid(false, REJECT_INVALID, "time-too-new", "block timestamp too far in the future");

    // Reject outdated version blocks when 95% (75% on testnet) of the network has upgraded:
    // check for version 2, 3 and 4 upgrades
    /*
    if((block.nVersion < 2 && nHeight >= consensusParams.BIP34Height) ||
       (block.nVersion < 3 && nHeight >= consensusParams.BIP66Height) ||
       (block.nVersion < 4 && nHeight >= consensusParams.BIP65Height))
            return state.Invalid(false, REJECT_OBSOLETE, strprintf("bad-version(0x%08x)", block.nVersion),
                                 strprintf("rejected nVersion=0x%08x block", block.nVersion));
    */

    return true;
}

bool IsBlockHashInChain(const uint256& hashBlock)
{
    if (hashBlock.IsNull() || !mapBlockIndex.count(hashBlock))
        return false;

    return chainActive.Contains(mapBlockIndex[hashBlock]);
}

bool IsTransactionInChain(const uint256& txId, int& nHeightTx, CTransactionRef & tx)
{
    uint256 hashBlock;
    if (!GetTransaction(txId, tx, Params().GetConsensus(), hashBlock, true))
        return false;
    if (!IsBlockHashInChain(hashBlock))
        return false;

    nHeightTx = mapBlockIndex.at(hashBlock)->nHeight;
    return true;
}

bool IsTransactionInChain(const uint256& txId, int& nHeightTx)
{
    CTransactionRef tx;
    return IsTransactionInChain(txId, nHeightTx, tx);
}

bool ContextualCheckBlock(const CBlock& block, CValidationState& state, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    const int nHeight = pindexPrev == NULL ? 0 : pindexPrev->nHeight + 1;

    // Start enforcing BIP113 (Median Time Past) using versionbits logic.
    int nLockTimeFlags = 0;
    if (VersionBitsState(pindexPrev, consensusParams, Consensus::DEPLOYMENT_CSV, versionbitscache) == THRESHOLD_ACTIVE) {
        nLockTimeFlags |= LOCKTIME_MEDIAN_TIME_PAST;
    }

    int64_t nLockTimeCutoff = (nLockTimeFlags & LOCKTIME_MEDIAN_TIME_PAST)
                              ? pindexPrev->GetMedianTimePast()
                              : block.GetBlockTime();

    bool fDIP0003Active_context = nHeight >= consensusParams.DIP0003Height;

    // Check that all transactions are finalized
    for (const auto& tx : block.vtx) {
        if (!IsFinalTx(*tx, nHeight, nLockTimeCutoff)) {
            return state.DoS(10, false, REJECT_INVALID, "bad-txns-nonfinal", false, "non-final transaction");
        }

        if (!ContextualCheckTransaction(*tx, state, consensusParams, pindexPrev)) {
            return false;
        }
    }

    if (nHeight >= consensusParams.nSubsidyHalvingFirst) {
        if (nHeight < consensusParams.nSubsidyHalvingFirst + consensusParams.nSubsidyHalvingInterval) {
            // "stage 2" interval between first and second halvings
            CScript devPayoutScript = GetScriptForDestination(CBitcoinAddress(consensusParams.stage2DevelopmentFundAddress).Get());
            CAmount devPayoutValue = (GetBlockSubsidy(nHeight, consensusParams, block.nTime) * consensusParams.stage2DevelopmentFundShare) / 100;
            bool found = false;
            for (const CTxOut &txout: block.vtx[0]->vout) {
                if ((found = txout.scriptPubKey == devPayoutScript && txout.nValue == devPayoutValue) == true)
                    break;
            }
            if (!found)
                return state.Invalid(false, state.GetRejectCode(), state.GetRejectReason(), "Stage 2 developer reward check failed");
        }
    }
    else if (!CheckZerocoinFoundersInputs(*block.vtx[0], state, consensusParams, nHeight, block.IsMTP())) {
        return state.Invalid(false, state.GetRejectCode(), state.GetRejectReason(), "Founders' reward check failed");
    }

    // Enforce rule that the coinbase starts with serialized block height
    /*
    if (nHeight >= consensusParams.BIP34Height)
    {
        CScript expect = CScript() << nHeight;
        if (block.vtx[0]->vin[0].scriptSig.size() < expect.size() ||
            !std::equal(expect.begin(), expect.end(), block.vtx[0]->vin[0].scriptSig.begin())) {
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-height", false, "block height mismatch in coinbase");
        }
    }
    */

    // Validation for witness commitments.
    // * We compute the witness hash (which is the hash including witnesses) of all the block's transactions, except the
    //   coinbase (where 0x0000....0000 is used instead).
    // * The coinbase scriptWitness is a stack of a single 32-byte vector, containing a witness nonce (unconstrained).
    // * We build a merkle tree with all those witness hashes as leaves (similar to the hashMerkleRoot in the block header).
    // * There must be at least one output whose scriptPubKey is a single 36-byte push, the first 4 bytes of which are
    //   {0xaa, 0x21, 0xa9, 0xed}, and the following 32 bytes are SHA256^2(witness root, witness nonce). In case there are
    //   multiple, the last one is used.
    bool fHaveWitness = false;
    if (VersionBitsState(pindexPrev, consensusParams, Consensus::DEPLOYMENT_SEGWIT, versionbitscache) == THRESHOLD_ACTIVE) {
        int commitpos = GetWitnessCommitmentIndex(block);
        if (commitpos != -1) {
            bool malleated = false;
            uint256 hashWitness = BlockWitnessMerkleRoot(block, &malleated);
            // The malleation check is ignored; as the transaction tree itself
            // already does not permit it, it is impossible to trigger in the
            // witness tree.
            if (block.vtx[0]->vin[0].scriptWitness.stack.size() != 1 || block.vtx[0]->vin[0].scriptWitness.stack[0].size() != 32) {
                return state.DoS(100, false, REJECT_INVALID, "bad-witness-nonce-size", true, strprintf("%s : invalid witness nonce size", __func__));
            }
            CHash256().Write(hashWitness.begin(), 32).Write(&block.vtx[0]->vin[0].scriptWitness.stack[0][0], 32).Finalize(hashWitness.begin());
            if (memcmp(hashWitness.begin(), &block.vtx[0]->vout[commitpos].scriptPubKey[6], 32)) {
                return state.DoS(100, false, REJECT_INVALID, "bad-witness-merkle-match", true, strprintf("%s : witness merkle commitment mismatch", __func__));
            }
            fHaveWitness = true;
        }
    }

    // No witness data is allowed in blocks that don't commit to witness data, as this would otherwise leave room for spam
    if (!fHaveWitness) {
        for (size_t i = 0; i < block.vtx.size(); i++) {
            if (block.vtx[i]->HasWitness()) {
                return state.DoS(100, false, REJECT_INVALID, "unexpected-witness", true, strprintf("%s : unexpected witness data found", __func__));
            }
        }
    }

    // After the coinbase witness nonce and commitment are verified,
    // we can check if the block weight passes (before we've checked the
    // coinbase witness, it would be possible for the weight to be too
    // large by filling up the coinbase witness, which doesn't change
    // the block hash, so we couldn't mark the block as permanently
    // failed).
    if (GetBlockWeight(block) > MAX_BLOCK_WEIGHT) {
        return state.DoS(100, false, REJECT_INVALID, "bad-blk-weight", false, strprintf("%s : weight limit failed", __func__));
    }

    if (fDIP0003Active_context) {
        if (block.vtx[0]->nType != TRANSACTION_COINBASE) {
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-type", false, "coinbase is not a CbTx");
        }
    }

    return true;
}

static bool AcceptBlockHeader(const CBlockHeader& block, CValidationState& state, const CChainParams& chainparams, CBlockIndex** ppindex, bool fCheckPOW = true)
{
    AssertLockHeld(cs_main);
    // Check for duplicate
    uint256 hash = block.GetHash();
    BlockMap::iterator miSelf = mapBlockIndex.find(hash);
    CBlockIndex *pindex = NULL;
    if (hash != chainparams.GetConsensus().hashGenesisBlock) {

        if (miSelf != mapBlockIndex.end()) {
            // Block header is already known.
            pindex = miSelf->second;
            if (ppindex)
                *ppindex = pindex;
            if (pindex->nStatus & BLOCK_FAILED_MASK)
                return state.Invalid(error("%s: block %s is marked invalid", __func__, hash.ToString()), 0, "duplicate");
            return true;
        }

        if (!CheckBlockHeader(block, state, chainparams.GetConsensus(), fCheckPOW))
            return error("%s: Consensus::CheckBlockHeader: %s, %s", __func__, hash.ToString(), FormatStateMessage(state));

        // Get prev block index
        CBlockIndex* pindexPrev = NULL;
        BlockMap::iterator mi = mapBlockIndex.find(block.hashPrevBlock);
        if (mi == mapBlockIndex.end())
            return state.DoS(10, error("%s: prev block not found", __func__), 0, "bad-prevblk");
        pindexPrev = (*mi).second;
        if (pindexPrev->nStatus & BLOCK_FAILED_MASK)
            return state.DoS(100, error("%s: prev block invalid", __func__), REJECT_INVALID, "bad-prevblk");

        assert(pindexPrev);
        if (fCheckpointsEnabled && !CheckIndexAgainstCheckpoint(pindexPrev, state, chainparams, hash))
            return error("%s: CheckIndexAgainstCheckpoint(): %s", __func__, state.GetRejectReason().c_str());

        if (!ContextualCheckBlockHeader(block, state, chainparams.GetConsensus(), pindexPrev, GetAdjustedTime()))
            return error("%s: Consensus::ContextualCheckBlockHeader: %s, %s", __func__, hash.ToString(), FormatStateMessage(state));
    }
    if (pindex == NULL)
        pindex = AddToBlockIndex(block);

    if (ppindex)
        *ppindex = pindex;

    CheckBlockIndex(chainparams.GetConsensus());

    // Notify external listeners about accepted block header
    GetMainSignals().AcceptedBlockHeader(pindex);

    return true;
}

// Exposed wrapper for AcceptBlockHeader
bool ProcessNewBlockHeaders(const std::vector<CBlockHeader>& headers, CValidationState& state, const CChainParams& chainparams, const CBlockIndex** ppindex)
{
    {
        LOCK(cs_main);
        for (const CBlockHeader& header : headers) {
            CBlockIndex *pindex = NULL; // Use a temp pindex instead of ppindex to avoid a const_cast
            if (!AcceptBlockHeader(header, state, chainparams, &pindex)) {
                return false;
            }
            if (ppindex) {
                *ppindex = pindex;
            }
        }
    }
    NotifyHeaderTip();
    return true;
}

/** Store block on disk. If dbp is non-NULL, the file is known to already reside on disk */
static bool AcceptBlock(const std::shared_ptr<const CBlock>& pblock, CValidationState& state, const CChainParams& chainparams, CBlockIndex** ppindex, bool fRequested, const CDiskBlockPos* dbp, bool* fNewBlock)
{
    const CBlock& block = *pblock;

    if (fNewBlock) *fNewBlock = false;
    AssertLockHeld(cs_main);

    CBlockIndex *pindexDummy = NULL;
    CBlockIndex *&pindex = ppindex ? *ppindex : pindexDummy;

    if (!AcceptBlockHeader(block, state, chainparams, &pindex))
        return false;

    LogPrintf("AcceptBlock nHeight=%s\n", pindex->nHeight);
    // Try to process all requested blocks that we don't have, but only
    // process an unrequested block if it's new and has enough work to
    // advance our tip, and isn't too many blocks ahead.
    bool fAlreadyHave = pindex->nStatus & BLOCK_HAVE_DATA;
    bool fHasMoreWork = (chainActive.Tip() ? pindex->nChainWork > chainActive.Tip()->nChainWork : true);
    // Blocks that are too out-of-order needlessly limit the effectiveness of
    // pruning, because pruning will not delete block files that contain any
    // blocks which are too close in height to the tip.  Apply this test
    // regardless of whether pruning is enabled; it should generally be safe to
    // not process unrequested blocks.
    bool fTooFarAhead = (pindex->nHeight > int(chainActive.Height() + MIN_BLOCKS_TO_KEEP));

    // TODO: Decouple this function from the block download logic by removing fRequested
    // This requires some new chain datastructure to efficiently look up if a
    // block is in a chain leading to a candidate for best tip, despite not
    // being such a candidate itself.

    // TODO: deal better with return value and error conditions for duplicate
    // and unrequested blocks.
    if (fAlreadyHave) return true;
    if (!fRequested) {  // If we didn't ask for it:
        if (pindex->nTx != 0) return true;  // This is a previously-processed block that was pruned
        if (!fHasMoreWork) return true;     // Don't process less-work chains
        if (fTooFarAhead) return true;      // Block height is too high
    }
    if (fNewBlock) *fNewBlock = true;

    if (!CheckBlock(block, state, chainparams.GetConsensus(), true, true, pindex->nHeight, false) ||
        !ContextualCheckBlock(block, state, chainparams.GetConsensus(), pindex->pprev)) {
        if (state.IsInvalid() && !state.CorruptionPossible()) {
            pindex->nStatus |= BLOCK_FAILED_VALID;
            setDirtyBlockIndex.insert(pindex);
        }
        return error("%s: %s", __func__, FormatStateMessage(state));
    }

    // Header is valid/has work, merkle tree and segwit merkle tree are good...RELAY NOW
    // (but if it does not build on our best tip, let the SendMessages loop relay it)
    if (!IsInitialBlockDownload() && chainActive.Tip() == pindex->pprev)
        GetMainSignals().NewPoWValidBlock(pindex, pblock);

    int nHeight = pindex->nHeight;

    // Write block to history file
    try {
        unsigned int nBlockSize = ::GetSerializeSize(block, SER_DISK, CLIENT_VERSION);
        CDiskBlockPos blockPos;
        if (dbp != NULL)
            blockPos = *dbp;
        if (!FindBlockPos(state, blockPos, nBlockSize+8, nHeight, block.GetBlockTime(), dbp != NULL))
            return error("AcceptBlock(): FindBlockPos failed");
        if (dbp == NULL)
            if (!WriteBlockToDisk(block, blockPos, chainparams.MessageStart()))
                AbortNode(state, "Failed to write block");
        if (!ReceivedBlockTransactions(block, state, pindex, blockPos))
            return error("AcceptBlock(): ReceivedBlockTransactions failed");
    } catch (const std::runtime_error& e) {
        return AbortNode(state, std::string("System error: ") + e.what());
    }

    if (fCheckForPruning)
        FlushStateToDisk(state, FLUSH_STATE_NONE); // we just allocated more disk space for block files

    return true;
}

bool ProcessNewBlock(const CChainParams& chainparams, const std::shared_ptr<const CBlock> pblock, bool fForceProcessing, bool *fNewBlock)
{
    CBlockIndex *pindex = NULL;
    {
        if (fNewBlock) *fNewBlock = false;
        CValidationState state;

        // TODO: refactor code so CheckTransaction and CheckBlock don't need cs_main
        LOCK(cs_main);

        // Ensure that CheckBlock() passes before calling AcceptBlock, as
        // belt-and-suspenders.
        bool ret = CheckBlock(*pblock, state, chainparams.GetConsensus());

        if (ret) {
            // Store to disk
            ret = AcceptBlock(pblock, state, chainparams, &pindex, fForceProcessing, NULL, fNewBlock);
        }
        CheckBlockIndex(chainparams.GetConsensus());
        if (!ret) {
            GetMainSignals().BlockChecked(*pblock, state);
            return error("%s: AcceptBlock FAILED", __func__);
        }
    }

    NotifyHeaderTip();

    CValidationState state; // Only used to report errors, not invalidity - ignore it
    if (!ActivateBestChain(state, chainparams, pblock))
        return error("%s: ActivateBestChain failed", __func__);

    return true;
}

bool TestBlockValidity(CValidationState& state, const CChainParams& chainparams, const CBlock& block, CBlockIndex* pindexPrev, bool fCheckPOW, bool fCheckMerkleRoot)
{
    AssertLockHeld(cs_main);
    assert(pindexPrev && pindexPrev == chainActive.Tip());
    if (fCheckpointsEnabled && !CheckIndexAgainstCheckpoint(pindexPrev, state, chainparams, block.GetHash()))
        return error("%s: CheckIndexAgainstCheckpoint(): %s", __func__, state.GetRejectReason().c_str());

    CCoinsViewCache viewNew(pcoinsTip);
    CBlockIndex indexDummy(block);
    indexDummy.pprev = pindexPrev;
    indexDummy.nHeight = pindexPrev->nHeight + 1;

    // begin tx and let it rollback
    auto dbTx = evoDb->BeginTransaction();

    // NOTE: CheckBlockHeader is called by CheckBlock
    if (!ContextualCheckBlockHeader(block, state, chainparams.GetConsensus(), pindexPrev, GetAdjustedTime()))
        return error("%s: Consensus::ContextualCheckBlockHeader: %s", __func__, FormatStateMessage(state));
    if (!CheckBlock(block, state, chainparams.GetConsensus(), fCheckPOW, fCheckMerkleRoot, indexDummy.nHeight, false))
        return error("%s: Consensus::CheckBlock: %s", __func__, FormatStateMessage(state));
    if (!ContextualCheckBlock(block, state, chainparams.GetConsensus(), pindexPrev))
        return error("%s: Consensus::ContextualCheckBlock: %s", __func__, FormatStateMessage(state));
    if (!ConnectBlock(block, state, &indexDummy, viewNew, chainparams, true))
        return false;
    assert(state.IsValid());

    return true;
}

/**
 * BLOCK PRUNING CODE
 */

/* Calculate the amount of disk space the block & undo files currently use */
uint64_t CalculateCurrentUsage()
{
    uint64_t retval = 0;
    BOOST_FOREACH(const CBlockFileInfo &file, vinfoBlockFile) {
        retval += file.nSize + file.nUndoSize;
    }
    return retval;
}

/* Prune a block file (modify associated database entries)*/
void PruneOneBlockFile(const int fileNumber)
{
    for (BlockMap::iterator it = mapBlockIndex.begin(); it != mapBlockIndex.end(); ++it) {
        CBlockIndex* pindex = it->second;
        if (pindex->nFile == fileNumber) {
            pindex->nStatus &= ~BLOCK_HAVE_DATA;
            pindex->nStatus &= ~BLOCK_HAVE_UNDO;
            pindex->nFile = 0;
            pindex->nDataPos = 0;
            pindex->nUndoPos = 0;
            setDirtyBlockIndex.insert(pindex);

            // Prune from mapBlocksUnlinked -- any block we prune would have
            // to be downloaded again in order to consider its chain, at which
            // point it would be considered as a candidate for
            // mapBlocksUnlinked or setBlockIndexCandidates.
            std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, std::multimap<CBlockIndex*, CBlockIndex*>::iterator> range = mapBlocksUnlinked.equal_range(pindex->pprev);
            while (range.first != range.second) {
                std::multimap<CBlockIndex *, CBlockIndex *>::iterator _it = range.first;
                range.first++;
                if (_it->second == pindex) {
                    mapBlocksUnlinked.erase(_it);
                }
            }
        }
    }

    vinfoBlockFile[fileNumber].SetNull();
    setDirtyFileInfo.insert(fileNumber);
}


void UnlinkPrunedFiles(const std::set<int>& setFilesToPrune)
{
    for (std::set<int>::iterator it = setFilesToPrune.begin(); it != setFilesToPrune.end(); ++it) {
        CDiskBlockPos pos(*it, 0);
        boost::filesystem::remove(GetBlockPosFilename(pos, "blk"));
        boost::filesystem::remove(GetBlockPosFilename(pos, "rev"));
        LogPrintf("Prune: %s deleted blk/rev (%05u)\n", __func__, *it);
    }
}

/* Calculate the block/rev files to delete based on height specified by user with RPC command pruneblockchain */
void FindFilesToPruneManual(std::set<int>& setFilesToPrune, int nManualPruneHeight)
{
    assert(fPruneMode && nManualPruneHeight > 0);

    LOCK2(cs_main, cs_LastBlockFile);
    if (chainActive.Tip() == NULL)
        return;

    // last block to prune is the lesser of (user-specified height, MIN_BLOCKS_TO_KEEP from the tip)
    unsigned int nLastBlockWeCanPrune = std::min((unsigned)nManualPruneHeight, chainActive.Tip()->nHeight - MIN_BLOCKS_TO_KEEP);
    int count=0;
    for (int fileNumber = 0; fileNumber < nLastBlockFile; fileNumber++) {
        if (vinfoBlockFile[fileNumber].nSize == 0 || vinfoBlockFile[fileNumber].nHeightLast > nLastBlockWeCanPrune)
            continue;
        PruneOneBlockFile(fileNumber);
        setFilesToPrune.insert(fileNumber);
        count++;
    }
    LogPrintf("Prune (Manual): prune_height=%d removed %d blk/rev pairs\n", nLastBlockWeCanPrune, count);
}

/* This function is called from the RPC code for pruneblockchain */
void PruneBlockFilesManual(int nManualPruneHeight)
{
    CValidationState state;
    FlushStateToDisk(state, FLUSH_STATE_NONE, nManualPruneHeight);
}

/* Calculate the block/rev files that should be deleted to remain under target*/
void FindFilesToPrune(std::set<int>& setFilesToPrune, uint64_t nPruneAfterHeight)
{
    LOCK2(cs_main, cs_LastBlockFile);
    if (chainActive.Tip() == NULL || nPruneTarget == 0) {
        return;
    }
    if ((uint64_t)chainActive.Tip()->nHeight <= nPruneAfterHeight) {
        return;
    }

    unsigned int nLastBlockWeCanPrune = chainActive.Tip()->nHeight - MIN_BLOCKS_TO_KEEP;
    uint64_t nCurrentUsage = CalculateCurrentUsage();
    // We don't check to prune until after we've allocated new space for files
    // So we should leave a buffer under our target to account for another allocation
    // before the next pruning.
    uint64_t nBuffer = BLOCKFILE_CHUNK_SIZE + UNDOFILE_CHUNK_SIZE;
    uint64_t nBytesToPrune;
    int count=0;

    if (nCurrentUsage + nBuffer >= nPruneTarget) {
        for (int fileNumber = 0; fileNumber < nLastBlockFile; fileNumber++) {
            nBytesToPrune = vinfoBlockFile[fileNumber].nSize + vinfoBlockFile[fileNumber].nUndoSize;

            if (vinfoBlockFile[fileNumber].nSize == 0)
                continue;

            if (nCurrentUsage + nBuffer < nPruneTarget)  // are we below our target?
                break;

            // don't prune files that could have a block within MIN_BLOCKS_TO_KEEP of the main chain's tip but keep scanning
            if (vinfoBlockFile[fileNumber].nHeightLast > nLastBlockWeCanPrune)
                continue;

            PruneOneBlockFile(fileNumber);
            // Queue up the files for removal
            setFilesToPrune.insert(fileNumber);
            nCurrentUsage -= nBytesToPrune;
            count++;
        }
    }

    LogPrint("prune", "Prune: target=%dMiB actual=%dMiB diff=%dMiB max_prune_height=%d removed %d blk/rev pairs\n",
           nPruneTarget/1024/1024, nCurrentUsage/1024/1024,
           ((int64_t)nPruneTarget - (int64_t)nCurrentUsage)/1024/1024,
           nLastBlockWeCanPrune, count);
}

bool CheckDiskSpace(uint64_t nAdditionalBytes)
{
    uint64_t nFreeBytesAvailable = boost::filesystem::space(GetDataDir()).available;

    // Check for nMinDiskSpace bytes (currently 50MB)
    if (nFreeBytesAvailable < nMinDiskSpace + nAdditionalBytes)
        return AbortNode("Disk space is low!", _("Error: Disk space is low!"));

    return true;
}

FILE* OpenDiskFile(const CDiskBlockPos &pos, const char *prefix, bool fReadOnly)
{
    if (pos.IsNull())
        return NULL;
    boost::filesystem::path path = GetBlockPosFilename(pos, prefix);
    boost::filesystem::create_directories(path.parent_path());
    FILE* file = fopen(path.string().c_str(), "rb+");
    if (!file && !fReadOnly)
        file = fopen(path.string().c_str(), "wb+");
    if (!file) {
        LogPrintf("Unable to open file %s\n", path.string());
        return NULL;
    }
    if (pos.nPos) {
        if (fseek(file, pos.nPos, SEEK_SET)) {
            LogPrintf("Unable to seek to position %u of %s\n", pos.nPos, path.string());
            fclose(file);
            return NULL;
        }
    }
    return file;
}

FILE* OpenBlockFile(const CDiskBlockPos &pos, bool fReadOnly) {
    return OpenDiskFile(pos, "blk", fReadOnly);
}

FILE* OpenUndoFile(const CDiskBlockPos &pos, bool fReadOnly) {
    return OpenDiskFile(pos, "rev", fReadOnly);
}

boost::filesystem::path GetBlockPosFilename(const CDiskBlockPos &pos, const char *prefix)
{
    return GetDataDir() / "blocks" / strprintf("%s%05u.dat", prefix, pos.nFile);
}

CBlockIndex * InsertBlockIndex(uint256 hash)
{
    if (hash.IsNull())
        return NULL;

    // Return existing
    BlockMap::iterator mi = mapBlockIndex.find(hash);
    if (mi != mapBlockIndex.end())
        return (*mi).second;

    // Create new
    CBlockIndex* pindexNew = new CBlockIndex();
    if (!pindexNew)
        throw std::runtime_error(std::string(__func__) + ": new CBlockIndex failed");
    mi = mapBlockIndex.insert(std::make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);

    return pindexNew;
}

bool static LoadBlockIndexDB(const CChainParams& chainparams)
{
    LogPrintf("LoadBlockIndexDB\n");
    if (!pblocktree->LoadBlockIndexGuts(InsertBlockIndex))
        return false;

    boost::this_thread::interruption_point();

    // Calculate nChainWork
    std::vector<std::pair<int, CBlockIndex*> > vSortedByHeight;
    vSortedByHeight.reserve(mapBlockIndex.size());
    BOOST_FOREACH(const PAIRTYPE(uint256, CBlockIndex*)& item, mapBlockIndex)
    {
        CBlockIndex* pindex = item.second;
        vSortedByHeight.push_back(std::make_pair(pindex->nHeight, pindex));

        // build mapPrevBlockIndex
        if (pindex->pprev) {
            mapPrevBlockIndex.emplace(pindex->pprev->GetBlockHash(), pindex);
        }
    }
    sort(vSortedByHeight.begin(), vSortedByHeight.end());
    BOOST_FOREACH(const PAIRTYPE(int, CBlockIndex*)& item, vSortedByHeight)
    {
        CBlockIndex* pindex = item.second;
        pindex->nChainWork = (pindex->pprev ? pindex->pprev->nChainWork : 0) + GetBlockProof(*pindex);
        pindex->nTimeMax = (pindex->pprev ? std::max(pindex->pprev->nTimeMax, pindex->nTime) : pindex->nTime);
        // We can link the chain of blocks for which we've received transactions at some point.
        // Pruned nodes may have deleted the block.
        if (pindex->nTx > 0) {
            if (pindex->pprev) {
                if (pindex->pprev->nChainTx) {
                    pindex->nChainTx = pindex->pprev->nChainTx + pindex->nTx;
                } else {
                    pindex->nChainTx = 0;
                    mapBlocksUnlinked.insert(std::make_pair(pindex->pprev, pindex));
                }
            } else {
                pindex->nChainTx = pindex->nTx;
            }
        }
        if (pindex->IsValid(BLOCK_VALID_TRANSACTIONS) && (pindex->nChainTx || pindex->pprev == NULL))
            setBlockIndexCandidates.insert(pindex);
        if (pindex->nStatus & BLOCK_FAILED_MASK && (!pindexBestInvalid || pindex->nChainWork > pindexBestInvalid->nChainWork))
            pindexBestInvalid = pindex;
        if (pindex->pprev)
            pindex->BuildSkip();
        if (pindex->IsValid(BLOCK_VALID_TREE) && (pindexBestHeader == NULL || CBlockIndexWorkComparator()(pindexBestHeader, pindex)))
            pindexBestHeader = pindex;
    }

    // Load block file info
    pblocktree->ReadLastBlockFile(nLastBlockFile);
    vinfoBlockFile.resize(nLastBlockFile + 1);
    LogPrintf("%s: last block file = %i\n", __func__, nLastBlockFile);
    for (int nFile = 0; nFile <= nLastBlockFile; nFile++) {
        pblocktree->ReadBlockFileInfo(nFile, vinfoBlockFile[nFile]);
    }
    LogPrintf("%s: last block file info: %s\n", __func__, vinfoBlockFile[nLastBlockFile].ToString());
    for (int nFile = nLastBlockFile + 1; true; nFile++) {
        CBlockFileInfo info;
        if (pblocktree->ReadBlockFileInfo(nFile, info)) {
            vinfoBlockFile.push_back(info);
        } else {
            break;
        }
    }

    // Check presence of blk files
    LogPrintf("Checking all blk files are present...\n");
    std::set<int> setBlkDataFiles;
    BOOST_FOREACH(const PAIRTYPE(uint256, CBlockIndex*)& item, mapBlockIndex)
    {
        CBlockIndex* pindex = item.second;
        if (pindex->nStatus & BLOCK_HAVE_DATA) {
            setBlkDataFiles.insert(pindex->nFile);
        }
    }
    for (std::set<int>::iterator it = setBlkDataFiles.begin(); it != setBlkDataFiles.end(); it++)
    {
        CDiskBlockPos pos(*it, 0);
        if (CAutoFile(OpenBlockFile(pos, true), SER_DISK, CLIENT_VERSION).IsNull()) {
            return false;
        }
    }

    // Check whether we have ever pruned block & undo files
    pblocktree->ReadFlag("prunedblockfiles", fHavePruned);
    if (fHavePruned)
        LogPrintf("LoadBlockIndexDB(): Block files have previously been pruned\n");

    // Check whether we need to continue reindexing
    bool fReindexing = false;
    pblocktree->ReadReindexing(fReindexing);
    fReindex |= fReindexing;

    // Check whether we have a transaction index
    pblocktree->ReadFlag("txindex", fTxIndex);
    LogPrintf("%s: transaction index %s\n", __func__, fTxIndex ? "enabled" : "disabled");

    // Check whether we have an address index
    pblocktree->ReadFlag("addressindex", fAddressIndex);
    LogPrintf("%s: address index %s\n", __func__, fAddressIndex ? "enabled" : "disabled");

    // Check whether we have a timestamp index
    pblocktree->ReadFlag("timestampindex", fTimestampIndex);
    LogPrintf("%s: timestamp index %s\n", __func__, fTimestampIndex ? "enabled" : "disabled");

    // Check whether we have a spent index
    pblocktree->ReadFlag("spentindex", fSpentIndex);
    LogPrintf("%s: spent index %s\n", __func__, fSpentIndex ? "enabled" : "disabled");


    // Load pointer to end of best chain
    BlockMap::iterator it = mapBlockIndex.find(pcoinsTip->GetBestBlock());
    if (it == mapBlockIndex.end())
        return true;
    chainActive.SetTip(it->second);

    PruneBlockIndexCandidates();

    sigma::BuildSigmaStateFromIndex(&chainActive);
    lelantus::BuildLelantusStateFromIndex(&chainActive);

    // Initialize MTP state
    MTPState::GetMTPState()->InitializeFromChain(&chainActive, chainparams.GetConsensus());

    LogPrintf("%s: hashBestChain=%s height=%d date=%s progress=%f\n", __func__,
        chainActive.Tip()->GetBlockHash().ToString(), chainActive.Height(),
        DateTimeStrFormat("%Y-%m-%d %H:%M:%S", chainActive.Tip()->GetBlockTime()),
        GuessVerificationProgress(chainparams.TxData(), chainActive.Tip()));

    return true;
}

CVerifyDB::CVerifyDB()
{
    uiInterface.ShowProgress(_("Verifying blocks..."), 0);
}

CVerifyDB::~CVerifyDB()
{
    uiInterface.ShowProgress("", 100);
}

bool CVerifyDB::VerifyDB(const CChainParams& chainparams, CCoinsView *coinsview, int nCheckLevel, int nCheckDepth)
{
    LOCK(cs_main);
    if (chainActive.Tip() == NULL || chainActive.Tip()->pprev == NULL)
        return true;

    // begin tx and let it rollback
    auto dbTx = evoDb->BeginTransaction();

    // Verify blocks in the best chain
    if (nCheckDepth <= 0)
        nCheckDepth = 1000000000; // suffices until the year 19000
    if (nCheckDepth > chainActive.Height())
        nCheckDepth = chainActive.Height();
    nCheckLevel = std::max(0, std::min(4, nCheckLevel));
    LogPrintf("Verifying last %i blocks at level %i\n", nCheckDepth, nCheckLevel);
    CCoinsViewCache coins(coinsview);
    CBlockIndex* pindexState = chainActive.Tip();
    CBlockIndex* pindexFailure = NULL;
    int nGoodTransactions = 0;
    CValidationState state;
    int reportDone = 0;
    LogPrintf("[0%%]...");
    for (CBlockIndex* pindex = chainActive.Tip(); pindex && pindex->pprev; pindex = pindex->pprev)
    {
        boost::this_thread::interruption_point();
        int percentageDone = std::max(1, std::min(99, (int)(((double)(chainActive.Height() - pindex->nHeight)) / (double)nCheckDepth * (nCheckLevel >= 4 ? 50 : 100))));
        if (reportDone < percentageDone/10) {
            // report every 10% step
            LogPrintf("[%d%%]...", percentageDone);
            reportDone = percentageDone/10;
        }
        uiInterface.ShowProgress(_("Verifying blocks..."), percentageDone);
        if (pindex->nHeight < chainActive.Height()-nCheckDepth)
            break;
        if (fPruneMode && !(pindex->nStatus & BLOCK_HAVE_DATA)) {
            // If pruning, only go back as far as we have data.
            LogPrintf("VerifyDB(): block verification stopping at height %d (pruning, no data)\n", pindex->nHeight);
            break;
        }
        CBlock block;
        // check level 0: read from disk
        if (!ReadBlockFromDisk(block, pindex, chainparams.GetConsensus()))
            return error("VerifyDB(): *** ReadBlockFromDisk failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
        LogPrintf("VerifyDB->CheckBlock() nHeight=%s\n", pindex->nHeight);
        // check level 1: verify block validity
        if (nCheckLevel >= 1 && !CheckBlock(block, state, chainparams.GetConsensus(), true, true, pindex->nHeight, true))
            return error("%s: *** found bad block at %d, hash=%s (%s)\n", __func__,
                         pindex->nHeight, pindex->GetBlockHash().ToString(), FormatStateMessage(state));
        // check level 2: verify undo validity
        if (nCheckLevel >= 2 && pindex) {
            CBlockUndo undo;
            CDiskBlockPos pos = pindex->GetUndoPos();
            if (!pos.IsNull()) {
                if (!UndoReadFromDisk(undo, pos, pindex->pprev->GetBlockHash()))
                    return error("VerifyDB(): *** found bad undo data at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
            }
        }
        // check level 3: check for inconsistencies during memory-only disconnect of tip blocks
        if (nCheckLevel >= 3 && pindex == pindexState && (coins.DynamicMemoryUsage() + pcoinsTip->DynamicMemoryUsage()) <= nCoinCacheUsage) {
            DisconnectResult res = DisconnectBlock(block, state, pindex, coins);
            if (res == DISCONNECT_FAILED) {
                return error("VerifyDB(): *** irrecoverable inconsistency in block data at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
            }
            pindexState = pindex->pprev;
            if (res == DISCONNECT_UNCLEAN) {
                nGoodTransactions = 0;
                pindexFailure = pindex;
            } else {
                nGoodTransactions += block.vtx.size();
            }
        }
        if (ShutdownRequested())
            return true;
    }
    if (pindexFailure)
        return error("VerifyDB(): *** coin database inconsistencies found (last %i blocks, %i good transactions before that)\n", chainActive.Height() - pindexFailure->nHeight + 1, nGoodTransactions);

    // check level 4: try reconnecting blocks
    if (nCheckLevel >= 4) {
        CBlockIndex *pindex = pindexState;
        while (pindex != chainActive.Tip()) {
            boost::this_thread::interruption_point();
            uiInterface.ShowProgress(_("Verifying blocks..."), std::max(1, std::min(99, 100 - (int)(((double)(chainActive.Height() - pindex->nHeight)) / (double)nCheckDepth * 50))));
            pindex = chainActive.Next(pindex);
            CBlock block;
            if (!ReadBlockFromDisk(block, pindex, chainparams.GetConsensus()))
                return error("VerifyDB(): *** ReadBlockFromDisk failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
            if (!ConnectBlock(block, state, pindex, coins, chainparams))
                return error("VerifyDB(): *** found unconnectable block at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
        }
    }

    LogPrintf("[DONE].\n");
    LogPrintf("No coin database inconsistencies in last %i blocks (%i transactions)\n", chainActive.Height() - pindexState->nHeight, nGoodTransactions);

    return true;
}

bool RewindBlockIndex(const CChainParams& params)
{
    LOCK(cs_main);

    int nHeight = 1;
    while (nHeight <= chainActive.Height()) {
        if (IsWitnessEnabled(chainActive[nHeight - 1], params.GetConsensus()) && !(chainActive[nHeight]->nStatus & BLOCK_OPT_WITNESS)) {
            break;
        }
        nHeight++;
    }

    // nHeight is now the height of the first insufficiently-validated block, or tipheight + 1
    CValidationState state;
    CBlockIndex* pindex = chainActive.Tip();
    while (chainActive.Height() >= nHeight) {
        if (fPruneMode && !(chainActive.Tip()->nStatus & BLOCK_HAVE_DATA)) {
            // If pruning, don't try rewinding past the HAVE_DATA point;
            // since older blocks can't be served anyway, there's
            // no need to walk further, and trying to DisconnectTip()
            // will fail (and require a needless reindex/redownload
            // of the blockchain).
            break;
        }
        if (!DisconnectTip(state, params, true)) {
            return error("RewindBlockIndex: unable to disconnect block at height %i", pindex->nHeight);
        }
        // Occasionally flush state to disk.
        if (!FlushStateToDisk(state, FLUSH_STATE_PERIODIC))
            return false;
    }

    // Reduce validity flag and have-data flags.
    // We do this after actual disconnecting, otherwise we'll end up writing the lack of data
    // to disk before writing the chainstate, resulting in a failure to continue if interrupted.
    for (BlockMap::iterator it = mapBlockIndex.begin(); it != mapBlockIndex.end(); it++) {
        CBlockIndex* pindexIter = it->second;

        // Note: If we encounter an insufficiently validated block that
        // is on chainActive, it must be because we are a pruning node, and
        // this block or some successor doesn't HAVE_DATA, so we were unable to
        // rewind all the way.  Blocks remaining on chainActive at this point
        // must not have their validity reduced.
        if (IsWitnessEnabled(pindexIter->pprev, params.GetConsensus()) && !(pindexIter->nStatus & BLOCK_OPT_WITNESS) && !chainActive.Contains(pindexIter)) {
            // Reduce validity
            pindexIter->nStatus = std::min<unsigned int>(pindexIter->nStatus & BLOCK_VALID_MASK, BLOCK_VALID_TREE) | (pindexIter->nStatus & ~BLOCK_VALID_MASK);
            // Remove have-data flags.
            pindexIter->nStatus &= ~(BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO);
            // Remove storage location.
            pindexIter->nFile = 0;
            pindexIter->nDataPos = 0;
            pindexIter->nUndoPos = 0;
            // Remove various other things
            pindexIter->nTx = 0;
            pindexIter->nChainTx = 0;
            pindexIter->nSequenceId = 0;
            // Make sure it gets written.
            setDirtyBlockIndex.insert(pindexIter);
            // Update indexes
            setBlockIndexCandidates.erase(pindexIter);
            std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, std::multimap<CBlockIndex*, CBlockIndex*>::iterator> ret = mapBlocksUnlinked.equal_range(pindexIter->pprev);
            while (ret.first != ret.second) {
                if (ret.first->second == pindexIter) {
                    mapBlocksUnlinked.erase(ret.first++);
                } else {
                    ++ret.first;
                }
            }
        } else if (pindexIter->IsValid(BLOCK_VALID_TRANSACTIONS) && pindexIter->nChainTx) {
            setBlockIndexCandidates.insert(pindexIter);
        }
    }

    PruneBlockIndexCandidates();

    CheckBlockIndex(params.GetConsensus());

    if (!FlushStateToDisk(state, FLUSH_STATE_ALWAYS)) {
        return false;
    }

    return true;
}

// May NOT be used after any connections are up as much
// of the peer-processing logic assumes a consistent
// block index state
void UnloadBlockIndex()
{
    LOCK(cs_main);
    setBlockIndexCandidates.clear();
    chainActive.SetTip(NULL);
    pindexBestInvalid = NULL;
    pindexBestHeader = NULL;
    txpools.clear();
    mapBlocksUnlinked.clear();
    vinfoBlockFile.clear();
    nLastBlockFile = 0;
    nBlockSequenceId = 1;
    setDirtyBlockIndex.clear();
    setDirtyFileInfo.clear();
    versionbitscache.Clear();
    for (int b = 0; b < VERSIONBITS_NUM_BITS; b++) {
        warningcache[b].clear();
    }

    BOOST_FOREACH(BlockMap::value_type& entry, mapBlockIndex) {
        delete entry.second;
    }
    mapBlockIndex.clear();
    fHavePruned = false;
}

bool LoadBlockIndex(const CChainParams& chainparams)
{
    // Load block index from databases
    if (!fReindex && !LoadBlockIndexDB(chainparams))
        return false;
    return true;
}

bool InitBlockIndex(const CChainParams& chainparams)
{
    LOCK(cs_main);

    // Check whether we're already initialized
    if (chainActive.Genesis() != NULL)
        return true;

    // Use the provided setting for -txindex in the new database
    fTxIndex = GetBoolArg("-txindex", DEFAULT_TXINDEX);
    pblocktree->WriteFlag("txindex", fTxIndex);

    // Use the provided setting for -timestampindex in the new database
    fTimestampIndex = GetBoolArg("-timestampindex", DEFAULT_TIMESTAMPINDEX);
    pblocktree->WriteFlag("timestampindex", fTimestampIndex);

    // Use the provided setting for -addressindex in the new database
    fAddressIndex = GetBoolArg("-addressindex", DEFAULT_ADDRESSINDEX);
    pblocktree->WriteFlag("addressindex", fAddressIndex);

    fSpentIndex = GetBoolArg("-spentindex", DEFAULT_SPENTINDEX);
    pblocktree->WriteFlag("spentindex", fSpentIndex);

    LogPrintf("Initializing databases...\n");

    // Only add the genesis block if not reindexing (in which case we reuse the one already on disk)
    if (!fReindex) {
        try {
            CBlock &block = const_cast<CBlock&>(chainparams.GenesisBlock());
            // Start new block file
            unsigned int nBlockSize = ::GetSerializeSize(block, SER_DISK, CLIENT_VERSION);
            CDiskBlockPos blockPos;
            CValidationState state;
            if (!FindBlockPos(state, blockPos, nBlockSize+8, 0, block.GetBlockTime()))
                return error("LoadBlockIndex(): FindBlockPos failed");
            if (!WriteBlockToDisk(block, blockPos, chainparams.MessageStart()))
                return error("LoadBlockIndex(): writing genesis block to disk failed");
            CBlockIndex *pindex = AddToBlockIndex(block);
            if (!ReceivedBlockTransactions(block, state, pindex, blockPos))
                return error("LoadBlockIndex(): genesis block not accepted");
            // Force a chainstate write so that when we VerifyDB in a moment, it doesn't check stale data
            return FlushStateToDisk(state, FLUSH_STATE_ALWAYS);
        } catch (const std::runtime_error& e) {
            return error("LoadBlockIndex(): failed to initialize block database: %s", e.what());
        }
    }

    return true;
}

bool LoadExternalBlockFile(const CChainParams& chainparams, FILE* fileIn, CDiskBlockPos *dbp)
{
    // Map of disk positions for blocks with unknown parent (only used for reindex)
    static std::multimap<uint256, CDiskBlockPos> mapBlocksUnknownParent;
    int64_t nStart = GetTimeMillis();

    int nLoaded = 0;
    try {
        // This takes over fileIn and calls fclose() on it in the CBufferedFile destructor
        CBufferedFile blkdat(fileIn, 2*MAX_BLOCK_SERIALIZED_SIZE, MAX_BLOCK_SERIALIZED_SIZE+8, SER_DISK, CLIENT_VERSION);
        uint64_t nRewind = blkdat.GetPos();
        while (!blkdat.eof()) {
            boost::this_thread::interruption_point();

            blkdat.SetPos(nRewind);
            nRewind++; // start one byte further next time, in case of failure
            blkdat.SetLimit(); // remove former limit
            unsigned int nSize = 0;
            try {
                // locate a header
                unsigned char buf[CMessageHeader::MESSAGE_START_SIZE];
                blkdat.FindByte(chainparams.MessageStart()[0]);
                nRewind = blkdat.GetPos()+1;
                blkdat >> FLATDATA(buf);
                if (memcmp(buf, chainparams.MessageStart(), CMessageHeader::MESSAGE_START_SIZE))
                    continue;
                // read size
                blkdat >> nSize;
                if (nSize < 80 || nSize > MAX_BLOCK_SERIALIZED_SIZE)
                    continue;
            } catch (const std::exception&) {
                // no valid block header found; don't complain
                break;
            }
            try {
                // read block
                uint64_t nBlockPos = blkdat.GetPos();
                if (dbp)
                    dbp->nPos = nBlockPos;
                blkdat.SetLimit(nBlockPos + nSize);
                blkdat.SetPos(nBlockPos);
                std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
                CBlock& block = *pblock;
                blkdat >> block;
                nRewind = blkdat.GetPos();

                // detect out of order blocks, and store them for later
                uint256 hash = block.GetHash();
                if (hash != chainparams.GetConsensus().hashGenesisBlock && mapBlockIndex.find(block.hashPrevBlock) == mapBlockIndex.end()) {
                    LogPrint("reindex", "%s: Out of order block %s, parent %s not known\n", __func__, hash.ToString(),
                            block.hashPrevBlock.ToString());
                    if (dbp)
                        mapBlocksUnknownParent.insert(std::make_pair(block.hashPrevBlock, *dbp));
                    continue;
                }
                // process in case the block isn't known yet
                if (mapBlockIndex.count(hash) == 0 || (mapBlockIndex[hash]->nStatus & BLOCK_HAVE_DATA) == 0) {
                    LOCK(cs_main);
                    CValidationState state;
                    if (AcceptBlock(pblock, state, chainparams, NULL, true, dbp, NULL))
                        nLoaded++;
                    if (state.IsError())
                        break;
                } else if (hash != chainparams.GetConsensus().hashGenesisBlock && mapBlockIndex[hash]->nHeight % 1000 == 0) {
                    LogPrint("reindex", "Block Import: already had block %s at height %d\n", hash.ToString(), mapBlockIndex[hash]->nHeight);
                }

                // Activate the genesis block so normal node progress can continue
// We should call it for every block as our tx verification algos rely on the real block heights.
//                if (hash == chainparams.GetConsensus().hashGenesisBlock) {
                    CValidationState state;
                    if (!ActivateBestChain(state, chainparams)) {
                        break;
                    }

                NotifyHeaderTip();

                LOCK(cs_main);

                // Recursively process earlier encountered successors of this block
                std::deque<uint256> queue;
                queue.push_back(hash);
                while (!queue.empty()) {
                    uint256 head = queue.front();
                    queue.pop_front();
                    std::pair<std::multimap<uint256, CDiskBlockPos>::iterator, std::multimap<uint256, CDiskBlockPos>::iterator> range = mapBlocksUnknownParent.equal_range(head);
                    while (range.first != range.second) {
                        std::multimap<uint256, CDiskBlockPos>::iterator it = range.first;
                        int nHeight = mapBlockIndex[head]->nHeight+1;
                        std::shared_ptr<CBlock> pblockrecursive = std::make_shared<CBlock>();
                        if (ReadBlockFromDisk(*pblockrecursive, it->second, nHeight, chainparams.GetConsensus()))
                        {
                            LogPrint("reindex", "%s: Processing out of order child %s of %s\n", __func__, pblockrecursive->GetHash().ToString(),
                                    head.ToString());
                            CValidationState dummy;
                            if (AcceptBlock(pblockrecursive, dummy, chainparams, NULL, true, &it->second, NULL))
                            {
                                nLoaded++;
                                queue.push_back(pblockrecursive->GetHash());
                            }
                        }
                        range.first++;
                        mapBlocksUnknownParent.erase(it);
                        NotifyHeaderTip();
                    }
                }
            } catch (const std::exception& e) {
                LogPrintf("%s: Deserialize or I/O error - %s\n", __func__, e.what());
            }
        }
    } catch (const std::runtime_error& e) {
        AbortNode(std::string("System error: ") + e.what());
    }
    if (nLoaded > 0)
        LogPrintf("Loaded %i blocks from external file in %dms\n", nLoaded, GetTimeMillis() - nStart);
    return nLoaded > 0;
}

void static CheckBlockIndex(const Consensus::Params& consensusParams)
{
    if (!fCheckBlockIndex) {
        return;
    }

    LOCK(cs_main);

    // During a reindex, we read the genesis block and call CheckBlockIndex before ActivateBestChain,
    // so we have the genesis block in mapBlockIndex but no active chain.  (A few of the tests when
    // iterating the block tree require that chainActive has been initialized.)
    if (chainActive.Height() < 0) {
        assert(mapBlockIndex.size() <= 1);
        return;
    }

    // Build forward-pointing map of the entire block tree.
    std::multimap<CBlockIndex*,CBlockIndex*> forward;
    for (BlockMap::iterator it = mapBlockIndex.begin(); it != mapBlockIndex.end(); it++) {
        forward.insert(std::make_pair(it->second->pprev, it->second));
    }

    assert(forward.size() == mapBlockIndex.size());

    std::pair<std::multimap<CBlockIndex*,CBlockIndex*>::iterator,std::multimap<CBlockIndex*,CBlockIndex*>::iterator> rangeGenesis = forward.equal_range(NULL);
    CBlockIndex *pindex = rangeGenesis.first->second;
    rangeGenesis.first++;
    assert(rangeGenesis.first == rangeGenesis.second); // There is only one index entry with parent NULL.

    // Iterate over the entire block tree, using depth-first search.
    // Along the way, remember whether there are blocks on the path from genesis
    // block being explored which are the first to have certain properties.
    size_t nNodes = 0;
    int nHeight = 0;
    CBlockIndex* pindexFirstInvalid = NULL; // Oldest ancestor of pindex which is invalid.
    CBlockIndex* pindexFirstMissing = NULL; // Oldest ancestor of pindex which does not have BLOCK_HAVE_DATA.
    CBlockIndex* pindexFirstNeverProcessed = NULL; // Oldest ancestor of pindex for which nTx == 0.
    CBlockIndex* pindexFirstNotTreeValid = NULL; // Oldest ancestor of pindex which does not have BLOCK_VALID_TREE (regardless of being valid or not).
    CBlockIndex* pindexFirstNotTransactionsValid = NULL; // Oldest ancestor of pindex which does not have BLOCK_VALID_TRANSACTIONS (regardless of being valid or not).
    CBlockIndex* pindexFirstNotChainValid = NULL; // Oldest ancestor of pindex which does not have BLOCK_VALID_CHAIN (regardless of being valid or not).
    CBlockIndex* pindexFirstNotScriptsValid = NULL; // Oldest ancestor of pindex which does not have BLOCK_VALID_SCRIPTS (regardless of being valid or not).
    while (pindex != NULL) {
        nNodes++;
        if (pindexFirstInvalid == NULL && pindex->nStatus & BLOCK_FAILED_VALID) pindexFirstInvalid = pindex;
        if (pindexFirstMissing == NULL && !(pindex->nStatus & BLOCK_HAVE_DATA)) pindexFirstMissing = pindex;
        if (pindexFirstNeverProcessed == NULL && pindex->nTx == 0) pindexFirstNeverProcessed = pindex;
        if (pindex->pprev != NULL && pindexFirstNotTreeValid == NULL && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TREE) pindexFirstNotTreeValid = pindex;
        if (pindex->pprev != NULL && pindexFirstNotTransactionsValid == NULL && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TRANSACTIONS) pindexFirstNotTransactionsValid = pindex;
        if (pindex->pprev != NULL && pindexFirstNotChainValid == NULL && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_CHAIN) pindexFirstNotChainValid = pindex;
        if (pindex->pprev != NULL && pindexFirstNotScriptsValid == NULL && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_SCRIPTS) pindexFirstNotScriptsValid = pindex;

        // Begin: actual consistency checks.
        if (pindex->pprev == NULL) {
            // Genesis block checks.
            assert(pindex->GetBlockHash() == consensusParams.hashGenesisBlock); // Genesis block's hash must match.
            assert(pindex == chainActive.Genesis()); // The current active chain's genesis block must be this block.
        }
        if (pindex->nChainTx == 0) assert(pindex->nSequenceId <= 0);  // nSequenceId can't be set positive for blocks that aren't linked (negative is used for preciousblock)
        // VALID_TRANSACTIONS is equivalent to nTx > 0 for all nodes (whether or not pruning has occurred).
        // HAVE_DATA is only equivalent to nTx > 0 (or VALID_TRANSACTIONS) if no pruning has occurred.
        if (!fHavePruned) {
            // If we've never pruned, then HAVE_DATA should be equivalent to nTx > 0
            assert(!(pindex->nStatus & BLOCK_HAVE_DATA) == (pindex->nTx == 0));
            assert(pindexFirstMissing == pindexFirstNeverProcessed);
        } else {
            // If we have pruned, then we can only say that HAVE_DATA implies nTx > 0
            if (pindex->nStatus & BLOCK_HAVE_DATA) assert(pindex->nTx > 0);
        }
        if (pindex->nStatus & BLOCK_HAVE_UNDO) assert(pindex->nStatus & BLOCK_HAVE_DATA);
        assert(((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TRANSACTIONS) == (pindex->nTx > 0)); // This is pruning-independent.
        // All parents having had data (at some point) is equivalent to all parents being VALID_TRANSACTIONS, which is equivalent to nChainTx being set.
        assert((pindexFirstNeverProcessed != NULL) == (pindex->nChainTx == 0)); // nChainTx != 0 is used to signal that all parent blocks have been processed (but may have been pruned).
        assert((pindexFirstNotTransactionsValid != NULL) == (pindex->nChainTx == 0));
        assert(pindex->nHeight == nHeight); // nHeight must be consistent.
        assert(pindex->pprev == NULL || pindex->nChainWork >= pindex->pprev->nChainWork); // For every block except the genesis block, the chainwork must be larger than the parent's.
        assert(nHeight < 2 || (pindex->pskip && (pindex->pskip->nHeight < nHeight))); // The pskip pointer must point back for all but the first 2 blocks.
        assert(pindexFirstNotTreeValid == NULL); // All mapBlockIndex entries must at least be TREE valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TREE) assert(pindexFirstNotTreeValid == NULL); // TREE valid implies all parents are TREE valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_CHAIN) assert(pindexFirstNotChainValid == NULL); // CHAIN valid implies all parents are CHAIN valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_SCRIPTS) assert(pindexFirstNotScriptsValid == NULL); // SCRIPTS valid implies all parents are SCRIPTS valid
        if (pindexFirstInvalid == NULL) {
            // Checks for not-invalid blocks.
            assert((pindex->nStatus & BLOCK_FAILED_MASK) == 0); // The failed mask cannot be set for blocks without invalid parents.
        }
        if (!CBlockIndexWorkComparator()(pindex, chainActive.Tip()) && pindexFirstNeverProcessed == NULL) {
            if (pindexFirstInvalid == NULL) {
                // If this block sorts at least as good as the current tip and
                // is valid and we have all data for its parents, it must be in
                // setBlockIndexCandidates.  chainActive.Tip() must also be there
                // even if some data has been pruned.
                if (pindexFirstMissing == NULL || pindex == chainActive.Tip()) {
                    assert(setBlockIndexCandidates.count(pindex));
                }
                // If some parent is missing, then it could be that this block was in
                // setBlockIndexCandidates but had to be removed because of the missing data.
                // In this case it must be in mapBlocksUnlinked -- see test below.
            }
        } else { // If this block sorts worse than the current tip or some ancestor's block has never been seen, it cannot be in setBlockIndexCandidates.
            assert(setBlockIndexCandidates.count(pindex) == 0);
        }
        // Check whether this block is in mapBlocksUnlinked.
        std::pair<std::multimap<CBlockIndex*,CBlockIndex*>::iterator,std::multimap<CBlockIndex*,CBlockIndex*>::iterator> rangeUnlinked = mapBlocksUnlinked.equal_range(pindex->pprev);
        bool foundInUnlinked = false;
        while (rangeUnlinked.first != rangeUnlinked.second) {
            assert(rangeUnlinked.first->first == pindex->pprev);
            if (rangeUnlinked.first->second == pindex) {
                foundInUnlinked = true;
                break;
            }
            rangeUnlinked.first++;
        }
        if (pindex->pprev && (pindex->nStatus & BLOCK_HAVE_DATA) && pindexFirstNeverProcessed != NULL && pindexFirstInvalid == NULL) {
            // If this block has block data available, some parent was never received, and has no invalid parents, it must be in mapBlocksUnlinked.
            assert(foundInUnlinked);
        }
        if (!(pindex->nStatus & BLOCK_HAVE_DATA)) assert(!foundInUnlinked); // Can't be in mapBlocksUnlinked if we don't HAVE_DATA
        if (pindexFirstMissing == NULL) assert(!foundInUnlinked); // We aren't missing data for any parent -- cannot be in mapBlocksUnlinked.
        if (pindex->pprev && (pindex->nStatus & BLOCK_HAVE_DATA) && pindexFirstNeverProcessed == NULL && pindexFirstMissing != NULL) {
            // We HAVE_DATA for this block, have received data for all parents at some point, but we're currently missing data for some parent.
            assert(fHavePruned); // We must have pruned.
            // This block may have entered mapBlocksUnlinked if:
            //  - it has a descendant that at some point had more work than the
            //    tip, and
            //  - we tried switching to that descendant but were missing
            //    data for some intermediate block between chainActive and the
            //    tip.
            // So if this block is itself better than chainActive.Tip() and it wasn't in
            // setBlockIndexCandidates, then it must be in mapBlocksUnlinked.
            if (!CBlockIndexWorkComparator()(pindex, chainActive.Tip()) && setBlockIndexCandidates.count(pindex) == 0) {
                if (pindexFirstInvalid == NULL) {
                    assert(foundInUnlinked);
                }
            }
        }
        // assert(pindex->GetBlockHash() == pindex->GetBlockHeader().GetHash()); // Perhaps too slow
        // End: actual consistency checks.

        // Try descending into the first subnode.
        std::pair<std::multimap<CBlockIndex*,CBlockIndex*>::iterator,std::multimap<CBlockIndex*,CBlockIndex*>::iterator> range = forward.equal_range(pindex);
        if (range.first != range.second) {
            // A subnode was found.
            pindex = range.first->second;
            nHeight++;
            continue;
        }
        // This is a leaf node.
        // Move upwards until we reach a node of which we have not yet visited the last child.
        while (pindex) {
            // We are going to either move to a parent or a sibling of pindex.
            // If pindex was the first with a certain property, unset the corresponding variable.
            if (pindex == pindexFirstInvalid) pindexFirstInvalid = NULL;
            if (pindex == pindexFirstMissing) pindexFirstMissing = NULL;
            if (pindex == pindexFirstNeverProcessed) pindexFirstNeverProcessed = NULL;
            if (pindex == pindexFirstNotTreeValid) pindexFirstNotTreeValid = NULL;
            if (pindex == pindexFirstNotTransactionsValid) pindexFirstNotTransactionsValid = NULL;
            if (pindex == pindexFirstNotChainValid) pindexFirstNotChainValid = NULL;
            if (pindex == pindexFirstNotScriptsValid) pindexFirstNotScriptsValid = NULL;
            // Find our parent.
            CBlockIndex* pindexPar = pindex->pprev;
            // Find which child we just visited.
            std::pair<std::multimap<CBlockIndex*,CBlockIndex*>::iterator,std::multimap<CBlockIndex*,CBlockIndex*>::iterator> rangePar = forward.equal_range(pindexPar);
            while (rangePar.first->second != pindex) {
                assert(rangePar.first != rangePar.second); // Our parent must have at least the node we're coming from as child.
                rangePar.first++;
            }
            // Proceed to the next one.
            rangePar.first++;
            if (rangePar.first != rangePar.second) {
                // Move to the sibling.
                pindex = rangePar.first->second;
                break;
            } else {
                // Move up further.
                pindex = pindexPar;
                nHeight--;
                continue;
            }
        }
    }

    // Check that we actually traversed the entire map.
    assert(nNodes == forward.size());
}

std::string CBlockFileInfo::ToString() const
{
    return strprintf("CBlockFileInfo(blocks=%u, size=%u, heights=%u...%u, time=%s...%s)", nBlocks, nSize, nHeightFirst, nHeightLast, DateTimeStrFormat("%Y-%m-%d", nTimeFirst), DateTimeStrFormat("%Y-%m-%d", nTimeLast));
}

CBlockFileInfo* GetBlockFileInfo(size_t n)
{
    return &vinfoBlockFile.at(n);
}

ThresholdState VersionBitsTipState(const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    LOCK(cs_main);
    return VersionBitsState(chainActive.Tip(), params, pos, versionbitscache);
}

int VersionBitsTipStateSinceHeight(const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    LOCK(cs_main);
    return VersionBitsStateSinceHeight(chainActive.Tip(), params, pos, versionbitscache);
}

static const uint64_t MEMPOOL_DUMP_VERSION = 1;

bool LoadMempool(void)
{
    int64_t nExpiryTimeout = GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60;
    FILE* filestr = fopen((GetDataDir() / "mempool.dat").string().c_str(), "rb");
    CAutoFile file(filestr, SER_DISK, CLIENT_VERSION);
    if (file.IsNull()) {
        LogPrintf("Failed to open mempool file from disk. Continuing anyway.\n");
        return false;
    }

    int64_t count = 0;
    int64_t skipped = 0;
    int64_t failed = 0;
    int64_t nNow = GetTime();

    try {
        uint64_t version;
        file >> version;
        if (version != MEMPOOL_DUMP_VERSION) {
            return false;
        }
        uint64_t num;
        file >> num;
        double prioritydummy = 0;
        while (num--) {
            CTransactionRef tx;
            int64_t nTime;
            int64_t nFeeDelta;
            file >> tx;
            file >> nTime;
            file >> nFeeDelta;

            CAmount amountdelta = nFeeDelta;
            if (amountdelta) {
                mempool.PrioritiseTransaction(tx->GetHash(), tx->GetHash().ToString(), prioritydummy, amountdelta);
            }
            CValidationState state;
            if (nTime + nExpiryTimeout > nNow) {
                LOCK(cs_main);
                AcceptToMemoryPoolWithTime(mempool, state, tx, true, NULL, nTime);
                if (state.IsValid()) {
                    ++count;
                } else {
                    ++failed;
                }
            } else {
                ++skipped;
            }
            if (ShutdownRequested())
                return false;
        }
        std::map<uint256, CAmount> mapDeltas;
        file >> mapDeltas;

        for (const auto& i : mapDeltas) {
            mempool.PrioritiseTransaction(i.first, i.first.ToString(), prioritydummy, i.second);
        }
    } catch (const std::exception& e) {
        LogPrintf("Failed to deserialize mempool data on disk: %s. Continuing anyway.\n", e.what());
        return false;
    }

    LogPrintf("Imported mempool transactions from disk: %i successes, %i failed, %i expired\n", count, failed, skipped);
    return true;
}

void DumpMempool(void)
{
    int64_t start = GetTimeMicros();

    std::map<uint256, CAmount> mapDeltas;
    std::vector<TxMempoolInfo> vinfo;

    {
        LOCK(mempool.cs);
        for (const auto &i : mempool.mapDeltas) {
            mapDeltas[i.first] = i.second.second;
        }
        vinfo = mempool.infoAll();
    }

    int64_t mid = GetTimeMicros();

    try {
        FILE* filestr = fopen((GetDataDir() / "mempool.dat.new").string().c_str(), "wb");
        if (!filestr) {
            return;
        }

        CAutoFile file(filestr, SER_DISK, CLIENT_VERSION);

        uint64_t version = MEMPOOL_DUMP_VERSION;
        file << version;

        file << (uint64_t)vinfo.size();
        for (const auto& i : vinfo) {
            file << *(i.tx);
            file << (int64_t)i.nTime;
            file << (int64_t)i.nFeeDelta;
            mapDeltas.erase(i.tx->GetHash());
        }

        file << mapDeltas;
        FileCommit(file.Get());
        file.fclose();
        RenameOver(GetDataDir() / "mempool.dat.new", GetDataDir() / "mempool.dat");
        int64_t last = GetTimeMicros();
        LogPrintf("Dumped mempool: %gs to copy, %gs to dump\n", (mid-start)*0.000001, (last-mid)*0.000001);
    } catch (const std::exception& e) {
        LogPrintf("Failed to dump mempool: %s. Continuing anyway.\n", e.what());
    }
}

//! Guess how far we are in the verification process at the given block index
double GuessVerificationProgress(const ChainTxData& data, CBlockIndex *pindex) {
    if (pindex == NULL)
        return 0.0;

    int64_t nNow = time(NULL);

    double fTxTotal;

    if (pindex->nChainTx <= data.nTxCount) {
        fTxTotal = data.nTxCount + (nNow - data.nTime) * data.dTxRate;
    } else {
        fTxTotal = pindex->nChainTx + (nNow - pindex->GetBlockTime()) * data.dTxRate;
    }

    return pindex->nChainTx / fTxTotal;
}

class CMainCleanup
{
public:
    CMainCleanup() {}
    ~CMainCleanup() {
        // block headers
        BlockMap::iterator it1 = mapBlockIndex.begin();
        for (; it1 != mapBlockIndex.end(); it1++)
            delete (*it1).second;
        mapBlockIndex.clear();
    }
} instance_of_cmaincleanup;
