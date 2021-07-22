// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "miner.h"

#include "amount.h"
#include "chain.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/consensus.h"
#include "consensus/merkle.h"
#include "consensus/validation.h"
#include "hash.h"
#include "base58.h"
#include "validation.h"
#include "net.h"
#include "policy/policy.h"
#include "pow.h"
#include "primitives/transaction.h"
#include "script/standard.h"
#include "timedata.h"
#include "txmempool.h"
#include "util.h"
#include "utilmoneystr.h"
#include "validationinterface.h"
#include "wallet/wallet.h"
#include "definition.h"
#include "crypto/scrypt.h"
#include "crypto/MerkleTreeProof/mtp.h"
#include "crypto/Lyra2Z/Lyra2Z.h"
#include "crypto/Lyra2Z/Lyra2.h"
#include "sigma.h"
#include "lelantus.h"
#include "evo/spork.h"
#include <algorithm>
#include <boost/thread.hpp>
#include <boost/tuple/tuple.hpp>
#include <queue>
#include <unistd.h>

#include "masternode-payments.h"

#include "evo/specialtx.h"
#include "evo/cbtx.h"
#include "evo/simplifiedmns.h"
#include "evo/deterministicmns.h"
#include "evo/spork.h"

#include "llmq/quorums_blockprocessor.h"

#include <utility>

//////////////////////////////////////////////////////////////////////////////
//
// BitcoinMiner
//

//
// Unconfirmed transactions in the memory pool often depend on other
// transactions in the memory pool. When we select transactions from the
// pool, we select by highest priority or fee rate, so we might consider
// transactions that depend on transactions that aren't yet in the block.

uint64_t nLastBlockTx = 0;
uint64_t nLastBlockSize = 0;
uint64_t nLastBlockWeight = 0;

class ScoreCompare
{
public:
    ScoreCompare() {}

    bool operator()(const CTxMemPool::txiter a, const CTxMemPool::txiter b)
    {
        return CompareTxMemPoolEntryByScore()(*b,*a); // Convert to less than
    }
};

int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    int64_t nOldTime = pblock->nTime;
    int64_t nNewTime = std::max(pindexPrev->GetMedianTimePast()+1, GetAdjustedTime());

    if (nOldTime < nNewTime)
        pblock->nTime = nNewTime;

    // Updating time can change work required on testnet:
    if (consensusParams.fPowAllowMinDifficultyBlocks)
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams);

    return nNewTime - nOldTime;
}

BlockAssembler::BlockAssembler(const CChainParams& _chainparams)
    : chainparams(_chainparams)
{
    // Block resource limits
    // If neither -blockmaxsize or -blockmaxweight is given, limit to DEFAULT_BLOCK_MAX_*
    // If only one is given, only restrict the specified resource.
    // If both are given, restrict both.
    nBlockMaxWeight = DEFAULT_BLOCK_MAX_WEIGHT;
    nBlockMaxSize = DEFAULT_BLOCK_MAX_SIZE;
    bool fWeightSet = false;
    if (IsArgSet("-blockmaxweight")) {
        nBlockMaxWeight = GetArg("-blockmaxweight", DEFAULT_BLOCK_MAX_WEIGHT);
        nBlockMaxSize = MAX_BLOCK_SERIALIZED_SIZE;
        fWeightSet = true;
    }
    if (IsArgSet("-blockmaxsize")) {
        nBlockMaxSize = GetArg("-blockmaxsize", DEFAULT_BLOCK_MAX_SIZE);
        if (!fWeightSet) {
            nBlockMaxWeight = nBlockMaxSize * WITNESS_SCALE_FACTOR;
        }
    }
    if (IsArgSet("-blockmintxfee")) {
        CAmount n = 0;
        ParseMoney(GetArg("-blockmintxfee", ""), n);
        blockMinFeeRate = CFeeRate(n);
    } else {
        blockMinFeeRate = CFeeRate(DEFAULT_BLOCK_MIN_TX_FEE);
    }

    // Limit weight to between 4K and MAX_BLOCK_WEIGHT-4K for sanity:
    nBlockMaxWeight = std::max((unsigned int)4000, std::min((unsigned int)(MAX_BLOCK_WEIGHT-4000), nBlockMaxWeight));
    // Limit size to between 1K and MAX_BLOCK_SERIALIZED_SIZE-1K for sanity:
    nBlockMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(MAX_BLOCK_SERIALIZED_SIZE-1000), nBlockMaxSize));
    // Whether we need to account for byte usage (in addition to weight usage)
    fNeedSizeAccounting = (nBlockMaxSize < MAX_BLOCK_SERIALIZED_SIZE-1000);
}

void BlockAssembler::resetBlock()
{
    inBlock.clear();

    // Reserve space for coinbase tx
    nBlockSize = 1000;
    nBlockWeight = 4000;
    nBlockSigOpsCost = 100;
    fIncludeWitness = false;

    // These counters do not include coinbase tx
    nBlockTx = 0;
    nFees = 0;

    lastFewTxs = 0;
    blockFinished = false;

    nSigmaSpendAmount = 0;
    nSigmaSpendInputs = 0;

    nLelantusSpendAmount = 0;
    nLelantusSpendInputs = 0;
}

std::unique_ptr<CBlockTemplate> BlockAssembler::CreateNewBlock(const CScript& scriptPubKeyIn, bool fMineWitnessTx)
{
    // Create new block
    LogPrintf("BlockAssembler::CreateNewBlock()\n");

    int64_t nTimeStart = GetTimeMicros();

    // fMTP is always true currently
    const Consensus::Params &params = chainparams.GetConsensus();

    resetBlock();

    pblocktemplate.reset(new CBlockTemplate());

    if(!pblocktemplate.get())
        return nullptr;
    pblock = &pblocktemplate->block; // pointer for convenience

    // Add dummy coinbase tx as first transaction
    pblock->vtx.emplace_back();
    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOpsCost.push_back(-1); // updated at end

    LOCK(cs_main);
    CBlockIndex* pindexPrev = chainActive.Tip();
    nHeight = pindexPrev->nHeight + 1;

    bool fDIP0003Active_context = nHeight >= chainparams.GetConsensus().DIP0003Height;
    bool fDIP0008Active_context = nHeight >= chainparams.GetConsensus().DIP0008Height;

    pblock->nTime = GetAdjustedTime();
    bool fMTP = (pblock->nTime >= params.nMTPSwitchTime);
    const int64_t nMedianTimePast = pindexPrev->GetMedianTimePast();

    pblock->nVersion = ComputeBlockVersion(pindexPrev, chainparams.GetConsensus()) | (fMTP ? 0x1000 : 0);
    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (chainparams.MineBlocksOnDemand())
        pblock->nVersion = GetArg("-blockversion", pblock->nVersion) | (fMTP ? 0x1000 : 0);

    nLockTimeCutoff = (STANDARD_LOCKTIME_VERIFY_FLAGS & LOCKTIME_MEDIAN_TIME_PAST)
                       ? nMedianTimePast
                       : pblock->GetBlockTime();

    if (fDIP0003Active_context) {
        for (auto& p : chainparams.GetConsensus().llmqs) {
            CTransactionRef qcTx;
            if (llmq::quorumBlockProcessor->GetMinableCommitmentTx(p.first, nHeight, qcTx)) {
                pblock->vtx.emplace_back(qcTx);
                pblocktemplate->vTxFees.emplace_back(0);
                pblocktemplate->vTxSigOpsCost.emplace_back(0);
                nBlockSize += qcTx->GetTotalSize();
                ++nBlockTx;
            }
        }
    }

    // Decide whether to include witness transactions
    // This is only needed in case the witness softfork activation is reverted
    // (which would require a very deep reorganization) or when
    // -promiscuousmempoolflags is used.
    // TODO: replace this with a call to main to assess validity of a mempool
    // transaction (which in most cases can be a no-op).
    fIncludeWitness = IsWitnessEnabled(pindexPrev, chainparams.GetConsensus()) && fMineWitnessTx;

    int nPackagesSelected = 0;
    int nDescendantsUpdated = 0;
    {
        LOCK(mempool.cs);
        FillBlackListForBlockTemplate();

        addPriorityTxs();
        addPackageTxs(nPackagesSelected, nDescendantsUpdated);
    }

    int64_t nTime1 = GetTimeMicros();

    nLastBlockTx = nBlockTx;
    nLastBlockSize = nBlockSize;
    nLastBlockWeight = nBlockWeight;

    CAmount nBlockSubsidy = GetBlockSubsidy(nHeight, chainparams.GetConsensus(), pblock->nTime);

    // Create coinbase transaction.
    CMutableTransaction coinbaseTx;
    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout.SetNull();
    coinbaseTx.vout.resize(1);
    coinbaseTx.vout[0].scriptPubKey = scriptPubKeyIn;

    coinbaseTx.vout[0].nValue = nFees + nBlockSubsidy;
    coinbaseTx.vin[0].scriptSig = CScript() << nHeight << OP_0;

    FillFoundersReward(coinbaseTx, fMTP);

    if (fDIP0003Active_context) {
        coinbaseTx.vin[0].scriptSig = CScript() << OP_RETURN;

        coinbaseTx.nVersion = 3;
        coinbaseTx.nType = TRANSACTION_COINBASE;

        CCbTx cbTx;


        if (fDIP0008Active_context) {
            cbTx.nVersion = 2;
        } else {
            cbTx.nVersion = 1;
        }

        cbTx.nHeight = nHeight;

        CValidationState state;
        if (!CalcCbTxMerkleRootMNList(*pblock, pindexPrev, cbTx.merkleRootMNList, state)) {
            throw std::runtime_error(strprintf("%s: CalcCbTxMerkleRootMNList failed: %s", __func__, FormatStateMessage(state)));
        }
        if (fDIP0008Active_context) {
            if (!CalcCbTxMerkleRootQuorums(*pblock, pindexPrev, cbTx.merkleRootQuorums, state)) {
                throw std::runtime_error(strprintf("%s: CalcCbTxMerkleRootQuorums failed: %s", __func__, FormatStateMessage(state)));
            }
        }

        SetTxPayload(coinbaseTx, cbTx);
    }
        
    std::vector<CTxOut> sbPayments;
    FillBlockPayments(coinbaseTx, nHeight, nBlockSubsidy, pblocktemplate->voutMasternodePayments, sbPayments);

    pblock->vtx[0] = MakeTransactionRef(std::move(coinbaseTx));
    pblocktemplate->vTxFees[0] = -nFees;

    uint64_t nSerializeSize = GetSerializeSize(*pblock, SER_NETWORK, PROTOCOL_VERSION);
    LogPrintf("CreateNewBlock(): total size: %u block weight: %u txs: %u fees: %ld sigops %d\n", nSerializeSize, GetBlockWeight(*pblock), nBlockTx, nFees, nBlockSigOpsCost);

    // Fill in header
    pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
    UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev);
    pblock->nBits          = GetNextWorkRequired(pindexPrev, pblock, chainparams.GetConsensus());
    pblock->nNonce         = 0;
    pblock->nNonce64       = 0;
    pblock->nHeight        = nHeight;
    pblocktemplate->vTxSigOpsCost[0] = GetLegacySigOpCount(*pblock->vtx[0]);

    // Firo - MTP
    if (fMTP)
        pblock->mtpHashData = std::make_shared<CMTPHashData>();

    CValidationState state;
    if (!TestBlockValidity(state, chainparams, *pblock, pindexPrev, false, false)) {
        throw std::runtime_error(strprintf("%s: TestBlockValidity failed: %s", __func__, FormatStateMessage(state)));
    }
    int64_t nTime2 = GetTimeMicros();

    LogPrint("bench", "CreateNewBlock() packages: %.2fms (%d packages, %d updated descendants), validity: %.2fms (total %.2fms)\n", 0.001 * (nTime1 - nTimeStart), nPackagesSelected, nDescendantsUpdated, 0.001 * (nTime2 - nTime1), 0.001 * (nTime2 - nTimeStart));

    return std::move(pblocktemplate);
}

bool BlockAssembler::isStillDependent(CTxMemPool::txiter iter)
{
    BOOST_FOREACH(CTxMemPool::txiter parent, mempool.GetMemPoolParents(iter))
    {
        if (!inBlock.count(parent)) {
            return true;
        }
    }
    return false;
}

void BlockAssembler::onlyUnconfirmed(CTxMemPool::setEntries& testSet)
{
    for (CTxMemPool::setEntries::iterator iit = testSet.begin(); iit != testSet.end(); ) {
        // Only test txs not already in the block
        if (inBlock.count(*iit)) {
            testSet.erase(iit++);
        }
        else {
            iit++;
        }
    }
}

bool BlockAssembler::TestPackage(uint64_t packageSize, int64_t packageSigOpsCost)
{
    // TODO: switch to weight-based accounting for packages instead of vsize-based accounting.
    if (nBlockWeight + WITNESS_SCALE_FACTOR * packageSize >= nBlockMaxWeight)
        return false;
    if (nBlockSigOpsCost + packageSigOpsCost >= MAX_BLOCK_SIGOPS_COST)
        return false;
    return true;
}

// Perform transaction-level checks before adding to block:
// - transaction finality (locktime)
// - premature witness (in case segwit transactions are added to mempool before
//   segwit activation)
// - serialized size (in case -blockmaxsize is in use)
bool BlockAssembler::TestPackageTransactions(const CTxMemPool::setEntries& package)
{
    uint64_t nPotentialBlockSize = nBlockSize; // only used with fNeedSizeAccounting
    BOOST_FOREACH (const CTxMemPool::txiter it, package) {
        if (!IsFinalTx(it->GetTx(), nHeight, nLockTimeCutoff))
            return false;
        if (!fIncludeWitness && it->GetTx().HasWitness())
            return false;
        if (fNeedSizeAccounting) {
            uint64_t nTxSize = ::GetSerializeSize(it->GetTx(), SER_NETWORK, PROTOCOL_VERSION);
            if (nPotentialBlockSize + nTxSize >= nBlockMaxSize) {
                return false;
            }
            nPotentialBlockSize += nTxSize;
        }
    }
    return true;
}

bool BlockAssembler::TestForBlock(CTxMemPool::txiter iter)
{
    if (nBlockWeight + iter->GetTxWeight() >= nBlockMaxWeight) {
        // If the block is so close to full that no more txs will fit
        // or if we've tried more than 50 times to fill remaining space
        // then flag that the block is finished
        if (nBlockWeight >  nBlockMaxWeight - 400 || lastFewTxs > 50) {
             blockFinished = true;
             return false;
        }
        // Once we're within 4000 weight of a full block, only look at 50 more txs
        // to try to fill the remaining space.
        if (nBlockWeight > nBlockMaxWeight - 4000) {
            lastFewTxs++;
        }
        return false;
    }

    if (fNeedSizeAccounting) {
        if (nBlockSize + ::GetSerializeSize(iter->GetTx(), SER_NETWORK, PROTOCOL_VERSION) >= nBlockMaxSize) {
            if (nBlockSize >  nBlockMaxSize - 100 || lastFewTxs > 50) {
                 blockFinished = true;
                 return false;
            }
            if (nBlockSize > nBlockMaxSize - 1000) {
                lastFewTxs++;
            }
            return false;
        }
    }

    if (nBlockSigOpsCost + iter->GetSigOpCost() >= MAX_BLOCK_SIGOPS_COST) {
        // If the block has room for no more sig ops then
        // flag that the block is finished
        if (nBlockSigOpsCost > MAX_BLOCK_SIGOPS_COST - 8) {
            blockFinished = true;
            return false;
        }
        // Otherwise attempt to find another tx with fewer sigops
        // to put in the block.
        return false;
    }

    // Must check that lock times are still valid
    // This can be removed once MTP is always enforced
    // as long as reorgs keep the mempool consistent.
    if (!IsFinalTx(iter->GetTx(), nHeight, nLockTimeCutoff))
        return false;

    const CTransaction &tx = iter->GetTx();

    // Check transaction against sigma limits
    if (tx.IsSigmaSpend()) {
        CAmount spendAmount = sigma::GetSpendAmount(tx);
        auto &params = chainparams.GetConsensus();

        if (tx.vin.size() > params.nMaxSigmaInputPerTransaction || spendAmount > params.nMaxValueSigmaSpendPerTransaction)
            return false;

        if (tx.vin.size() + nSigmaSpendInputs > params.nMaxSigmaInputPerBlock)
            return false;

        if (spendAmount + nSigmaSpendAmount > params.nMaxValueSigmaSpendPerBlock)
            return false;
    }

    // Check transaction against lelantus limits
    if(tx.IsLelantusJoinSplit()) {
        CAmount spendAmount = lelantus::GetSpendTransparentAmount(tx);
        size_t spendNumber = lelantus::GetSpendInputs(tx);
        auto &params = chainparams.GetConsensus();

        if (spendNumber > params.nMaxLelantusInputPerTransaction || spendAmount > params.nMaxValueLelantusSpendPerTransaction)
            return false;

        if (spendNumber + nLelantusSpendInputs > params.nMaxLelantusInputPerBlock)
            return false;

        if (spendAmount + nLelantusSpendAmount > params.nMaxValueLelantusSpendPerBlock)
            return false;
    }

    return true;
}

void BlockAssembler::AddToBlock(CTxMemPool::txiter iter)
{
    const CTransaction &tx = iter->GetTx();
    if (tx.IsSigmaSpend()) {
        // Update sigma stats
        CAmount spendAmount = sigma::GetSpendAmount(tx);

        if ((nSigmaSpendAmount += spendAmount) > chainparams.GetConsensus().nMaxValueSigmaSpendPerBlock)
            return;

        if ((nSigmaSpendInputs += tx.vin.size()) > chainparams.GetConsensus().nMaxSigmaInputPerBlock)
            return;
    }

    if(tx.IsLelantusJoinSplit()) {
        CAmount spendAmount = lelantus::GetSpendTransparentAmount(tx);
        size_t spendNumber = lelantus::GetSpendInputs(tx);
        auto &params = chainparams.GetConsensus();

        if (spendAmount > params.nMaxValueLelantusSpendPerTransaction)
            return;

        if ((nLelantusSpendAmount += spendAmount) > params.nMaxValueLelantusSpendPerBlock)
            return;

        if ((nLelantusSpendInputs += spendNumber) > params.nMaxLelantusInputPerBlock)
            return;
    }

    pblock->vtx.emplace_back(iter->GetSharedTx());
    pblocktemplate->vTxFees.push_back(iter->GetFee());
    pblocktemplate->vTxSigOpsCost.push_back(iter->GetSigOpCost());
    if (fNeedSizeAccounting) {
        nBlockSize += ::GetSerializeSize(iter->GetTx(), SER_NETWORK, PROTOCOL_VERSION);
    }
    nBlockWeight += iter->GetTxWeight();
    ++nBlockTx;
    nBlockSigOpsCost += iter->GetSigOpCost();
    nFees += iter->GetFee();
    inBlock.insert(iter);

    bool fPrintPriority = GetBoolArg("-printpriority", DEFAULT_PRINTPRIORITY);
    if (fPrintPriority) {
        double dPriority = iter->GetPriority(nHeight);
        CAmount dummy;
        mempool.ApplyDeltas(iter->GetTx().GetHash(), dPriority, dummy);
        LogPrintf("priority %.1f fee %s txid %s\n",
                  dPriority,
                  CFeeRate(iter->GetModifiedFee(), iter->GetTxSize()).ToString(),
                  iter->GetTx().GetHash().ToString());
    }
}

int BlockAssembler::UpdatePackagesForAdded(const CTxMemPool::setEntries& alreadyAdded,
        indexed_modified_transaction_set &mapModifiedTx)
{
    int nDescendantsUpdated = 0;
    BOOST_FOREACH(const CTxMemPool::txiter it, alreadyAdded) {
        // do not add descendants for sigma spend transaction
        // it is not allowed to have sigma spend output consumed in the same block
        if (it->GetTx().IsSigmaSpend())
            continue;

        CTxMemPool::setEntries descendants;
        mempool.CalculateDescendants(it, descendants);
        // Insert all descendants (not yet in block) into the modified set
        BOOST_FOREACH(CTxMemPool::txiter desc, descendants) {
            if (alreadyAdded.count(desc) || txBlackList.count(desc) > 0)
                continue;
            ++nDescendantsUpdated;
            modtxiter mit = mapModifiedTx.find(desc);
            if (mit == mapModifiedTx.end()) {
                CTxMemPoolModifiedEntry modEntry(desc);
                modEntry.nSizeWithAncestors -= it->GetTxSize();
                modEntry.nModFeesWithAncestors -= it->GetModifiedFee();
                modEntry.nSigOpCostWithAncestors -= it->GetSigOpCost();
                mapModifiedTx.insert(modEntry);
            } else {
                mapModifiedTx.modify(mit, update_for_parent_inclusion(it));
            }
        }
    }
    return nDescendantsUpdated;
}

// Skip entries in mapTx that are already in a block or are present
// in mapModifiedTx (which implies that the mapTx ancestor state is
// stale due to ancestor inclusion in the block)
// Also skip transactions that we've already failed to add. This can happen if
// we consider a transaction in mapModifiedTx and it fails: we can then
// potentially consider it again while walking mapTx.  It's currently
// guaranteed to fail again, but as a belt-and-suspenders check we put it in
// failedTx and avoid re-evaluation, since the re-evaluation would be using
// cached size/sigops/fee values that are not actually correct.
bool BlockAssembler::SkipMapTxEntry(CTxMemPool::txiter it, indexed_modified_transaction_set &mapModifiedTx, CTxMemPool::setEntries &failedTx)
{
    assert (it != mempool.mapTx.end());
    if (mapModifiedTx.count(it) || inBlock.count(it) || failedTx.count(it) || txBlackList.count(it))
        return true;
    return false;
}

void BlockAssembler::SortForBlock(const CTxMemPool::setEntries& package, CTxMemPool::txiter entry, std::vector<CTxMemPool::txiter>& sortedEntries)
{
    // Sort package by ancestor count
    // If a transaction A depends on transaction B, then A's ancestor count
    // must be greater than B's.  So this is sufficient to validly order the
    // transactions for block inclusion.
    sortedEntries.clear();
    sortedEntries.insert(sortedEntries.begin(), package.begin(), package.end());
    std::sort(sortedEntries.begin(), sortedEntries.end(), CompareTxIterByAncestorCount());
}

// This transaction selection algorithm orders the mempool based
// on feerate of a transaction including all unconfirmed ancestors.
// Since we don't remove transactions from the mempool as we select them
// for block inclusion, we need an alternate method of updating the feerate
// of a transaction with its not-yet-selected ancestors as we go.
// This is accomplished by walking the in-mempool descendants of selected
// transactions and storing a temporary modified state in mapModifiedTxs.
// Each time through the loop, we compare the best transaction in
// mapModifiedTxs with the next transaction in the mempool to decide what
// transaction package to work on next.
void BlockAssembler::addPackageTxs(int &nPackagesSelected, int &nDescendantsUpdated)
{
    // mapModifiedTx will store sorted packages after they are modified
    // because some of their txs are already in the block
    indexed_modified_transaction_set mapModifiedTx;
    // Keep track of entries that failed inclusion, to avoid duplicate work
    CTxMemPool::setEntries failedTx;

    // Start by adding all descendants of previously added txs to mapModifiedTx
    // and modifying them for their already included ancestors
    UpdatePackagesForAdded(inBlock, mapModifiedTx);

    CTxMemPool::indexed_transaction_set::index<ancestor_score>::type::iterator mi = mempool.mapTx.get<ancestor_score>().begin();
    CTxMemPool::txiter iter;

    // Limit the number of attempts to add transactions to the block when it is
    // close to full; this is just a simple heuristic to finish quickly if the
    // mempool has a lot of entries.
    const int64_t MAX_CONSECUTIVE_FAILURES = 1000;
    int64_t nConsecutiveFailed = 0;

    while (mi != mempool.mapTx.get<ancestor_score>().end() || !mapModifiedTx.empty())
    {
        // First try to find a new transaction in mapTx to evaluate.
        if (mi != mempool.mapTx.get<ancestor_score>().end() &&
                SkipMapTxEntry(mempool.mapTx.project<0>(mi), mapModifiedTx, failedTx)) {
            ++mi;
            continue;
        }

        // Now that mi is not stale, determine which transaction to evaluate:
        // the next entry from mapTx, or the best from mapModifiedTx?
        bool fUsingModified = false;

        modtxscoreiter modit = mapModifiedTx.get<ancestor_score>().begin();
        if (mi == mempool.mapTx.get<ancestor_score>().end()) {
            // We're out of entries in mapTx; use the entry from mapModifiedTx
            iter = modit->iter;
            fUsingModified = true;
        } else {
            // Try to compare the mapTx entry to the mapModifiedTx entry
            iter = mempool.mapTx.project<0>(mi);
            if (modit != mapModifiedTx.get<ancestor_score>().end() &&
                    CompareModifiedEntry()(*modit, CTxMemPoolModifiedEntry(iter))) {
                // The best entry in mapModifiedTx has higher score
                // than the one from mapTx.
                // Switch which transaction (package) to consider
                iter = modit->iter;
                fUsingModified = true;
            } else {
                // Either no entry in mapModifiedTx, or it's worse than mapTx.
                // Increment mi for the next loop iteration.
                ++mi;
            }
        }

        // We skip mapTx entries that are inBlock, and mapModifiedTx shouldn't
        // contain anything that is inBlock.
        assert(!inBlock.count(iter));

        uint64_t packageSize = iter->GetSizeWithAncestors();
        CAmount packageFees = iter->GetModFeesWithAncestors();
        int64_t packageSigOpsCost = iter->GetSigOpCostWithAncestors();
        if (fUsingModified) {
            packageSize = modit->nSizeWithAncestors;
            packageFees = modit->nModFeesWithAncestors;
            packageSigOpsCost = modit->nSigOpCostWithAncestors;
        }

        if (packageFees < blockMinFeeRate.GetFee(packageSize)) {
            // Everything else we might consider has a lower fee rate
            return;
        }

        if (!TestPackage(packageSize, packageSigOpsCost)) {
            if (fUsingModified) {
                // Since we always look at the best entry in mapModifiedTx,
                // we must erase failed entries so that we can consider the
                // next best entry on the next loop iteration
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }

            ++nConsecutiveFailed;

            if (nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES && nBlockWeight >
                    nBlockMaxWeight - 4000) {
                // Give up if we're close to full and haven't succeeded in a while
                break;
            }
            continue;
        }

        CTxMemPool::setEntries ancestors;
        uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
        std::string dummy;
        mempool.CalculateMemPoolAncestors(*iter, ancestors, nNoLimit, nNoLimit, nNoLimit, nNoLimit, dummy, false);

        onlyUnconfirmed(ancestors);
        ancestors.insert(iter);

        // Test if all tx's are Final
        if (!TestPackageTransactions(ancestors)) {
            if (fUsingModified) {
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }
            continue;
        }

        // This transaction will make it in; reset the failed counter.
        nConsecutiveFailed = 0;

        // Package can be added. Sort the entries in a valid order.
        std::vector<CTxMemPool::txiter> sortedEntries;
        SortForBlock(ancestors, iter, sortedEntries);

        for (size_t i=0; i<sortedEntries.size(); ++i) {
            AddToBlock(sortedEntries[i]);
            // Erase from the modified set, if present
            mapModifiedTx.erase(sortedEntries[i]);
        }

        ++nPackagesSelected;

        // Update transactions that depend on each of these
        nDescendantsUpdated += UpdatePackagesForAdded(ancestors, mapModifiedTx);
    }
}

void BlockAssembler::addPriorityTxs()
{
    // How much of the block should be dedicated to high-priority transactions,
    // included regardless of the fees they pay
    unsigned int nBlockPrioritySize = GetArg("-blockprioritysize", DEFAULT_BLOCK_PRIORITY_SIZE);
    nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);

    if (nBlockPrioritySize == 0) {
        return;
    }

    bool fSizeAccounting = fNeedSizeAccounting;
    fNeedSizeAccounting = true;

    // This vector will be sorted into a priority queue:
    std::vector<TxCoinAgePriority> vecPriority;
    TxCoinAgePriorityCompare pricomparer;
    std::map<CTxMemPool::txiter, double, CTxMemPool::CompareIteratorByHash> waitPriMap;
    typedef std::map<CTxMemPool::txiter, double, CTxMemPool::CompareIteratorByHash>::iterator waitPriIter;
    double actualPriority = -1;

    vecPriority.reserve(mempool.mapTx.size());
    for (CTxMemPool::indexed_transaction_set::iterator mi = mempool.mapTx.begin();
         mi != mempool.mapTx.end(); ++mi)
    {
        // Skip transactions depending on privacy tx outputs in the mempool
        if (txBlackList.count(mi))
            continue;

        double dPriority = mi->GetPriority(nHeight);
        CAmount dummy;
        mempool.ApplyDeltas(mi->GetTx().GetHash(), dPriority, dummy);
        vecPriority.push_back(TxCoinAgePriority(dPriority, mi));
    }
    std::make_heap(vecPriority.begin(), vecPriority.end(), pricomparer);

    CTxMemPool::txiter iter;
    while (!vecPriority.empty() && !blockFinished) { // add a tx from priority queue to fill the blockprioritysize
        iter = vecPriority.front().second;
        actualPriority = vecPriority.front().first;
        std::pop_heap(vecPriority.begin(), vecPriority.end(), pricomparer);
        vecPriority.pop_back();

        // If tx already in block, skip
        if (inBlock.count(iter)) {
            assert(false); // shouldn't happen for priority txs
            continue;
        }

        // cannot accept witness transactions into a non-witness block
        if (!fIncludeWitness && iter->GetTx().HasWitness())
            continue;

        // If tx is dependent on other mempool txs which haven't yet been included
        // then put it in the waitSet
        if (isStillDependent(iter)) {
            waitPriMap.insert(std::make_pair(iter, actualPriority));
            continue;
        }

        // If this tx fits in the block add it, otherwise keep looping
        if (TestForBlock(iter)) {
            AddToBlock(iter);

            // If now that this txs is added we've surpassed our desired priority size
            // or have dropped below the AllowFreeThreshold, then we're done adding priority txs
            if (nBlockSize >= nBlockPrioritySize || !AllowFree(actualPriority)) {
                // Make exception for zerocoin->sigma remints
                if (!iter->GetTx().IsZerocoinRemint())
                    break;
            }

            // This tx was successfully added, so
            // add transactions that depend on this one to the priority queue to try again
            BOOST_FOREACH(CTxMemPool::txiter child, mempool.GetMemPoolChildren(iter))
            {
                waitPriIter wpiter = waitPriMap.find(child);
                if (wpiter != waitPriMap.end()) {
                    vecPriority.push_back(TxCoinAgePriority(wpiter->second,child));
                    std::push_heap(vecPriority.begin(), vecPriority.end(), pricomparer);
                    waitPriMap.erase(wpiter);
                }
            }
        }
    }
    fNeedSizeAccounting = fSizeAccounting;
}

void BlockAssembler::FillFoundersReward(CMutableTransaction &coinbaseTx, bool fMTP) {
    auto &params = chainparams.GetConsensus();
    CAmount coin = COIN / (fMTP ? params.nMTPRewardReduction : 1);

    if (nHeight >= params.nSubsidyHalvingFirst && nHeight < params.nSubsidyHalvingFirst + params.nSubsidyHalvingInterval) {
        // Stage 2
        CScript devPayoutScript = GetScriptForDestination(CBitcoinAddress(params.stage2DevelopmentFundAddress).Get());
        CAmount devPayoutValue = (GetBlockSubsidyWithMTPFlag(nHeight, params, fMTP) * params.stage2DevelopmentFundShare) / 100;

        coinbaseTx.vout[0].nValue -= devPayoutValue;
        coinbaseTx.vout.push_back(CTxOut(devPayoutValue, devPayoutScript));
    }

    else if ((nHeight > 0) && (nHeight < params.nSubsidyHalvingFirst)) {
        // Stage 1: To founders and investors
        CScript FOUNDER_1_SCRIPT;
        CScript FOUNDER_2_SCRIPT;
        CScript FOUNDER_3_SCRIPT;
        CScript FOUNDER_4_SCRIPT;
        CScript FOUNDER_5_SCRIPT;
        if (nHeight < params.nZnodePaymentsStartBlock) {
            // Take some reward away from us
            coinbaseTx.vout[0].nValue -= 10 * coin;

            if (params.IsMain() && (GetAdjustedTime() > nStartRewardTime)) {
                FOUNDER_1_SCRIPT = GetScriptForDestination(CBitcoinAddress("aCAgTPgtYcA4EysU4UKC86EQd5cTtHtCcr").Get());
                if (nHeight + 1 < 14000) {
                    FOUNDER_2_SCRIPT = GetScriptForDestination(CBitcoinAddress("aLrg41sXbXZc5MyEj7dts8upZKSAtJmRDR").Get());
                } else {
                    FOUNDER_2_SCRIPT = GetScriptForDestination(CBitcoinAddress("aHu897ivzmeFuLNB6956X6gyGeVNHUBRgD").Get());
                }
                FOUNDER_3_SCRIPT = GetScriptForDestination(CBitcoinAddress("aQ18FBVFtnueucZKeVg4srhmzbpAeb1KoN").Get());
                FOUNDER_4_SCRIPT = GetScriptForDestination(CBitcoinAddress("a1HwTdCmQV3NspP2QqCGpehoFpi8NY4Zg3").Get());
                FOUNDER_5_SCRIPT = GetScriptForDestination(CBitcoinAddress("a1kCCGddf5pMXSipLVD9hBG2MGGVNaJ15U").Get());
            } else if (params.IsMain() && (GetAdjustedTime() <= nStartRewardTime)) {
                throw std::runtime_error("CreateNewBlock() : Create new block too early");
            } else if (!params.IsMain()) {
                FOUNDER_1_SCRIPT = GetScriptForDestination(CBitcoinAddress("TDk19wPKYq91i18qmY6U9FeTdTxwPeSveo").Get());
                FOUNDER_2_SCRIPT = GetScriptForDestination(CBitcoinAddress("TWZZcDGkNixTAMtRBqzZkkMHbq1G6vUTk5").Get());
                FOUNDER_3_SCRIPT = GetScriptForDestination(CBitcoinAddress("TRZTFdNCKCKbLMQV8cZDkQN9Vwuuq4gDzT").Get());
                FOUNDER_4_SCRIPT = GetScriptForDestination(CBitcoinAddress("TG2ruj59E5b1u9G3F7HQVs6pCcVDBxrQve").Get());
                FOUNDER_5_SCRIPT = GetScriptForDestination(CBitcoinAddress("TCsTzQZKVn4fao8jDmB9zQBk9YQNEZ3XfS").Get());
            }

            // And give it to the founders
            coinbaseTx.vout.push_back(CTxOut(2 * coin, CScript(FOUNDER_1_SCRIPT.begin(), FOUNDER_1_SCRIPT.end())));
            coinbaseTx.vout.push_back(CTxOut(2 * coin, CScript(FOUNDER_2_SCRIPT.begin(), FOUNDER_2_SCRIPT.end())));
            coinbaseTx.vout.push_back(CTxOut(2 * coin, CScript(FOUNDER_3_SCRIPT.begin(), FOUNDER_3_SCRIPT.end())));
            coinbaseTx.vout.push_back(CTxOut(2 * coin, CScript(FOUNDER_4_SCRIPT.begin(), FOUNDER_4_SCRIPT.end())));
            coinbaseTx.vout.push_back(CTxOut(2 * coin, CScript(FOUNDER_5_SCRIPT.begin(), FOUNDER_5_SCRIPT.end())));
        } else if (nHeight >= Params().GetConsensus().nZnodePaymentsStartBlock) {
            // Take some reward away from us
            coinbaseTx.vout[0].nValue -= 7 * coin;

            if (params.IsMain() && (GetAdjustedTime() > nStartRewardTime)) {
                FOUNDER_1_SCRIPT = GetScriptForDestination(CBitcoinAddress("aCAgTPgtYcA4EysU4UKC86EQd5cTtHtCcr").Get());
                if (nHeight + 1 < 14000) {
                    FOUNDER_2_SCRIPT = GetScriptForDestination(CBitcoinAddress("aLrg41sXbXZc5MyEj7dts8upZKSAtJmRDR").Get());
                } else {
                    FOUNDER_2_SCRIPT = GetScriptForDestination(CBitcoinAddress("aHu897ivzmeFuLNB6956X6gyGeVNHUBRgD").Get());
                }
                FOUNDER_3_SCRIPT = GetScriptForDestination(CBitcoinAddress("aQ18FBVFtnueucZKeVg4srhmzbpAeb1KoN").Get());
                FOUNDER_4_SCRIPT = GetScriptForDestination(CBitcoinAddress("a1HwTdCmQV3NspP2QqCGpehoFpi8NY4Zg3").Get());
                FOUNDER_5_SCRIPT = GetScriptForDestination(CBitcoinAddress("a1kCCGddf5pMXSipLVD9hBG2MGGVNaJ15U").Get());
            } else if (params.IsMain() && (GetAdjustedTime() <= nStartRewardTime)) {
                throw std::runtime_error("CreateNewBlock() : Create new block too early");
            } else if (!params.IsMain()) {
                FOUNDER_1_SCRIPT = GetScriptForDestination(CBitcoinAddress("TDk19wPKYq91i18qmY6U9FeTdTxwPeSveo").Get());
                FOUNDER_2_SCRIPT = GetScriptForDestination(CBitcoinAddress("TWZZcDGkNixTAMtRBqzZkkMHbq1G6vUTk5").Get());
                FOUNDER_3_SCRIPT = GetScriptForDestination(CBitcoinAddress("TRZTFdNCKCKbLMQV8cZDkQN9Vwuuq4gDzT").Get());
                FOUNDER_4_SCRIPT = GetScriptForDestination(CBitcoinAddress("TG2ruj59E5b1u9G3F7HQVs6pCcVDBxrQve").Get());
                FOUNDER_5_SCRIPT = GetScriptForDestination(CBitcoinAddress("TCsTzQZKVn4fao8jDmB9zQBk9YQNEZ3XfS").Get());
            }

            // And give it to the founders
            coinbaseTx.vout.push_back(CTxOut(1 * coin, CScript(FOUNDER_1_SCRIPT.begin(), FOUNDER_1_SCRIPT.end())));
            coinbaseTx.vout.push_back(CTxOut(1 * coin, CScript(FOUNDER_2_SCRIPT.begin(), FOUNDER_2_SCRIPT.end())));
            coinbaseTx.vout.push_back(CTxOut(1 * coin, CScript(FOUNDER_3_SCRIPT.begin(), FOUNDER_3_SCRIPT.end())));
            coinbaseTx.vout.push_back(CTxOut(3 * coin, CScript(FOUNDER_4_SCRIPT.begin(), FOUNDER_4_SCRIPT.end())));
            coinbaseTx.vout.push_back(CTxOut(1 * coin, CScript(FOUNDER_5_SCRIPT.begin(), FOUNDER_5_SCRIPT.end())));
        }
    }
}

void BlockAssembler::FillBlackListForBlockTemplate() {
    CTxMemPool::setEntries sporkTxs;

    for (CTxMemPool::txiter mi = mempool.mapTx.begin(); mi != mempool.mapTx.end(); ++mi)
    {
        if (txBlackList.count(mi) > 0)
            continue;

        const CTransaction &tx = mi->GetTx();

        // transactions depending (directly or not) on sigma spends in the mempool cannot be included in the
        // same block with spend transaction
        if (tx.IsSigmaSpend()) {
            mempool.CalculateDescendants(mi, txBlackList);
            // remove privacy transaction itself
            txBlackList.erase(mi);
        }

        if (tx.nVersion >= 3 && tx.nType == TRANSACTION_PROVIDER_REGISTER) {
            CProRegTx proTx;
            if (GetTxPayload(tx, proTx) && !proTx.collateralOutpoint.hash.IsNull() &&
                    // ProRegTx referencing external collateral can't be in same block with the collateral itself
                    (mempool.get(proTx.collateralOutpoint.hash) ||
                    // ProRegTx cannot be in the same block as transaction spending external collateral
                        mempool.isSpent(proTx.collateralOutpoint)))
                mempool.CalculateDescendants(mi, txBlackList);
        }

        if (tx.nVersion >= 3 && tx.nType == TRANSACTION_SPORK) {
            CSporkTx sporkTx;
            if (GetTxPayload<CSporkTx>(tx, sporkTx)) {
                sporkTxs.insert(mi);
            }
        }
    }

    // Update spork map with sporks to be included in block
    std::vector<CTransactionRef> sporkTxRefs;
    for (auto sporkTx: sporkTxs) {
        if (txBlackList.count(sporkTx) == 0)
            sporkTxRefs.push_back(sporkTx->GetSharedTx());
    }
    CSporkManager *sporkManager = CSporkManager::GetSporkManager();
    ActiveSporkMap prevSporkMap = chainActive.Tip()->activeDisablingSporks;
    ActiveSporkMap sporkMap;
    sporkManager->UpdateActiveSporkMap(sporkMap, prevSporkMap, chainActive.Tip()->nHeight+1, sporkTxRefs);

    // blacklist all the transactions not allowed under the spork set
    if (!sporkMap.empty()) {
        for (CTxMemPool::txiter mi = mempool.mapTx.begin(); mi != mempool.mapTx.end(); ++mi) {
            CValidationState state;
            if (!sporkManager->IsTransactionAllowed(mi->GetTx(), sporkMap, state))
                mempool.CalculateDescendants(mi, txBlackList);
        }
    }

    // Now if we have limit on lelantus transparent outputs scan mempool and drop all the transactions exceeding the limit
    if (sporkMap.count(CSporkAction::featureLelantusTransparentLimit) > 0) {
        CAmount limit = sporkMap[CSporkAction::featureLelantusTransparentLimit].second;

        std::vector<CTxMemPool::txiter> joinSplitTxs;
        for (CTxMemPool::txiter mi = mempool.mapTx.begin(); mi != mempool.mapTx.end(); ++mi) {
            if (txBlackList.count(mi) == 0 && mi->GetTx().IsLelantusJoinSplit())
                joinSplitTxs.push_back(mi);
        }

        // sort join splits in order of their transparent outputs so large txs won't block smaller ones
        // from getting into the mempool
        std::sort(joinSplitTxs.begin(), joinSplitTxs.end(), 
            [](CTxMemPool::txiter a, CTxMemPool::txiter b) -> bool {
                return lelantus::GetSpendTransparentAmount(a->GetTx()) < lelantus::GetSpendTransparentAmount(b->GetTx());
            });

        CAmount transparentAmount = 0;
        std::vector<CTxMemPool::txiter>::const_iterator it;
        for (it = joinSplitTxs.cbegin(); it != joinSplitTxs.cend(); ++it) {
            CAmount output = lelantus::GetSpendTransparentAmount((*it)->GetTx());
            if (transparentAmount + output > limit)
                break;
            transparentAmount += output;
        }

        // found all the joinsplit transaction fitting in the limit, blacklist the rest
        while (it != joinSplitTxs.cend())
            mempool.CalculateDescendants(*it++, txBlackList);
    }
}

//////////////////////////////////////////////////////////////////////////////
//
// Internal miner
//

//
// ScanHash scans nonces looking for a hash with at least some zero bits.
// The nonce is usually preserved between calls, but periodically or if the
// nonce is 0xffff0000 or above, the block is rebuilt and nNonce starts over at
// zero.
//
//bool static ScanHash(const CBlockHeader *pblock, uint32_t& nNonce, uint256 *phash)
//{
//    // Write the first 76 bytes of the block header to a double-SHA256 state.
//    CHash256 hasher;
//    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
//    ss << *pblock;
//    assert(ss.size() == 80);
//    hasher.Write((unsigned char*)&ss[0], 76);
//
//    while (true) {
//        nNonce++;
//
//        // Write the last 4 bytes of the block header (the nonce) to a copy of
//        // the double-SHA256 state, and compute the result.
//        CHash256(hasher).Write((unsigned char*)&nNonce, 4).Finalize((unsigned char*)phash);
//
//        // Return the nonce if the hash has at least some zero bits,
//        // caller will check if it has enough to reach the target
//        if (((uint16_t*)phash)[15] == 0)
//            return true;
//
//        // If nothing found after trying for a while, return -1
//        if ((nNonce & 0xfff) == 0)
//            return false;
//    }
//}

static bool ProcessBlockFound(const CBlock* pblock, const CChainParams& chainparams)
{
    LogPrintf("%s\n", pblock->ToString());
    LogPrintf("generated %s\n", FormatMoney(pblock->vtx[0]->vout[0].nValue));

    // Found a solution
    {
        LOCK(cs_main);
        if (pblock->hashPrevBlock != chainActive.Tip()->GetBlockHash())
            return error("FiroMiner: generated block is stale");
    }

    // Inform about the new block
    GetMainSignals().BlockFound(pblock->GetHash());

    // Process this block the same as if we had received it from another node
    if (!ProcessNewBlock(chainparams, std::shared_ptr<const CBlock>(new CBlock(*pblock)), true, NULL))
        return error("FiroMiner: ProcessNewBlock, block not accepted");

    return true;
}

void static FiroMiner(const CChainParams &chainparams) {
    SetThreadPriority(THREAD_PRIORITY_LOWEST);
    RenameThread("firo-miner");

    unsigned int nExtraNonce = 0;

    boost::shared_ptr<CReserveScript> coinbaseScript;
    GetMainSignals().ScriptForMining(coinbaseScript);
    bool fTestNet = chainparams.GetConsensus().IsTestnet();
    try {
        // Throw an error if no script was provided.  This can happen
        // due to some internal error but also if the keypool is empty.
        // In the latter case, already the pointer is NULL.
        if (!coinbaseScript || coinbaseScript->reserveScript.empty()) {
            LogPrintf("FiroMiner stop here coinbaseScript=%s, coinbaseScript->reserveScript.empty()=%s\n", coinbaseScript, coinbaseScript->reserveScript.empty());
            throw std::runtime_error("No coinbase script available (mining requires a wallet)");
        }

        while (true) {
            if (chainparams.MiningRequiresPeers()) {
                // Busy-wait for the network to come online so we don't waste time mining
                // on an obsolete chain. In regtest mode we expect to fly solo.

                // Also try to wait for znode winners unless we're on regtest chain
                do {
                    bool fvNodesEmpty = g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL) == 0;
                    bool fHasZnodesWinnerForNextBlock;
                    const Consensus::Params &params = chainparams.GetConsensus();
                    {
                        LOCK2(cs_main, mempool.cs);
                        int nCount = 0;
                        fHasZnodesWinnerForNextBlock =
                                params.IsRegtest() ||
                                chainActive.Height()+1 >= chainparams.GetConsensus().DIP0003EnforcementHeight;
                    }
                    if (!fvNodesEmpty && fHasZnodesWinnerForNextBlock && !IsInitialBlockDownload()) {
                        break;
                    }
                    MilliSleep(1000);
                } while (true);
            }
            //
            // Create new block
            //
            unsigned int nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
            CBlockIndex *pindexPrev = chainActive.Tip();
            if (pindexPrev) {
                LogPrintf("loop pindexPrev->nHeight=%s\n", pindexPrev->nHeight);
            }
            LogPrintf("BEFORE: pblocktemplate\n");
            std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler(Params()).CreateNewBlock(coinbaseScript->reserveScript, {});
            LogPrintf("AFTER: pblocktemplate\n");
            if (!pblocktemplate.get()) {
                LogPrintf("Error in FiroMiner: Keypool ran out, please call keypoolrefill before restarting the mining thread\n");
                return;
            }
            CBlock *pblock = &pblocktemplate->block;
            IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

            LogPrintf("Running FiroMiner with %u transactions in block (%u bytes)\n", pblock->vtx.size(),
                      ::GetSerializeSize(*pblock, SER_NETWORK, PROTOCOL_VERSION));

            LogPrintf("BEFORE: search\n");
            //
            // Search
            //
            int64_t nStart = GetTime();
            arith_uint256 hashTarget = arith_uint256().SetCompact(pblock->nBits);
            LogPrintf("hashTarget: %s\n", hashTarget.ToString());
            LogPrintf("fTestnet: %d\n", fTestNet);
            LogPrintf("pindexPrev->nHeight: %s\n", pindexPrev->nHeight);
            LogPrintf("pblock: %s\n", pblock->ToString());
            LogPrintf("pblock->nVersion: %s\n", pblock->nVersion);
            LogPrintf("pblock->nTime: %s\n", pblock->nTime);
            LogPrintf("pblock->nNonce: %s\n", &pblock->nNonce);
            LogPrintf("powLimit: %s\n", Params().GetConsensus().powLimit.ToString());

            while (true) {
                // Check if something found
                uint256 thash;
                uint256 mix_hash;

                while (true) {
                    if (pblock->IsProgPow()) {
                        thash = pblock->GetProgPowHashFull(mix_hash);
                    } else if (pblock->IsMTP()) {
                        //sleep(60);
                        LogPrintf("BEFORE: mtp_hash\n");
                        thash = mtp::hash(*pblock, Params().GetConsensus().powLimit);
                        pblock->mtpHashValue = thash;
                    } else if (!fTestNet && pindexPrev->nHeight + 1 >= HF_LYRA2Z_HEIGHT) {
                        lyra2z_hash(BEGIN(pblock->nVersion), BEGIN(thash));
                    } else if (!fTestNet && pindexPrev->nHeight + 1 >= HF_LYRA2_HEIGHT) {
                        LYRA2(BEGIN(thash), 32, BEGIN(pblock->nVersion), 80, BEGIN(pblock->nVersion), 80, 2, 8192, 256);
                    } else if (!fTestNet && pindexPrev->nHeight + 1 >= HF_LYRA2VAR_HEIGHT) {
                        LYRA2(BEGIN(thash), 32, BEGIN(pblock->nVersion), 80, BEGIN(pblock->nVersion), 80, 2,
                              pindexPrev->nHeight + 1, 256);
                    } else if (fTestNet && pindexPrev->nHeight + 1 >= HF_LYRA2Z_HEIGHT_TESTNET) { // testnet
                        lyra2z_hash(BEGIN(pblock->nVersion), BEGIN(thash));
                    } else if (fTestNet && pindexPrev->nHeight + 1 >= HF_LYRA2_HEIGHT_TESTNET) { // testnet
                        LYRA2(BEGIN(thash), 32, BEGIN(pblock->nVersion), 80, BEGIN(pblock->nVersion), 80, 2, 8192, 256);
                    } else if (fTestNet && pindexPrev->nHeight + 1 >= HF_LYRA2VAR_HEIGHT_TESTNET) { // testnet
                        LYRA2(BEGIN(thash), 32, BEGIN(pblock->nVersion), 80, BEGIN(pblock->nVersion), 80, 2, pindexPrev->nHeight + 1, 256);
                    } else {
                        unsigned long int scrypt_scratpad_size_current_block =
                                ((1 << (GetNfactor(pblock->nTime) + 1)) * 128) + 63;
                        char *scratchpad = (char *) malloc(scrypt_scratpad_size_current_block * sizeof(char));
                        scrypt_N_1_1_256_sp_generic(BEGIN(pblock->nVersion), BEGIN(thash), scratchpad,
                                                    GetNfactor(pblock->nTime));
//                        LogPrintf("scrypt thash: %s\n", thash.ToString().c_str());
//                        LogPrintf("hashTarget: %s\n", hashTarget.ToString().c_str());
                        free(scratchpad);
                    }

                    boost::this_thread::interruption_point();

                    //LogPrintf("*****\nhash   : %s  \ntarget : %s\n", UintToArith256(thash).ToString(), hashTarget.ToString());
                    auto powTarget = UintToArith256(thash);
                    if (powTarget <= hashTarget) {
                        pblock->mix_hash = mix_hash; // Store ProgPoW mix_hash
                        // Found a solution
                        LogPrintf("Found a solution. Hash: %s", powTarget.ToString());
                        SetThreadPriority(THREAD_PRIORITY_NORMAL);
//                        CheckWork(pblock, *pwallet, reservekey);
                        LogPrintf("FiroMiner:\n");
                        LogPrintf("proof-of-work found  \n  hash: %s  \ntarget: %s\n", powTarget.ToString(), hashTarget.ToString());
                        ProcessBlockFound(pblock, chainparams);
                        SetThreadPriority(THREAD_PRIORITY_LOWEST);
                        coinbaseScript->KeepScript();
                        // In regression test mode, stop mining after a block is found.
                        if (chainparams.MineBlocksOnDemand())
                            throw boost::thread_interrupted();
                        break;
                    }
                    pblock->nNonce += 1;
                    pblock->nNonce64 += 1;
                    if ((pblock->nNonce & 0xFF) == 0)
                        break;
                }
                // Regtest mode doesn't require peers
                if (g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL) == 0 && chainparams.MiningRequiresPeers())
                    break;
                if (pblock->nNonce >= 0xffff0000)
                    break;
                if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 60)
                    break;
                if (pindexPrev != chainActive.Tip())
                    break;

                // Update nTime every few seconds
                if (UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev) < 0)
                    break; // Recreate the block if the clock has run backwards,
                // so that we can use the correct time.
                if (chainparams.GetConsensus().fPowAllowMinDifficultyBlocks) {
                    // Changing pblock->nTime can change work required on testnet:
                    hashTarget.SetCompact(pblock->nBits);
                }
            }
        }
    }
    catch (const boost::thread_interrupted &) {
        LogPrintf("FiroMiner terminated\n");
        throw;
    }
    catch (const std::runtime_error &e) {
        LogPrintf("FiroMiner runtime error: %s\n", e.what());
        return;
    }
}

void GenerateBitcoins(bool fGenerate, int nThreads, const CChainParams& chainparams)
{
    static boost::thread_group* minerThreads = NULL;

    if (nThreads < 0)
        nThreads = GetNumCores();

    if (minerThreads != NULL)
    {
        minerThreads->interrupt_all();
        delete minerThreads;
        minerThreads = NULL;
    }

    if (nThreads == 0 || !fGenerate)
        return;

    minerThreads = new boost::thread_group();
    for (int i = 0; i < nThreads; i++)
        minerThreads->create_thread(boost::bind(&FiroMiner, boost::cref(chainparams)));
}

void IncrementExtraNonce(CBlock* pblock, const CBlockIndex* pindexPrev, unsigned int& nExtraNonce)
{
    // Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;
    unsigned int nHeight = pindexPrev->nHeight+1; // Height first in coinbase required for block.version=2
    CMutableTransaction txCoinbase(*pblock->vtx[0]);
    txCoinbase.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(nExtraNonce)) + COINBASE_FLAGS;
    assert(txCoinbase.vin[0].scriptSig.size() <= 100);

    pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
}
