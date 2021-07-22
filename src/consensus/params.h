// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include "uint256.h"
#include <map>
#include <string>
#include <set>
#include <unordered_set>
#include <secp256k1/include/GroupElement.h>

namespace Consensus {

enum DeploymentPos
{
    DEPLOYMENT_TESTDUMMY,
    DEPLOYMENT_CSV, // Deployment of BIP68, BIP112, and BIP113.
    DEPLOYMENT_SEGWIT, // Deployment of BIP141, BIP143, and BIP147.

    DEPLOYMENT_MTP, // Deployment of MTP

    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in versionbits.cpp
    MAX_VERSION_BITS_DEPLOYMENTS
};

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit;
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime;
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout;
};

enum LLMQType : uint8_t
{
    LLMQ_NONE = 0xff,

    LLMQ_50_60 = 1, // 50 members, 30 (60%) threshold, one per hour
    LLMQ_400_60 = 2, // 400 members, 240 (60%) threshold, one every 12 hours
    LLMQ_400_85 = 3, // 400 members, 340 (85%) threshold, one every 24 hours

    // for testing only
    LLMQ_10_70 = 4,  // 10 members, 7 (70%) threshold, one per hour
    LLMQ_5_60 = 100, // 5 members, 3 (60%) threshold, one per hour
};

// Configures a LLMQ and its DKG
// See https://github.com/dashpay/dips/blob/master/dip-0006.md for more details
struct LLMQParams {
    LLMQType type;

    // not consensus critical, only used in logging, RPC and UI
    std::string name;

    // the size of the quorum, e.g. 50 or 400
    int size;

    // The minimum number of valid members after the DKK. If less members are determined valid, no commitment can be
    // created. Should be higher then the threshold to allow some room for failing nodes, otherwise quorum might end up
    // not being able to ever created a recovered signature if more nodes fail after the DKG
    int minSize;

    // The threshold required to recover a final signature. Should be at least 50%+1 of the quorum size. This value
    // also controls the size of the public key verification vector and has a large influence on the performance of
    // recovery. It also influences the amount of minimum messages that need to be exchanged for a single signing session.
    // This value has the most influence on the security of the quorum. The number of total malicious masternodes
    // required to negatively influence signing sessions highly correlates to the threshold percentage.
    int threshold;

    // The interval in number blocks for DKGs and the creation of LLMQs. If set to 24 for example, a DKG will start
    // every 24 blocks, which is approximately once every hour.
    int dkgInterval;

    // The number of blocks per phase in a DKG session. There are 6 phases plus the mining phase that need to be processed
    // per DKG. Set this value to a number of blocks so that each phase has enough time to propagate all required
    // messages to all members before the next phase starts. If blocks are produced too fast, whole DKG sessions will
    // fail.
    int dkgPhaseBlocks;

    // The starting block inside the DKG interval for when mining of commitments starts. The value is inclusive.
    // Starting from this block, the inclusion of (possibly null) commitments is enforced until the first non-null
    // commitment is mined. The chosen value should be at least 5 * dkgPhaseBlocks so that it starts right after the
    // finalization phase.
    int dkgMiningWindowStart;

    // The ending block inside the DKG interval for when mining of commitments ends. The value is inclusive.
    // Choose a value so that miners have enough time to receive the commitment and mine it. Also take into consideration
    // that miners might omit real commitments and revert to always including null commitments. The mining window should
    // be large enough so that other miners have a chance to produce a block containing a non-null commitment. The window
    // should at the same time not be too large so that not too much space is wasted with null commitments in case a DKG
    // session failed.
    int dkgMiningWindowEnd;

    // In the complaint phase, members will vote on other members being bad (missing valid contribution). If at least
    // dkgBadVotesThreshold have voted for another member to be bad, it will considered to be bad by all other members
    // as well. This serves as a protection against late-comers who send their contribution on the bring of
    // phase-transition, which would otherwise result in inconsistent views of the valid members set
    int dkgBadVotesThreshold;

    // Number of quorums to consider "active" for signing sessions
    int signingActiveQuorumCount;

    // Used for inter-quorum communication. This is the number of quorums for which we should keep old connections. This
    // should be at least one more then the active quorums set.
    int keepOldConnections;
};

/**
 * Type of chain
 */
enum ChainType {
    chainMain,
    chainTestnet,
    chainRegtest
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    ChainType chainType;

    uint256 hashGenesisBlock;
    /** First subsidy halving */
    int nSubsidyHalvingFirst;
    /** Subsequent subsidy halving intervals */
    int nSubsidyHalvingInterval;
    /** Stop subsidy at this block number */
    int nSubsidyHalvingStopBlock;

    /** parameters for coinbase payment distribution between first and second halvings (aka stage 2) */
    /** P2PKH or P2SH address for developer funds */
    std::string stage2DevelopmentFundAddress;
    /** percentage of block subsidy going to developer fund */
    int stage2DevelopmentFundShare;
    /** percentage of block subsidy going to znode */
    int stage2ZnodeShare;

    int nStartDuplicationCheck;
    int nStartBlacklist;

    /** Used to check majorities for block version upgrade */
    int nMajorityEnforceBlockUpgrade;
    int nMajorityRejectBlockOutdated;
    int nMajorityWindow;
    /** Block height and hash at which BIP34 becomes active */
    int BIP34Height;
    uint256 BIP34Hash;
    /** Block height at which BIP65 becomes active */
    int BIP65Height;
    /** Block height at which BIP66 becomes active */
    int BIP66Height;
    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
     * (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint32_t nRuleChangeActivationThreshold;
    uint32_t nMinerConfirmationWindow;
    BIP9Deployment vDeployments[MAX_VERSION_BITS_DEPLOYMENTS];
    /** Proof of work parameters */
    uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;
    int64_t nPowTargetSpacing;
    int64_t nPowTargetTimespan;
    int64_t nChainStartTime;
    unsigned char nMinNFactor;
    unsigned char nMaxNFactor;
    int nZnodePaymentsStartBlock;

    int nInstantSendConfirmationsRequired; // in blocks
    int nInstantSendKeepLock; // in blocks
    int nInstantSendSigsRequired;
    int nInstantSendSigsTotal;

	/** Zerocoin-related block numbers when features are changed */
    int nCheckBugFixedAtBlock;
    int nZnodePaymentsBugFixedAtBlock;
	int nSpendV15StartBlock;
	int nSpendV2ID_1, nSpendV2ID_10, nSpendV2ID_25, nSpendV2ID_50, nSpendV2ID_100;

	int nModulusV2StartBlock;
    int nModulusV1MempoolStopBlock;
	int nModulusV1StopBlock;

    int nMultipleSpendInputsInOneTxStartBlock;

    int nDontAllowDupTxsStartBlock;

    // Values for dandelion.

    // The minimum amount of time a Dandelion transaction is embargoed (seconds).
    uint32_t nDandelionEmbargoMinimum;

    // The average additional embargo time beyond the minimum amount (seconds).
    uint32_t nDandelionEmbargoAvgAdd;

    // Maximum number of outbound peers designated as Dandelion destinations.
    uint32_t nDandelionMaxDestinations;

    // Expected time between Dandelion routing shuffles (in seconds).
    uint32_t nDandelionShuffleInterval;

    // Probability (percentage) that a Dandelion transaction enters fluff phase.
    uint32_t nDandelionFluff;

    // Values for sigma implementation.

    // The block number after which sigma are accepted.
    int nSigmaStartBlock;

    int nSigmaPaddingBlock;

    int nDisableUnpaddedSigmaBlock;

    int nStartSigmaBlacklist;
    int nRestartSigmaWithBlacklistCheck;

    // The block number after which old sigma clients are banned.
    int nOldSigmaBanBlock;

    // The block number after which lelantus is accepted.
    int nLelantusStartBlock;

    int nLelantusFixesStartBlock;

    // Lelantus Blacklist
    std::unordered_set<secp_primitives::GroupElement> lelantusBlacklist;

    // Sigma Blacklist
    std::unordered_set<secp_primitives::GroupElement> sigmaBlacklist;

    // The block number introducing evo sporks
    int nEvoSporkStartBlock;

    // The block number to stop using evo sporks
    int nEvoSporkStopBlock;

    // Key to sign spork txs
    std::string evoSporkKeyID;

    // The block number when Bip39 was implemented in Zcoin
    int nMnemonicBlock;

    // Number of blocks after nSigmaMintStartBlock during which we still accept zerocoin V2 mints into mempool.
    int nZerocoinV2MintMempoolGracefulPeriod;

    // Number of blocks after nSigmaMintStartBlock during which we still accept zerocoin V2 mints to newly mined blocks.
    int nZerocoinV2MintGracefulPeriod;

    // Number of blocks after nSigmaMintStartBlock during which we still accept zerocoin V2 spend into mempool.
    int nZerocoinV2SpendMempoolGracefulPeriod;

    // Number of blocks after nSigmaMintStartBlock during which we still accept zerocoin V2 spend to newly mined blocks.
    int nZerocoinV2SpendGracefulPeriod;

    // Amount of maximum sigma spend per block.
    unsigned nMaxSigmaInputPerBlock;

    // Value of maximum sigma spend per block.
    int64_t nMaxValueSigmaSpendPerBlock;

    // Amount of maximum sigma spend per transaction.
    unsigned nMaxSigmaInputPerTransaction;

    // Value of maximum sigma spend per transaction.
    int64_t nMaxValueSigmaSpendPerTransaction;

    // Amount of maximum lelantus spend per block.
    unsigned nMaxLelantusInputPerBlock;

    // Value of maximum lelantus spend per block.
    int64_t nMaxValueLelantusSpendPerBlock;

    // Amount of maximum lelantus spend per transaction.
    unsigned nMaxLelantusInputPerTransaction;

    // Value of maximum lelantus spend per transaction.
    int64_t nMaxValueLelantusSpendPerTransaction;

    // Value of maximum lelantus mint.
    int64_t nMaxValueLelantusMint;

    // Number of blocks with allowed zerocoin to sigma remint transaction (after nSigmaStartBlock)
    int nZerocoinToSigmaRemintWindowSize;

    /** switch to MTP time */
    uint32_t nMTPSwitchTime;
    /** number of block when MTP switch occurs or 0 if not clear yet */
    int nMTPStartBlock;
    /** block number to reduce distance between blocks */
    int nMTPFiveMinutesStartBlock;

    /** don't adjust difficulty until some block number */
    int nDifficultyAdjustStartBlock;
    /** fixed diffuculty to use before adjustment takes place */
    int nFixedDifficulty;

    /** pow target spacing after switch to MTP */
    int64_t nPowTargetSpacingMTP;

    /** initial MTP difficulty */
    int nInitialMTPDifficulty;

    /** reduction coefficient for rewards after MTP kicks in */
    int nMTPRewardReduction;

    /** block number to disable zerocoin on consensus level */
    int nDisableZerocoinStartBlock;

    /** block to start accepting pro reg txs for evo znodes */
    int DIP0003Height;

    /** block to switch to evo znode payments */
    int DIP0003EnforcementHeight;
    uint256 DIP0003EnforcementHash;

    /** block to start using chainlocks */
    int DIP0008Height;

    /** maximum reorg depth */
    int nMaxReorgDepth;
    /** block to start reorg depth enforcement */
    int nMaxReorgDepthEnforcementBlock;

    /** move lelantus data to v3 payload since this block */
    int nLelantusV3PayloadStartBlock;

    /** whitelisted transactions */
    std::set<uint256> txidWhitelist;

    int nEvoZnodeMinimumConfirmations;

    std::map<LLMQType, LLMQParams> llmqs;
    LLMQType llmqChainLocks;
    LLMQType llmqForInstantSend{LLMQ_NONE};

    /** Time between blocks for LLMQ random time purposes. Can be less than actual average distance between blocks */
    int nLLMQPowTargetSpacing;

    int64_t DifficultyAdjustmentInterval(bool fMTP = false) const { return nPowTargetTimespan / (fMTP ? nPowTargetSpacingMTP : nPowTargetSpacing); }
    uint256 nMinimumChainWork;
    uint256 defaultAssumeValid;

    bool IsMain() const { return chainType == chainMain; }
    bool IsTestnet() const { return chainType == chainTestnet; }
    bool IsRegtest() const { return chainType == chainRegtest; }
};
} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
