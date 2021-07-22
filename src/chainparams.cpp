// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"
#include "consensus/consensus.h"
#include "firo_params.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"
#include "bitcoin_bignum/bignum.h"
#include "blacklists.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"
#include "arith_uint256.h"

using namespace secp_primitives;

static CBlock CreateGenesisBlock(const char *pszTimestamp, const CScript &genesisOutputScript, uint32_t nTime, uint32_t nNonce,
        uint32_t nBits, int32_t nVersion, const CAmount &genesisReward,
        std::vector<unsigned char> extraNonce) {
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 504365040 << CBigNum(4).getvch() << std::vector < unsigned char >
    ((const unsigned char *) pszTimestamp, (const unsigned char *) pszTimestamp + strlen(pszTimestamp)) << extraNonce;
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount &genesisReward,
                   std::vector<unsigned char> extraNonce) {
    //btzc: firo timestamp
    const char *pszTimestamp = "Times 2014/10/31 Maine Judge Says Nurse Must Follow Ebola Quarantine for Now";
    const CScript genesisOutputScript = CScript();
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward,
                              extraNonce);
}

// this one is for testing only
static Consensus::LLMQParams llmq5_60 = {
        .type = Consensus::LLMQ_5_60,
        .name = "llmq_5_60",
        .size = 5,
        .minSize = 3,
        .threshold = 3,

        .dkgInterval = 24, // one DKG per hour
        .dkgPhaseBlocks = 2,
        .dkgMiningWindowStart = 10, // dkgPhaseBlocks * 5 = after finalization
        .dkgMiningWindowEnd = 18,
        .dkgBadVotesThreshold = 8,

        .signingActiveQuorumCount = 2, // just a few ones to allow easier testing

        .keepOldConnections = 3,
};

// to use on testnet
static Consensus::LLMQParams llmq10_70 = {
        .type = Consensus::LLMQ_10_70,
        .name = "llmq_10_70",
        .size = 10,
        .minSize = 8,
        .threshold = 7,

        .dkgInterval = 24, // one DKG per hour
        .dkgPhaseBlocks = 2,
        .dkgMiningWindowStart = 10, // dkgPhaseBlocks * 5 = after finalization
        .dkgMiningWindowEnd = 18,
        .dkgBadVotesThreshold = 8,

        .signingActiveQuorumCount = 2, // just a few ones to allow easier testing

        .keepOldConnections = 3,
};

static Consensus::LLMQParams llmq50_60 = {
        .type = Consensus::LLMQ_50_60,
        .name = "llmq_50_60",
        .size = 50,
        .minSize = 40,
        .threshold = 30,

        .dkgInterval = 18, // one DKG per 90 minutes
        .dkgPhaseBlocks = 2,
        .dkgMiningWindowStart = 10, // dkgPhaseBlocks * 5 = after finalization
        .dkgMiningWindowEnd = 16,
        .dkgBadVotesThreshold = 40,

        .signingActiveQuorumCount = 16, // a full day worth of LLMQs

        .keepOldConnections = 17,
};

static Consensus::LLMQParams llmq400_60 = {
        .type = Consensus::LLMQ_400_60,
        .name = "llmq_400_60",
        .size = 400,
        .minSize = 300,
        .threshold = 240,

        .dkgInterval = 12 * 12, // one DKG every 12 hours
        .dkgPhaseBlocks = 4,
        .dkgMiningWindowStart = 20, // dkgPhaseBlocks * 5 = after finalization
        .dkgMiningWindowEnd = 28,
        .dkgBadVotesThreshold = 300,

        .signingActiveQuorumCount = 4, // two days worth of LLMQs

        .keepOldConnections = 5,
};

// Used for deployment and min-proto-version signalling, so it needs a higher threshold
static Consensus::LLMQParams llmq400_85 = {
        .type = Consensus::LLMQ_400_85,
        .name = "llmq_400_85",
        .size = 400,
        .minSize = 350,
        .threshold = 340,

        .dkgInterval = 12 * 24, // one DKG every 24 hours
        .dkgPhaseBlocks = 4,
        .dkgMiningWindowStart = 20, // dkgPhaseBlocks * 5 = after finalization
        .dkgMiningWindowEnd = 48, // give it a larger mining window to make sure it is mined
        .dkgBadVotesThreshold = 300,

        .signingActiveQuorumCount = 4, // two days worth of LLMQs

        .keepOldConnections = 5,
};


/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";

        consensus.chainType = Consensus::chainMain;

        consensus.nSubsidyHalvingFirst = 302438;
        consensus.nSubsidyHalvingInterval = 420000;
        consensus.nSubsidyHalvingStopBlock = 3646849;

        consensus.stage2DevelopmentFundShare = 15;
        consensus.stage2ZnodeShare = 35;
        consensus.stage2DevelopmentFundAddress = "aFrAVZFr8pva5mG8XKaUH8EXcFVVNxLiuB";

        consensus.nStartBlacklist = 293990;
        consensus.nStartDuplicationCheck = 293526;

        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.nMinNFactor = 10;
        consensus.nMaxNFactor = 30;
        consensus.nChainStartTime = 1389306217;
        consensus.BIP34Height = 227931;
        consensus.BIP34Hash = uint256S("0x000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8");
        consensus.BIP65Height = INT_MAX;
        consensus.BIP66Height = INT_MAX;
        consensus.powLimit = uint256S("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 60 * 60; // 60 minutes between retargets
        consensus.nPowTargetSpacing = 10 * 60; // 10 minute blocks
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1475020800; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1462060800; // May 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1479168000; // November 15th, 2016.
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1510704000; // November 15th, 2017.

        // Deployment of MTP
        consensus.vDeployments[Consensus::DEPLOYMENT_MTP].bit = 12;
        consensus.vDeployments[Consensus::DEPLOYMENT_MTP].nStartTime = SWITCH_TO_MTP_BLOCK_HEADER - 2*60; // 2 hours leeway
        consensus.vDeployments[Consensus::DEPLOYMENT_MTP].nTimeout = SWITCH_TO_MTP_BLOCK_HEADER + consensus.nMinerConfirmationWindow*2 * 5*60;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000708f98bf623f02e");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("50aff78270725ec253a722ec18069deb233f2e57eb7d64479f027141619cdda4 "); //184200

        consensus.nCheckBugFixedAtBlock = ZC_CHECK_BUG_FIXED_AT_BLOCK;
        consensus.nZnodePaymentsBugFixedAtBlock = ZC_ZNODE_PAYMENT_BUG_FIXED_AT_BLOCK;
	    consensus.nSpendV15StartBlock = ZC_V1_5_STARTING_BLOCK;
	    consensus.nSpendV2ID_1 = ZC_V2_SWITCH_ID_1;
	    consensus.nSpendV2ID_10 = ZC_V2_SWITCH_ID_10;
	    consensus.nSpendV2ID_25 = ZC_V2_SWITCH_ID_25;
	    consensus.nSpendV2ID_50 = ZC_V2_SWITCH_ID_50;
	    consensus.nSpendV2ID_100 = ZC_V2_SWITCH_ID_100;
	    consensus.nModulusV2StartBlock = ZC_MODULUS_V2_START_BLOCK;
        consensus.nModulusV1MempoolStopBlock = ZC_MODULUS_V1_MEMPOOL_STOP_BLOCK;
	    consensus.nModulusV1StopBlock = ZC_MODULUS_V1_STOP_BLOCK;
        consensus.nMultipleSpendInputsInOneTxStartBlock = ZC_MULTIPLE_SPEND_INPUT_STARTING_BLOCK;
        consensus.nDontAllowDupTxsStartBlock = 119700;

        // znode params
        consensus.nZnodePaymentsStartBlock = HF_ZNODE_PAYMENT_START; // not true, but it's ok as long as it's less then nZnodePaymentsIncreaseBlock
        // consensus.nZnodePaymentsIncreaseBlock = 680000; // actual historical value // not used for now, probably later
        // consensus.nZnodePaymentsIncreasePeriod = 576*30; // 17280 - actual historical value // not used for now, probably later
        // consensus.nSuperblockStartBlock = 614820;
        // consensus.nBudgetPaymentsStartBlock = 328008; // actual historical value
        // consensus.nBudgetPaymentsCycleBlocks = 16616; // ~(60*24*30)/2.6, actual number of blocks per month is 200700 / 12 = 16725
        // consensus.nBudgetPaymentsWindowBlocks = 100;

        // evo znodes
        consensus.DIP0003Height = 278300; // Approximately June 22 2020, 12:00 UTC
        consensus.DIP0003EnforcementHeight = 284400; // Approximately July 13 2020, 12:00 UTC
        consensus.DIP0003EnforcementHash = uint256S("0x8b8d7c05bb2d75f8c5e076cb6c10ef464e94ddcda2744740db03aeda2d6cc006");
        consensus.DIP0008Height = 341100; // Approximately Jan 28 2021, 11:00 UTC
        consensus.nEvoZnodeMinimumConfirmations = 15;

        // long living quorum params
        consensus.llmqs[Consensus::LLMQ_50_60] = llmq50_60;
        consensus.llmqs[Consensus::LLMQ_400_60] = llmq400_60;
        consensus.llmqs[Consensus::LLMQ_400_85] = llmq400_85;
        consensus.nLLMQPowTargetSpacing = 5*60;
        consensus.llmqChainLocks = Consensus::LLMQ_400_60;
        consensus.llmqForInstantSend = Consensus::LLMQ_50_60;

        consensus.nMTPSwitchTime = SWITCH_TO_MTP_BLOCK_HEADER;
        consensus.nMTPStartBlock = 117564;
        consensus.nMTPFiveMinutesStartBlock = SWITCH_TO_MTP_5MIN_BLOCK;
        consensus.nDifficultyAdjustStartBlock = 0;
        consensus.nFixedDifficulty = 0x2000ffff;
        consensus.nPowTargetSpacingMTP = 5*60;
        consensus.nInitialMTPDifficulty = 0x1c021e57;
        consensus.nMTPRewardReduction = 2;

        consensus.nDisableZerocoinStartBlock = 157000;

        nMaxTipAge = 6 * 60 * 60; // ~144 blocks behind -> 2 x fork detection time, was 24 * 60 * 60 in bitcoin

        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 60*60; // fulfilled requests expire in 1 hour
        strZnodePaymentsPubKey = "04549ac134f694c0243f503e8c8a9a986f5de6610049c40b07816809b0d1d06a21b07be27b9bb555931773f62ba6cf35a25fd52f694d4e1106ccd237a7bb899fdd";

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
       `  * a large 32-bit integer with any alignment.
         */
        //btzc: update firo pchMessage
        pchMessageStart[0] = 0xe3;
        pchMessageStart[1] = 0xd9;
        pchMessageStart[2] = 0xfe;
        pchMessageStart[3] = 0xf1;
        nDefaultPort = 8168;
        nPruneAfterHeight = 100000;
        /**
         * btzc: firo init genesis block
         * nBits = 0x1e0ffff0
         * nTime = 1414776286
         * nNonce = 142392
         * genesisReward = 0 * COIN
         * nVersion = 2
         * extraNonce
         */
        std::vector<unsigned char> extraNonce(4);
        extraNonce[0] = 0x82;
        extraNonce[1] = 0x3f;
        extraNonce[2] = 0x00;
        extraNonce[3] = 0x00;
        genesis = CreateGenesisBlock(ZC_GENESIS_BLOCK_TIME, 142392, 0x1e0ffff0, 2, 0 * COIN, extraNonce);
        const std::string s = genesis.GetHash().ToString();
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x4381deb85b1b2c9843c222944b616d997516dcbd6a964e1eaf0def0830695233"));
        assert(genesis.hashMerkleRoot == uint256S("0x365d2aa75d061370c9aefdabac3985716b1e3b4bb7c4af4ed54f25e5aaa42783"));
        vSeeds.push_back(CDNSSeedData("amsterdam.firo.org", "amsterdam.firo.org", false));
        vSeeds.push_back(CDNSSeedData("australia.firo.org", "australia.firo.org", false));
        vSeeds.push_back(CDNSSeedData("chicago.firo.org", "chicago.firo.org", false));
        vSeeds.push_back(CDNSSeedData("london.firo.org", "london.firo.org", false));
        vSeeds.push_back(CDNSSeedData("frankfurt.firo.org", "frankfurt.firo.org", false));
        vSeeds.push_back(CDNSSeedData("newjersey.firo.org", "newjersey.firo.org", false));
        vSeeds.push_back(CDNSSeedData("sanfrancisco.firo.org", "sanfrancisco.firo.org", false));
        vSeeds.push_back(CDNSSeedData("tokyo.firo.org", "tokyo.firo.org", false));
        vSeeds.push_back(CDNSSeedData("singapore.firo.org", "singapore.firo.org", false));
        // Note that of those with the service bits flag, most only support a subset of possible options
        base58Prefixes[PUBKEY_ADDRESS] = std::vector < unsigned char > (1, 82);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector < unsigned char > (1, 7);
        base58Prefixes[SECRET_KEY] = std::vector < unsigned char > (1, 210);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container < std::vector < unsigned char > > ();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container < std::vector < unsigned char > > ();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fAllowMultiplePorts = false;

        checkpointData = (CCheckpointData) {
                boost::assign::map_list_of
                (0, uint256S("0xf11046292ff76af48b66de6f1a210c09825d2ab4f56975ec507766ebf9c9f443"))
                (14000, uint256S("0xeab9b7e451284cb75ada7609e0220bee2b4f289fed9d9cf2a9e3aa548b2d38eb"))
                (14271, uint256S("0xf15088099a30f98e85a09789880f74cadca42f725c0cc1666484865539d2f335"))
                (20580, uint256S("0x591b00ac1ba7d30b9f440efc467072400805a900e92f04f272e6f70cb55ab026"))
                (121378, uint256S("0xa7d9a56dd2986442b5c10ad036eb4e6555eaa8d9f6645c7b9620597792a153ac"))
                (341100, uint256S("0x1ca6cbd9f6e13db8e0e1db0b77f8b1a037b01c69558214bc1ae2ce1f81da4890"))
        };

        chainTxData = ChainTxData{
                1545712287, // * UNIX timestamp of last checkpoint block
                933513,     // * total number of transactions between genesis and last checkpoint
                            //   (the tx=... number in the SetBestChain debug.log lines)
                0.014       // * estimated number of transactions per second after checkpoint
        };
        consensus.nSpendV15StartBlock = ZC_V1_5_STARTING_BLOCK;
        consensus.nSpendV2ID_1 = ZC_V2_SWITCH_ID_1;
        consensus.nSpendV2ID_10 = ZC_V2_SWITCH_ID_10;
        consensus.nSpendV2ID_25 = ZC_V2_SWITCH_ID_25;
        consensus.nSpendV2ID_50 = ZC_V2_SWITCH_ID_50;
        consensus.nSpendV2ID_100 = ZC_V2_SWITCH_ID_100;
        consensus.nModulusV2StartBlock = ZC_MODULUS_V2_START_BLOCK;
        consensus.nModulusV1MempoolStopBlock = ZC_MODULUS_V1_MEMPOOL_STOP_BLOCK;
        consensus.nModulusV1StopBlock = ZC_MODULUS_V1_STOP_BLOCK;

        // Sigma related values.
        consensus.nSigmaStartBlock = ZC_SIGMA_STARTING_BLOCK;
        consensus.nSigmaPaddingBlock = ZC_SIGMA_PADDING_BLOCK;
        consensus.nDisableUnpaddedSigmaBlock = ZC_SIGMA_DISABLE_UNPADDED_BLOCK;
        consensus.nStartSigmaBlacklist = 293790;
        consensus.nRestartSigmaWithBlacklistCheck = 296900;
        consensus.nOldSigmaBanBlock = ZC_OLD_SIGMA_BAN_BLOCK;
        consensus.nLelantusStartBlock = ZC_LELANTUS_STARTING_BLOCK;
        consensus.nLelantusFixesStartBlock = ZC_LELANTUS_FIXES_START_BLOCK;
        consensus.nZerocoinV2MintMempoolGracefulPeriod = ZC_V2_MINT_GRACEFUL_MEMPOOL_PERIOD;
        consensus.nZerocoinV2MintGracefulPeriod = ZC_V2_MINT_GRACEFUL_PERIOD;
        consensus.nZerocoinV2SpendMempoolGracefulPeriod = ZC_V2_SPEND_GRACEFUL_MEMPOOL_PERIOD;
        consensus.nZerocoinV2SpendGracefulPeriod = ZC_V2_SPEND_GRACEFUL_PERIOD;
        consensus.nMaxSigmaInputPerBlock = ZC_SIGMA_INPUT_LIMIT_PER_BLOCK;
        consensus.nMaxValueSigmaSpendPerBlock = ZC_SIGMA_VALUE_SPEND_LIMIT_PER_BLOCK;
        consensus.nMaxSigmaInputPerTransaction = ZC_SIGMA_INPUT_LIMIT_PER_TRANSACTION;
        consensus.nMaxValueSigmaSpendPerTransaction = ZC_SIGMA_VALUE_SPEND_LIMIT_PER_TRANSACTION;
        consensus.nMaxLelantusInputPerBlock = ZC_LELANTUS_INPUT_LIMIT_PER_BLOCK;
        consensus.nMaxValueLelantusSpendPerBlock = ZC_LELANTUS_VALUE_SPEND_LIMIT_PER_BLOCK;
        consensus.nMaxLelantusInputPerTransaction = ZC_LELANTUS_INPUT_LIMIT_PER_TRANSACTION;
        consensus.nMaxValueLelantusSpendPerTransaction = ZC_LELANTUS_VALUE_SPEND_LIMIT_PER_TRANSACTION;
        consensus.nMaxValueLelantusMint = ZC_LELANTUS_MAX_MINT;
        consensus.nZerocoinToSigmaRemintWindowSize = 50000;

        for (const auto& str : lelantus::lelantus_blacklist) {
            GroupElement coin;
            coin.deserialize(ParseHex(str).data());
            consensus.lelantusBlacklist.insert(coin);
        }

        for (const auto& str : sigma::sigma_blacklist) {
            GroupElement coin;
            coin.deserialize(ParseHex(str).data());
            consensus.sigmaBlacklist.insert(coin);
        }

        consensus.evoSporkKeyID = "a78fERshquPsTv2TuKMSsxTeKom56uBwLP";
        consensus.nEvoSporkStartBlock = ZC_LELANTUS_STARTING_BLOCK;
        consensus.nEvoSporkStopBlock = ZC_LELANTUS_STARTING_BLOCK + 24*12*365;  // one year after lelantus

        // reorg
        consensus.nMaxReorgDepth = 5;
        consensus.nMaxReorgDepthEnforcementBlock = 338000;

        // whitelist
        consensus.txidWhitelist.insert(uint256S("3ecea345c7b174271bbdcde8cad6097d9a3dc420259743d52cc9cf1945aaba03"));

        // Dandelion related values.
        consensus.nDandelionEmbargoMinimum = DANDELION_EMBARGO_MINIMUM;
        consensus.nDandelionEmbargoAvgAdd = DANDELION_EMBARGO_AVG_ADD;
        consensus.nDandelionMaxDestinations = DANDELION_MAX_DESTINATIONS;
        consensus.nDandelionShuffleInterval = DANDELION_SHUFFLE_INTERVAL;
        consensus.nDandelionFluff = DANDELION_FLUFF;

        // Bip39
        consensus.nMnemonicBlock = 222400;

        // moving lelantus data to v3 payload
        consensus.nLelantusV3PayloadStartBlock = 400000;
    }
    virtual bool SkipUndoForBlock(int nHeight) const
    {
        return nHeight == 293526;
    }
    virtual bool ApplyUndoForTxout(int nHeight, uint256 const & txid, int n) const
    {
        // We only apply first 23 tx inputs UNDOs for the tx 7702 in block 293526
        if (!SkipUndoForBlock(nHeight)) {
            return true;
        }
        static std::map<uint256, int> const txs = { {uint256S("7702eaa0e042846d39d01eeb4c87f774913022e9958cfd714c5c2942af380569"), 22} };
        std::map<uint256, int>::const_iterator const itx = txs.find(txid);
        if (itx == txs.end()) {
            return false;
        }
        if (n <= itx->second) {
            return true;
        }
        return false;
    }
};

static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";

        consensus.chainType = Consensus::chainTestnet;

        consensus.nSubsidyHalvingFirst = 12000;
        consensus.nSubsidyHalvingInterval = 100000;
        consensus.nSubsidyHalvingStopBlock = 1000000;

        consensus.stage2DevelopmentFundShare = 15;
        consensus.stage2ZnodeShare = 35;
        consensus.stage2DevelopmentFundAddress = "TUuKypsbbnHHmZ2auC2BBWfaP1oTEnxjK2";

        consensus.nStartBlacklist = 0;
        consensus.nStartDuplicationCheck = 0;
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 100;
        consensus.nMinNFactor = 10;
        consensus.nMaxNFactor = 30;
        consensus.nChainStartTime = 1389306217;
        consensus.BIP34Height = 21111;
        consensus.BIP34Hash = uint256S("0x0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8");
        consensus.powLimit = uint256S("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 60 * 60; // 60 minutes between retargets
        consensus.nPowTargetSpacing = 5 * 60; // 5 minute blocks
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1456790400; // March 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1462060800; // May 1st 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1493596800; // May 1st 2017

        // Deployment of MTP
        consensus.vDeployments[Consensus::DEPLOYMENT_MTP].bit = 12;
        consensus.vDeployments[Consensus::DEPLOYMENT_MTP].nStartTime = 1539172800 - 2*60;
        consensus.vDeployments[Consensus::DEPLOYMENT_MTP].nTimeout = 1539172800 + consensus.nMinerConfirmationWindow*2 * 5*60;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000708f98bf623f02e");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("3825896ac39b8b27220e7bfaed81c5f979ca11dc874e564c5e70756ad06077b0 "); // 50000

        consensus.nSpendV15StartBlock = 5000;
        consensus.nCheckBugFixedAtBlock = 1;
        consensus.nZnodePaymentsBugFixedAtBlock = 1;

        consensus.nSpendV2ID_1 = ZC_V2_TESTNET_SWITCH_ID_1;
        consensus.nSpendV2ID_10 = ZC_V2_TESTNET_SWITCH_ID_10;
        consensus.nSpendV2ID_25 = ZC_V2_TESTNET_SWITCH_ID_25;
        consensus.nSpendV2ID_50 = ZC_V2_TESTNET_SWITCH_ID_50;
        consensus.nSpendV2ID_100 = ZC_V2_TESTNET_SWITCH_ID_100;
        consensus.nModulusV2StartBlock = ZC_MODULUS_V2_TESTNET_START_BLOCK;
        consensus.nModulusV1MempoolStopBlock = ZC_MODULUS_V1_TESTNET_MEMPOOL_STOP_BLOCK;
        consensus.nModulusV1StopBlock = ZC_MODULUS_V1_TESTNET_STOP_BLOCK;
        consensus.nMultipleSpendInputsInOneTxStartBlock = 1;
        consensus.nDontAllowDupTxsStartBlock = 1;

        // Znode params testnet
        consensus.nZnodePaymentsStartBlock = 2200;
        //consensus.nZnodePaymentsIncreaseBlock = 360; // not used for now, probably later
        //consensus.nZnodePaymentsIncreasePeriod = 650; // not used for now, probably later
        //consensus.nSuperblockStartBlock = 61000;
        //consensus.nBudgetPaymentsStartBlock = 60000;
        //consensus.nBudgetPaymentsCycleBlocks = 50;
        //consensus.nBudgetPaymentsWindowBlocks = 10;
        nMaxTipAge = 0x7fffffff; // allow mining on top of old blocks for testnet

        // evo znodes
        consensus.DIP0003Height = 3340;
        consensus.DIP0003EnforcementHeight = 3800;
        consensus.DIP0003EnforcementHash.SetNull();

        consensus.DIP0008Height = 25000;
        consensus.nEvoZnodeMinimumConfirmations = 0;

        // long living quorum params
        consensus.llmqs[Consensus::LLMQ_10_70] = llmq10_70;
        consensus.llmqs[Consensus::LLMQ_50_60] = llmq50_60;
        consensus.llmqs[Consensus::LLMQ_400_60] = llmq400_60;
        consensus.llmqs[Consensus::LLMQ_400_85] = llmq400_85;
        consensus.nLLMQPowTargetSpacing = 20;
        consensus.llmqChainLocks = Consensus::LLMQ_10_70;
        consensus.llmqForInstantSend = Consensus::LLMQ_10_70;

        consensus.nMTPSwitchTime = 1539172800;
        consensus.nMTPStartBlock = 1;
        consensus.nMTPFiveMinutesStartBlock = 0;
        consensus.nDifficultyAdjustStartBlock = 100;
        consensus.nFixedDifficulty = 0x2000ffff;
        consensus.nPowTargetSpacingMTP = 5*60;
        consensus.nInitialMTPDifficulty = 0x2000ffff;  // !!!! change it to the real value
        consensus.nMTPRewardReduction = 2;

        consensus.nDisableZerocoinStartBlock = 1;

        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes
        strZnodePaymentsPubKey = "046f78dcf911fbd61910136f7f0f8d90578f68d0b3ac973b5040fb7afb501b5939f39b108b0569dca71488f5bbf498d92e4d1194f6f941307ffd95f75e76869f0e";

        pchMessageStart[0] = 0xcf;
        pchMessageStart[1] = 0xfc;
        pchMessageStart[2] = 0xbe;
        pchMessageStart[3] = 0xea;
        nDefaultPort = 18168;
        nPruneAfterHeight = 1000;
        /**
         * btzc: testnet params
         * nTime: 1414776313
         * nNonce: 1620571
         */
        std::vector<unsigned char> extraNonce(4);
        extraNonce[0] = 0x09;
        extraNonce[1] = 0x00;
        extraNonce[2] = 0x00;
        extraNonce[3] = 0x00;

        genesis = CreateGenesisBlock(ZC_GENESIS_BLOCK_TIME, 3577337, 0x1e0ffff0, 2, 0 * COIN, extraNonce);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock ==
                uint256S("0xaa22adcc12becaf436027ffe62a8fb21b234c58c23865291e5dc52cf53f64fca"));
        assert(genesis.hashMerkleRoot ==
                uint256S("0xf70dba2d976778b985de7b5503ede884988d78fbb998d6969e4f676b40b9a741"));
        vFixedSeeds.clear();
        vSeeds.clear();
        // firo test seeds

        vSeeds.push_back(CDNSSeedData("EVO1", "evo1.firo.org", false));
        vSeeds.push_back(CDNSSeedData("EVO2", "evo2.firo.org", false));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector < unsigned char > (1, 65);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector < unsigned char > (1, 178);
        base58Prefixes[SECRET_KEY] = std::vector < unsigned char > (1, 185);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container < std::vector < unsigned char > > ();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container < std::vector < unsigned char > > ();
        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fAllowMultiplePorts = true;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (0, uint256S("0x"))
        };

        chainTxData = ChainTxData{
            1414776313,
            0,
            0.001
        };

        consensus.nSpendV15StartBlock = ZC_V1_5_TESTNET_STARTING_BLOCK;
        consensus.nSpendV2ID_1 = ZC_V2_TESTNET_SWITCH_ID_1;
        consensus.nSpendV2ID_10 = ZC_V2_TESTNET_SWITCH_ID_10;
        consensus.nSpendV2ID_25 = ZC_V2_TESTNET_SWITCH_ID_25;
        consensus.nSpendV2ID_50 = ZC_V2_TESTNET_SWITCH_ID_50;
        consensus.nSpendV2ID_100 = ZC_V2_TESTNET_SWITCH_ID_100;
        consensus.nModulusV2StartBlock = ZC_MODULUS_V2_TESTNET_START_BLOCK;
        consensus.nModulusV1MempoolStopBlock = ZC_MODULUS_V1_TESTNET_MEMPOOL_STOP_BLOCK;
        consensus.nModulusV1StopBlock = ZC_MODULUS_V1_TESTNET_STOP_BLOCK;

        // Sigma related values.
        consensus.nSigmaStartBlock = 1;
        consensus.nSigmaPaddingBlock = 1;
        consensus.nDisableUnpaddedSigmaBlock = 1;
        consensus.nStartSigmaBlacklist = INT_MAX;
        consensus.nRestartSigmaWithBlacklistCheck = INT_MAX;
        consensus.nOldSigmaBanBlock = 1;

        consensus.nLelantusStartBlock = ZC_LELANTUS_TESTNET_STARTING_BLOCK;
        consensus.nLelantusFixesStartBlock = ZC_LELANTUS_TESTNET_FIXES_START_BLOCK;

        consensus.nZerocoinV2MintMempoolGracefulPeriod = ZC_V2_MINT_TESTNET_GRACEFUL_MEMPOOL_PERIOD;
        consensus.nZerocoinV2MintGracefulPeriod = ZC_V2_MINT_TESTNET_GRACEFUL_PERIOD;
        consensus.nZerocoinV2SpendMempoolGracefulPeriod = ZC_V2_SPEND_TESTNET_GRACEFUL_MEMPOOL_PERIOD;
        consensus.nZerocoinV2SpendGracefulPeriod = ZC_V2_SPEND_TESTNET_GRACEFUL_PERIOD;
        consensus.nMaxSigmaInputPerBlock = ZC_SIGMA_INPUT_LIMIT_PER_BLOCK;
        consensus.nMaxValueSigmaSpendPerBlock = ZC_SIGMA_VALUE_SPEND_LIMIT_PER_BLOCK;
        consensus.nMaxSigmaInputPerTransaction = ZC_SIGMA_INPUT_LIMIT_PER_TRANSACTION;
        consensus.nMaxValueSigmaSpendPerTransaction = ZC_SIGMA_VALUE_SPEND_LIMIT_PER_TRANSACTION;
        consensus.nMaxLelantusInputPerBlock = ZC_LELANTUS_INPUT_LIMIT_PER_BLOCK;
        consensus.nMaxValueLelantusSpendPerBlock = 1100 * COIN;
        consensus.nMaxLelantusInputPerTransaction = ZC_LELANTUS_INPUT_LIMIT_PER_TRANSACTION;
        consensus.nMaxValueLelantusSpendPerTransaction = 1001 * COIN;
        consensus.nMaxValueLelantusMint = 1001 * COIN;
        consensus.nZerocoinToSigmaRemintWindowSize = 0;

        for (const auto& str : lelantus::lelantus_testnet_blacklist) {
            GroupElement coin;
            coin.deserialize(ParseHex(str).data());
            consensus.lelantusBlacklist.insert(coin);
        }

        consensus.evoSporkKeyID = "TWSEa1UsZzDHywDG6CZFDNdeJU6LzhbbBL";
        consensus.nEvoSporkStartBlock = 22000;
        consensus.nEvoSporkStopBlock = 40000;

        // reorg
        consensus.nMaxReorgDepth = 4;
        consensus.nMaxReorgDepthEnforcementBlock = 25150;

        // whitelist
        consensus.txidWhitelist.insert(uint256S("44b3829117bd248544c71b430d585cb88b4ce156a7d4fdb9ef3ae96efa8f09d3"));

        // Dandelion related values.
        consensus.nDandelionEmbargoMinimum = DANDELION_TESTNET_EMBARGO_MINIMUM;
        consensus.nDandelionEmbargoAvgAdd = DANDELION_TESTNET_EMBARGO_AVG_ADD;
        consensus.nDandelionMaxDestinations = DANDELION_MAX_DESTINATIONS;
        consensus.nDandelionShuffleInterval = DANDELION_SHUFFLE_INTERVAL;
        consensus.nDandelionFluff = DANDELION_FLUFF;

        // Bip39
        consensus.nMnemonicBlock = 1;

        // moving lelantus data to v3 payload
        consensus.nLelantusV3PayloadStartBlock = 35000;
    }
};

static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";

        consensus.chainType = Consensus::chainRegtest;

        // To be changed for specific tests
        consensus.nSubsidyHalvingFirst = 302438;
        consensus.nSubsidyHalvingInterval = 420000;
        consensus.nSubsidyHalvingStopBlock = 3646849;

        consensus.nStartBlacklist = 0;
        consensus.nStartDuplicationCheck = 0;
        consensus.stage2DevelopmentFundShare = 15;
        consensus.stage2ZnodeShare = 35;

        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.BIP34Height = -1; // BIP34 has not necessarily activated on regtest
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 60 * 60 * 1000; // 60 minutes between retargets
        consensus.nPowTargetSpacing = 1; // 10 minute blocks
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nZnodePaymentsStartBlock = 120;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = INT_MAX;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_MTP].bit = 12;
        consensus.vDeployments[Consensus::DEPLOYMENT_MTP].nStartTime = INT_MAX;
        consensus.vDeployments[Consensus::DEPLOYMENT_MTP].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");
        // Znode code
        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes
        nMaxTipAge = 6 * 60 * 60; // ~144 blocks behind -> 2 x fork detection time, was 24 * 60 * 60 in bitcoin

        consensus.nCheckBugFixedAtBlock = 120;
        consensus.nZnodePaymentsBugFixedAtBlock = 1;
        consensus.nSpendV15StartBlock = 1;
        consensus.nSpendV2ID_1 = 2;
        consensus.nSpendV2ID_10 = 3;
        consensus.nSpendV2ID_25 = 3;
        consensus.nSpendV2ID_50 = 3;
        consensus.nSpendV2ID_100 = 3;
        consensus.nModulusV2StartBlock = 130;
        consensus.nModulusV1MempoolStopBlock = 135;
        consensus.nModulusV1StopBlock = 140;
        consensus.nMultipleSpendInputsInOneTxStartBlock = 1;
        consensus.nDontAllowDupTxsStartBlock = 1;

        // evo znodes
        consensus.DIP0003Height = 500;
        consensus.DIP0003EnforcementHeight = 550;
        consensus.DIP0003EnforcementHash.SetNull();

        consensus.DIP0008Height = 550;
        consensus.nEvoZnodeMinimumConfirmations = 1;

        // long living quorum params
        consensus.llmqs[Consensus::LLMQ_5_60] = llmq5_60;
        consensus.llmqs[Consensus::LLMQ_50_60] = llmq50_60;
        consensus.llmqs[Consensus::LLMQ_400_60] = llmq400_60;
        consensus.llmqs[Consensus::LLMQ_400_85] = llmq400_85;
        consensus.nLLMQPowTargetSpacing = 1;
        consensus.llmqChainLocks = Consensus::LLMQ_5_60;
        consensus.llmqForInstantSend = Consensus::LLMQ_5_60;

        consensus.nMTPSwitchTime = INT_MAX;
        consensus.nMTPStartBlock = 0;
        consensus.nMTPFiveMinutesStartBlock = 0;
        consensus.nDifficultyAdjustStartBlock = 5000;
        consensus.nFixedDifficulty = 0x207fffff;
        consensus.nPowTargetSpacingMTP = 5*60;
        consensus.nInitialMTPDifficulty = 0x2070ffff;  // !!!! change it to the real value
        consensus.nMTPRewardReduction = 2;

        consensus.nDisableZerocoinStartBlock = INT_MAX;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 18444;
        nPruneAfterHeight = 1000;

        /**
          * btzc: testnet params
          * nTime: 1414776313
          * nNonce: 1620571
          */
        std::vector<unsigned char> extraNonce(4);
        extraNonce[0] = 0x08;
        extraNonce[1] = 0x00;
        extraNonce[2] = 0x00;
        extraNonce[3] = 0x00;
        genesis = CreateGenesisBlock(ZC_GENESIS_BLOCK_TIME, 414098459, 0x207fffff, 1, 0 * COIN, extraNonce);
        consensus.hashGenesisBlock = genesis.GetHash();

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fAllowMultiplePorts = true;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (0, uint256S("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"))
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };
        base58Prefixes[PUBKEY_ADDRESS] = std::vector < unsigned char > (1, 65);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector < unsigned char > (1, 178);
        base58Prefixes[SECRET_KEY] = std::vector < unsigned char > (1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container < std::vector < unsigned char > > ();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container < std::vector < unsigned char > > ();

        nSpendV15StartBlock = ZC_V1_5_TESTNET_STARTING_BLOCK;
        nSpendV2ID_1 = ZC_V2_TESTNET_SWITCH_ID_1;
        nSpendV2ID_10 = ZC_V2_TESTNET_SWITCH_ID_10;
        nSpendV2ID_25 = ZC_V2_TESTNET_SWITCH_ID_25;
        nSpendV2ID_50 = ZC_V2_TESTNET_SWITCH_ID_50;
        nSpendV2ID_100 = ZC_V2_TESTNET_SWITCH_ID_100;
        nModulusV2StartBlock = ZC_MODULUS_V2_TESTNET_START_BLOCK;
        nModulusV1MempoolStopBlock = ZC_MODULUS_V1_TESTNET_MEMPOOL_STOP_BLOCK;
        nModulusV1StopBlock = ZC_MODULUS_V1_TESTNET_STOP_BLOCK;

        // Sigma related values.
        consensus.nSigmaStartBlock = 100;
        consensus.nSigmaPaddingBlock = 1;
        consensus.nDisableUnpaddedSigmaBlock = 1;
        consensus.nStartSigmaBlacklist = INT_MAX;
        consensus.nRestartSigmaWithBlacklistCheck = INT_MAX;
        consensus.nOldSigmaBanBlock = 1;
        consensus.nLelantusStartBlock = 400;
        consensus.nLelantusFixesStartBlock = 400;
        consensus.nZerocoinV2MintMempoolGracefulPeriod = 1;
        consensus.nZerocoinV2MintGracefulPeriod = 1;
        consensus.nZerocoinV2SpendMempoolGracefulPeriod = 1;
        consensus.nZerocoinV2SpendGracefulPeriod = 1;
        consensus.nMaxSigmaInputPerBlock = ZC_SIGMA_INPUT_LIMIT_PER_BLOCK;
        consensus.nMaxValueSigmaSpendPerBlock = ZC_SIGMA_VALUE_SPEND_LIMIT_PER_BLOCK;
        consensus.nMaxSigmaInputPerTransaction = ZC_SIGMA_INPUT_LIMIT_PER_TRANSACTION;
        consensus.nMaxValueSigmaSpendPerTransaction = ZC_SIGMA_VALUE_SPEND_LIMIT_PER_TRANSACTION;
        consensus.nMaxLelantusInputPerBlock = ZC_LELANTUS_INPUT_LIMIT_PER_BLOCK;
        consensus.nMaxValueLelantusSpendPerBlock = ZC_LELANTUS_VALUE_SPEND_LIMIT_PER_BLOCK;
        consensus.nMaxLelantusInputPerTransaction = ZC_LELANTUS_INPUT_LIMIT_PER_TRANSACTION;
        consensus.nMaxValueLelantusSpendPerTransaction = ZC_LELANTUS_VALUE_SPEND_LIMIT_PER_TRANSACTION;
        consensus.nMaxValueLelantusMint = ZC_LELANTUS_MAX_MINT;
        consensus.nZerocoinToSigmaRemintWindowSize = 1000;

        // evo spork
        consensus.evoSporkKeyID = "TSpmHGzQT4KJrubWa4N2CRmpA7wKMMWDg4";  // private key is cW2YM2xaeCaebfpKguBahUAgEzLXgSserWRuD29kSyKHq1TTgwRQ
        consensus.nEvoSporkStartBlock = 1000;
        consensus.nEvoSporkStopBlock = 1500;

        // reorg
        consensus.nMaxReorgDepth = 4;
        consensus.nMaxReorgDepthEnforcementBlock = 300;

        // Dandelion related values.
        consensus.nDandelionEmbargoMinimum = 0;
        consensus.nDandelionEmbargoAvgAdd = 1;
        consensus.nDandelionMaxDestinations = DANDELION_MAX_DESTINATIONS;
        consensus.nDandelionShuffleInterval = DANDELION_SHUFFLE_INTERVAL;
        consensus.nDandelionFluff = DANDELION_FLUFF;

        // Bip39
        consensus.nMnemonicBlock = 0;

        // moving lelantus data to v3 payload
        consensus.nLelantusV3PayloadStartBlock = 1000;
    }

    void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
            return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
            return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
            return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

void UpdateRegtestBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    regTestParams.UpdateBIP9Parameters(d, nStartTime, nTimeout);
}

