#ifndef FIRO_PARAMS_H
#define FIRO_PARAMS_H

#define ZEROCOIN_MODULUS   "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357"
#define ZEROCOIN_MODULUS_V2 "C7970CEEDCC3B0754490201A7AA613CD73911081C790F5F1A8726F463550BB5B7FF0DB8E1EA1189EC72F93D1650011BD721AEEACC2ACDE32A04107F0648C2813A31F5B0B7765FF8B44B4B6FFC93384B646EB09C7CF5E8592D40EA33C80039F35B4F14A04B51F7BFD781BE4D1673164BA8EB991C2C4D730BBBE35F592BDEF524AF7E8DAEFD26C66FC02C479AF89D64D373F442709439DE66CEB955F3EA37D5159F6135809F85334B5CB1813ADDC80CD05609F10AC6A95AD65872C909525BDAD32BC729592642920F24C61DC5B3C3B7923E56B16A4D9D373D8721F24A3FC0F1B3131F55615172866BCCC30F95054C824E733A5EB6817F7BC16399D48C6361CC7E5"

/** Dust Soft Limit, allowed with additional fee per output */
//static const int64_t DUST_SOFT_LIMIT = 100000; // 0.001 FIRO
/** Dust Hard Limit, ignored as wallet inputs (mininput default) */
static const int64_t DUST_HARD_LIMIT = 1000;   // 0.00001 FIRO mininput

// There were bugs before this block, don't do some checks on early blocks
#define ZC_CHECK_BUG_FIXED_AT_BLOCK         61168

// Before this block we allowed not paying to the znodes.
#define ZC_ZNODE_PAYMENT_BUG_FIXED_AT_BLOCK         107246

// Do strict check on duplicate minted public coin value after this block
#define ZC_CHECK_DUPLICATE_MINT_AT_BLOCK    70000

// The mint id number to change to zerocoin v2
#define ZC_V2_SWITCH_ID_1 200
#define ZC_V2_SWITCH_ID_10 30
#define ZC_V2_SWITCH_ID_25 15
#define ZC_V2_SWITCH_ID_50 15
#define ZC_V2_SWITCH_ID_100 100

// Same for testnet
#define ZC_V2_TESTNET_SWITCH_ID_1 18
#define ZC_V2_TESTNET_SWITCH_ID_10 7
#define ZC_V2_TESTNET_SWITCH_ID_25 5
#define ZC_V2_TESTNET_SWITCH_ID_50 4
#define ZC_V2_TESTNET_SWITCH_ID_100 10

#define ZC_V1_5_STARTING_BLOCK          78500
#define ZC_V1_5_TESTNET_STARTING_BLOCK  37954

#define ZC_V1_5_GRACEFUL_MEMPOOL_PERIOD	500
#define ZC_V1_5_GRACEFUL_PERIOD			1500

// Block after which sigma mints are activated.
#define ZC_SIGMA_STARTING_BLOCK         184200 //Approx July 30th, 2019, 8:00 AM UTC
#define ZC_SIGMA_TESTNET_STARTING_BLOCK 50000

// Block after which anonymity sets are being padded.
#define ZC_SIGMA_PADDING_BLOCK         220720 //Approx December 5th 12PM UTC
#define ZC_SIGMA_TESTNET_PADDING_BLOCK 110000

//Block after whinch we are disabling sigma to enable after starting padding
#define ZC_SIGMA_DISABLE_UNPADDED_BLOCK         219904 //December 2nd 12PM UTC
#define ZC_SIGMA_TESTNET_DISABLE_UNPADDED_BLOCK 109160

// The block number after which old sigma clients are banned.
#define ZC_OLD_SIGMA_BAN_BLOCK          181850 //Approx July 22nd, 2019, 4:00 AM UTC

// Block after which lelantus mints are activated.
#define ZC_LELANTUS_STARTING_BLOCK         336888
#define ZC_LELANTUS_FIXES_START_BLOCK      365544 //Approx April 22, 20211, 2:00 PM UTC
#define ZC_LELANTUS_TESTNET_STARTING_BLOCK 15700
#define ZC_LELANTUS_TESTNET_FIXES_START_BLOCK   27600

// Number of blocks after ZC_SIGMA_STARTING_BLOCK during which we still accept zerocoin V2 mints into mempool.
#define ZC_V2_MINT_GRACEFUL_MEMPOOL_PERIOD          4500
#define ZC_V2_MINT_TESTNET_GRACEFUL_MEMPOOL_PERIOD  500

// Number of blocks after ZC_SIGMA_STARTING_BLOCK during which we still accept zerocoin V2 mints to newly mined blocks.
#define ZC_V2_MINT_GRACEFUL_PERIOD          5000
#define ZC_V2_MINT_TESTNET_GRACEFUL_PERIOD  1000

// Number of blocks after ZC_SIGMA_STARTING_BLOCK during which we still accept zerocoin V2 spends into mempool.
#define ZC_V2_SPEND_GRACEFUL_MEMPOOL_PERIOD         9000
#define ZC_V2_SPEND_TESTNET_GRACEFUL_MEMPOOL_PERIOD 1500

// Number of blocks after ZC_SIGMA_STARTING_BLOCK during which we still accept zerocoin V2 spends to newly mined blocks.
#define ZC_V2_SPEND_GRACEFUL_PERIOD         10000
#define ZC_V2_SPEND_TESTNET_GRACEFUL_PERIOD 2000

#define ZC_MODULUS_V2_START_BLOCK		89300
#define ZC_MODULUS_V1_MEMPOOL_STOP_BLOCK        89500
#define ZC_MODULUS_V1_STOP_BLOCK		89800

#define ZC_MODULUS_V2_TESTNET_START_BLOCK       87000
#define ZC_MODULUS_V1_TESTNET_MEMPOOL_STOP_BLOCK 87500
#define ZC_MODULUS_V1_TESTNET_STOP_BLOCK        88000

#define ZC_MODULUS_V2_BASE_ID			1000

#define ZC_MULTIPLE_SPEND_INPUT_STARTING_BLOCK  119000

// Number of coins per id in spend v1/v1.5
#define ZC_SPEND_V1_COINSPERID			10
// Number of coins per id in spend v2.0
#define ZC_SPEND_V2_COINSPERID			10000
// limit of coins number per id in spend v3.0
#define ZC_SPEND_V3_COINSPERID_LIMIT    16000

// limit of coins number per id in Lelantus
#define ZC_LELANTUS_MAX_MINT_NUM    65000
#define ZC_LELANTUS_SET_START_SIZE  16000

// Version of index that introduced storing accumulators and coin serials
#define ZC_ADVANCED_INDEX_VERSION           130500
// Version of wallet.db entry that introduced storing extra information for mints
#define ZC_ADVANCED_WALLETDB_MINT_VERSION	130504
// Version of the block index entry that introduces Lelantus protocol
#define LELANTUS_PROTOCOL_ENABLEMENT_VERSION	140100
// Version of the block index enty that introduces evo sporks
#define EVOSPORK_MIN_VERSION                140200

// number of mint confirmations needed to spend coin
#define ZC_MINT_CONFIRMATIONS               2

// Genesis block timestamp
#define ZC_GENESIS_BLOCK_TIME               1414776286

#define SWITCH_TO_MTP_BLOCK_HEADER 1544443200 // 2018 December 10th 12:00 UTC
#define SWITCH_TO_MTP_5MIN_BLOCK            118600

#define SWITCH_PROGPOW_BLOCK_HEADER 1617678362 // TODO set real switch time (actual is 2021 April 16th)

// Number of zerocoin spends allowed per block and per transaction
#define ZC_SPEND_LIMIT         5

// Value of sigma spends allowed per block
#define ZC_SIGMA_VALUE_SPEND_LIMIT_PER_BLOCK  (600 * COIN)

// Amount of sigma spends allowed per block
#define ZC_SIGMA_INPUT_LIMIT_PER_BLOCK         50

// Value of sigma spends allowed per transaction
#define ZC_SIGMA_VALUE_SPEND_LIMIT_PER_TRANSACTION     (500 * COIN)

// Amount of sigma spends allowed per transaction
#define ZC_SIGMA_INPUT_LIMIT_PER_TRANSACTION            35

// Value of lelantus spends allowed per block
#define ZC_LELANTUS_VALUE_SPEND_LIMIT_PER_BLOCK  (5100 * COIN)

// Amount of lelantus spends allowed per block
#define ZC_LELANTUS_INPUT_LIMIT_PER_BLOCK         100

// Value of lelantus spends allowed per transaction
#define ZC_LELANTUS_VALUE_SPEND_LIMIT_PER_TRANSACTION     (5001 * COIN)

// Amount of lelantus spends allowed per transaction
#define ZC_LELANTUS_INPUT_LIMIT_PER_TRANSACTION            50

// Maximum amount of lelantus mint
#define ZC_LELANTUS_MAX_MINT            (5001 * COIN)

// Number of zerocoin mints allowed per transaction
#define ZC_MINT_LIMIT         100

/** Maximum number of outbound peers designated as Dandelion destinations */
#define DANDELION_MAX_DESTINATIONS 2

/** Expected time between Dandelion routing shuffles (in seconds). */
#define DANDELION_SHUFFLE_INTERVAL 600

/** The minimum amount of time a Dandelion transaction is embargoed (seconds) */
#define DANDELION_EMBARGO_MINIMUM 10
#define DANDELION_TESTNET_EMBARGO_MINIMUM 1

/** The average additional embargo time beyond the minimum amount (seconds) */
#define DANDELION_EMBARGO_AVG_ADD 20
#define DANDELION_TESTNET_EMBARGO_AVG_ADD 1

/** Probability (percentage) that a Dandelion transaction enters fluff phase */
#define DANDELION_FLUFF 10

// Versions of zerocoin mint/spend transactions
#define ZEROCOIN_TX_VERSION_3               30
#define ZEROCOIN_TX_VERSION_3_1             31
#define LELANTUS_TX_VERSION_4               40
#define SIGMA_TO_LELANTUS_JOINSPLIT         41
#define LELANTUS_TX_VERSION_4_5             45
#define SIGMA_TO_LELANTUS_JOINSPLIT_FIXED   46
#define ZEROCOIN_PUBLICKEY_TO_SERIALNUMBER  "PUBLICKEY_TO_SERIALNUMBER"

#endif
