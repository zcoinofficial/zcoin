#include "../chainparams.h"
#include "../lelantus.h"
#include "../script/standard.h"
#include "../validation.h"
#include "../wallet/coincontrol.h"
#include "../wallet/wallet.h"
#include "../net.h"

#include "test_bitcoin.h"
#include "fixtures.h"
#include <iostream>
#include <boost/test/unit_test.hpp>

static bool CommitToMempool(const CTransaction &tx)
{
    CWallet *wallet = pwalletMain;
    CWalletTx walletTx(wallet, MakeTransactionRef(tx));
    CReserveKey reserveKey(wallet);
    CValidationState state;
    wallet->CommitTransaction(walletTx, reserveKey, g_connman.get(), state);
    return mempool.exists(tx.GetHash());
}

namespace lelantus {

struct JoinSplitScriptGenerator {
    Params const *params;
    std::vector<std::pair<PrivateCoin, uint32_t>> coins;
    std::map<uint32_t, std::vector<PublicCoin>> anons;
    CAmount vout;
    std::vector<PrivateCoin> coinsOut;
    CAmount fee;
    std::map<uint32_t, uint256> groupBlockHashes;
    uint256 txHash;

    std::pair<CScript, JoinSplit> Get() {
        // auto p = params ? params : Params::get_default();
        auto p = Params::get_default();

        CScript script;

        JoinSplit joinSplit(p, coins, anons, {}, vout, coinsOut, fee, groupBlockHashes, txHash, LELANTUS_TX_VERSION_4);

        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << joinSplit;

        script << OP_LELANTUSJOINSPLIT;
        script.insert(script.end(), ss.begin(), ss.end());

        return {script, joinSplit};
    }
};

class LelantusTests : public LelantusTestingSetup {
public:
    LelantusTests() :
        LelantusTestingSetup(),
        lelantusState(CLelantusState::GetState()),
        consensus(::Params().GetConsensus()) {
    }

    ~LelantusTests() {
        lelantusState->Reset();
    }

public:

    std::vector<PublicCoin> ExtractCoins(std::vector<PrivateCoin> const &coins) {
        std::vector<PublicCoin> pubs;
        pubs.reserve(coins.size());

        for (auto &c : coins) {
            pubs.push_back(c.getPublicCoin());
        }

        return pubs;
    }

    void ExtractJoinSplit(CMutableTransaction const &tx,
        std::vector<PublicCoin> &newMints,
        std::vector<Scalar> &serials) {
        for (auto const &in : tx.vin) {
            if (in.IsLelantusJoinSplit()) {
                auto js = ParseLelantusJoinSplit(tx);
                auto const &s = js->getCoinSerialNumbers();
                serials.insert(serials.end(), s.begin(), s.end());
            }
        }

        for (auto const &out : tx.vout) {
            if (out.scriptPubKey.IsLelantusJMint()) {
                GroupElement coin;
                ParseLelantusMintScript(out.scriptPubKey, coin);

                newMints.push_back(coin);
            }
        }
    }

    CBlock GetCBlock(CBlockIndex const *blockIdx) {
        CBlock block;
        if (!ReadBlockFromDisk(block, blockIdx, ::Params().GetConsensus())) {
            throw std::invalid_argument("No block index data");
        }

        return block;
    }

    void PopulateLelantusTxInfo(
        CBlock &block,
        std::vector<std::pair<lelantus::PublicCoin, std::pair<uint64_t, uint256>>> const &mints,
        std::vector<std::pair<Scalar, int>> const &serials) {
        block.lelantusTxInfo = std::make_shared<lelantus::CLelantusTxInfo>();
        block.lelantusTxInfo->mints.insert(block.lelantusTxInfo->mints.end(), mints.begin(), mints.end());

        for (auto const &s : serials) {
            block.lelantusTxInfo->spentSerials.emplace(s);
        }

        block.lelantusTxInfo->Complete();
    }

    CTransaction GenerateJoinSplit(
        std::vector<CAmount> const &outs,
        std::vector<CAmount> const &mints,
        CCoinControl const *coinControl = nullptr) {

        std::vector<CRecipient> vecs;
        for (auto const &out : outs) {
            LOCK(pwalletMain->cs_wallet);
            auto pub = pwalletMain->GenerateNewKey();

            vecs.push_back(
            {
                GetScriptForDestination(pub.GetID()),
                out,
                false
            });
        }

        std::vector<CLelantusEntry>  spendCoins;
        std::vector<CSigmaEntry> sigmaSpendCoins;
        std::vector<CHDMint> mintCoins;

        CAmount fee;
        auto result = pwalletMain->CreateLelantusJoinSplitTransaction(
            vecs, fee, mints, spendCoins, sigmaSpendCoins, mintCoins, coinControl);

        if (!pwalletMain->CommitLelantusTransaction(
            result, spendCoins, sigmaSpendCoins, mintCoins)) {
            throw std::runtime_error("Fail to commit transaction");
        }

        return result;
    }

public:
    CLelantusState *lelantusState;
    Consensus::Params const &consensus;
};

BOOST_FIXTURE_TEST_SUITE(lelantus_tests, LelantusTests)

BOOST_AUTO_TEST_CASE(schnorr_proof)
{
    auto params = Params::get_default();

    PrivateCoin coin(params, 1);

    CDataStream  serializedSchnorrProof(SER_NETWORK, PROTOCOL_VERSION);
    GenerateMintSchnorrProof(coin, serializedSchnorrProof);

    auto commitment = coin.getPublicCoin();
    SchnorrProof proof;
    serializedSchnorrProof >> proof;

    BOOST_CHECK(VerifyMintSchnorrProof(1, commitment.getValue(), proof));
}

BOOST_AUTO_TEST_CASE(is_lelantus_allowed)
{
    auto start = ::Params().GetConsensus().nLelantusStartBlock;
    BOOST_CHECK(!IsLelantusAllowed(0));
    BOOST_CHECK(!IsLelantusAllowed(start - 1));
    BOOST_CHECK(IsLelantusAllowed(start));
    BOOST_CHECK(IsLelantusAllowed(start + 1));
}

BOOST_AUTO_TEST_CASE(parse_lelantus_mintscript)
{
    // payload: op_code + pubcoin + schnorrproof
    PrivateCoin priv(params, 1);
    auto &pub = priv.getPublicCoin();

    CDataStream  proofSerialized(SER_NETWORK, PROTOCOL_VERSION);

    GenerateMintSchnorrProof(priv, proofSerialized);

    CScript script(OP_LELANTUSMINT);

    auto vch = pub.getValue().getvch();
    script.insert(script.end(), vch.begin(), vch.end());
    script.insert(script.end(), proofSerialized.begin(), proofSerialized.end());

    // verify
    secp_primitives::GroupElement parsedCoin;
    ParseLelantusMintScript(script, parsedCoin);

    BOOST_CHECK(pub.getValue() == parsedCoin);

    SchnorrProof proof;
    uint256 mintTag;
    ParseLelantusMintScript(script, parsedCoin, proof, mintTag);

    BOOST_CHECK(pub.getValue() == parsedCoin);
    BOOST_CHECK(VerifyMintSchnorrProof(1, parsedCoin, proof));

    CDataStream  parsedProof(SER_NETWORK, PROTOCOL_VERSION);
    parsedProof << proof;

    BOOST_CHECK(proofSerialized.vch == parsedProof.vch);

    GroupElement parsedCoin2;
    ParseLelantusMintScript(script, parsedCoin2);

    BOOST_CHECK(pub.getValue() == parsedCoin2);

    script.resize(script.size() - 1);
    BOOST_CHECK_THROW(ParseLelantusMintScript(script, parsedCoin, proof, mintTag), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(parse_lelantus_jmint)
{
    GroupElement val;
    val.randomize();

    CScript script(OP_LELANTUSJMINT);

    auto vch = val.getvch();
    script.insert(script.end(), vch.begin(), vch.end());

    std::vector<unsigned char> encrypted;
    encrypted.resize(16);

    std::fill(encrypted.begin(), encrypted.end(), 0xff);
    script.insert(script.end(), encrypted.begin(), encrypted.end());

    // parse and verify
    GroupElement outCoin;
    std::vector<unsigned char> outEnc;
    ParseLelantusJMintScript(script, outCoin, outEnc);

    BOOST_CHECK(val == outCoin);
    BOOST_CHECK(encrypted == outEnc);

    GroupElement outCoin2;
    ParseLelantusMintScript(script, outCoin2);

    BOOST_CHECK(val == outCoin2);

    // parse invalid
    script.resize(script.size() - 1);
    BOOST_CHECK_THROW(ParseLelantusJMintScript(script, outCoin, outEnc), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(get_outpoint)
{
    GenerateBlocks(110);

    // generate mints
    std::vector<CMutableTransaction> txs;
    auto mints = GenerateMints({2, 10}, txs);
    auto mint = mints[0];
    auto nonCommitted = mints[1];
    auto tx = txs[0];
    size_t mintIdx = 0;
    for (; mintIdx < tx.vout.size(); mintIdx++) {
        if (tx.vout[mintIdx].scriptPubKey.IsLelantusMint()) {
            break;
        }
    }

    auto blockIdx = GenerateBlock({txs[0]});

    CBlock block;
    BOOST_CHECK(ReadBlockFromDisk(block, blockIdx, ::Params().GetConsensus()));

    block.lelantusTxInfo = std::make_shared<lelantus::CLelantusTxInfo>();
    block.lelantusTxInfo->mints.emplace_back(std::make_pair(mint.GetPubcoinValue(), std::make_pair(mint.GetAmount(), uint256())));

    lelantusState->AddMintsToStateAndBlockIndex(blockIdx, &block);
    lelantusState->AddBlock(blockIdx);

    // verify
    COutPoint expectedOut(tx.GetHash(), mintIdx);

    // GetOutPointFromBlock
    COutPoint out;
    BOOST_CHECK(GetOutPointFromBlock(out, mint.GetPubcoinValue(), block));
    BOOST_CHECK(expectedOut == out);

    BOOST_CHECK(!GetOutPointFromBlock(out, nonCommitted.GetPubcoinValue(), block));

    // GetOutPoint
    // by pubcoin
    out = COutPoint();
    BOOST_CHECK(GetOutPoint(out, PublicCoin(mint.GetPubcoinValue())));
    BOOST_CHECK(expectedOut == out);

    BOOST_CHECK(!GetOutPoint(out, PublicCoin(nonCommitted.GetPubcoinValue())));

    // by pubcoin value
    out = COutPoint();
    BOOST_CHECK(GetOutPoint(out, mint.GetPubcoinValue()));
    BOOST_CHECK(expectedOut == out);

    BOOST_CHECK(!GetOutPoint(out, nonCommitted.GetPubcoinValue()));

    // by pubcoin hash
    out = COutPoint();
    BOOST_CHECK(GetOutPoint(out, mint.GetPubCoinHash()));
    BOOST_CHECK(expectedOut == out);

    BOOST_CHECK(!GetOutPoint(out, nonCommitted.GetPubCoinHash()));
}

BOOST_AUTO_TEST_CASE(build_lelantus_state)
{
    GenerateBlocks(110);

    // generate mints
    std::vector<CMutableTransaction> txs;
    auto mints = GenerateMints({1 * COIN, 2 * COIN, 10 * COIN, 100 * COIN}, txs);

    GenerateBlock({txs[0], txs[1]});
    auto blockIdx1 = chainActive.Tip();
    auto block1 = GetCBlock(blockIdx1);

    GenerateBlock({txs[2], txs[3]});
    auto blockIdx2 = chainActive.Tip();
    auto block2 = GetCBlock(blockIdx2);

    block1.lelantusTxInfo = std::make_shared<lelantus::CLelantusTxInfo>();
    block2.lelantusTxInfo = std::make_shared<lelantus::CLelantusTxInfo>();

    block1.lelantusTxInfo->mints.emplace_back(std::make_pair(mints[0].GetPubcoinValue(), std::make_pair(mints[0].GetAmount(), uint256())));
    block1.lelantusTxInfo->mints.emplace_back(std::make_pair(mints[1].GetPubcoinValue(), std::make_pair(mints[1].GetAmount(), uint256())));
    block1.lelantusTxInfo->mints.emplace_back(std::make_pair(mints[2].GetPubcoinValue(), std::make_pair(mints[2].GetAmount(), uint256())));
    block1.lelantusTxInfo->mints.emplace_back(std::make_pair(mints[3].GetPubcoinValue(), std::make_pair(mints[3].GetAmount(), uint256())));

    lelantusState->AddMintsToStateAndBlockIndex(blockIdx1, &block1);
    lelantusState->AddMintsToStateAndBlockIndex(blockIdx2, &block2);

    BOOST_CHECK(BuildLelantusStateFromIndex(&chainActive));
    BOOST_CHECK(lelantusState->HasCoin(mints[0].GetPubcoinValue()));
    BOOST_CHECK(lelantusState->HasCoin(mints[1].GetPubcoinValue()));
    BOOST_CHECK(lelantusState->HasCoin(mints[2].GetPubcoinValue()));
    BOOST_CHECK(lelantusState->HasCoin(mints[3].GetPubcoinValue()));
}

BOOST_AUTO_TEST_CASE(connect_and_disconnect_block)
{
    // util function
    auto reconnect = [](CBlock const &block) {
        LOCK(cs_main);

        std::shared_ptr<CBlock const> sharedBlock =
        std::make_shared<CBlock const>(block);

        CValidationState state;
        ActivateBestChain(state, ::Params(), sharedBlock);
    };

    GenerateBlocks(1000);

    std::vector<CMutableTransaction> mintTxs;
    auto hdMints = GenerateMints({3 * COIN, 3 * COIN, 3 * COIN}, mintTxs);

    struct {
        // expected state.
        std::vector<PublicCoin> coins;
        std::vector<Scalar> serials;

        // first group
        CBlockIndex *first = nullptr;
        CBlockIndex *last = nullptr;

        int lastId = 0;

        // real state
        CLelantusState *state;

        void Verify() const {
            auto const &spends = state->GetSpends();
            BOOST_CHECK_EQUAL(serials.size(), spends.size());
            for (auto const &s : serials) {
                BOOST_CHECK_MESSAGE(spends.count(s), "serial is not found on state");
            }

            auto const &mints = state->GetMints();
            BOOST_CHECK_EQUAL(coins.size(), mints.size());
            for (auto const &c : coins) {
                BOOST_CHECK_MESSAGE(mints.count(c), "public is not found on state");
            }

            auto retrievedId = state->GetLatestCoinID();

            CLelantusState::LelantusCoinGroupInfo group;
            state->GetCoinGroupInfo(retrievedId, group);
            BOOST_CHECK_EQUAL(lastId, retrievedId);
            BOOST_CHECK_EQUAL(first, group.firstBlock);
            BOOST_CHECK_EQUAL(last, group.lastBlock);
            BOOST_CHECK_EQUAL(coins.size(), group.nCoins);
        }
    } checker;
    checker.state = lelantusState;

    // Cache empty checker
    auto emptyChecker = checker;

    // Generate some txs which contain mints
    auto blockIdx1 = GenerateBlock({mintTxs[0], mintTxs[1]});
    BOOST_CHECK(blockIdx1);
    auto block1 = GetCBlock(blockIdx1);

    checker.coins.push_back(hdMints[0].GetPubcoinValue());
    checker.coins.push_back(hdMints[1].GetPubcoinValue());
    checker.first = blockIdx1;
    checker.last = blockIdx1;
    checker.lastId = 1;
    checker.Verify();

    // Generate empty blocks should not effect state
    GenerateBlocks(10);
    checker.Verify();

    // Add spend tx

    // Create two txs which contains same serial.
    CCoinControl coinControl;

    {
        auto tx = mintTxs[0];
        auto it = std::find_if(tx.vout.begin(), tx.vout.end(), [](CTxOut const &out) -> bool {
            return out.scriptPubKey.IsLelantusMint();
        });
        BOOST_CHECK(it != tx.vout.end());

        coinControl.Select(COutPoint(tx.GetHash(), std::distance(tx.vout.begin(), it)));
    }

    auto jsTx1 = GenerateJoinSplit({1 * COIN}, {}, &coinControl);

    // Update isused status
    {
        auto mint = hdMints[0];
        auto hash = primitives::GetPubCoinValueHash(mint.GetPubcoinValue());

        CLelantusMintMeta meta;
        BOOST_CHECK(pwalletMain->zwallet->GetTracker()
            .GetLelantusMetaFromPubcoin(hash, meta));

        BOOST_CHECK(meta.isUsed);

        meta.isUsed = false;
        BOOST_CHECK(pwalletMain->zwallet->GetTracker().UpdateState(meta));

        meta = CLelantusMintMeta();
        BOOST_CHECK(pwalletMain->zwallet->GetTracker()
            .GetLelantusMetaFromPubcoin(hash, meta));
        BOOST_CHECK(!meta.isUsed);
    }

    // Create duplicated serial tx and test this at the bottom
    auto dupJsTx1 = GenerateJoinSplit({1 * COIN}, {}, &coinControl);

    std::vector<PublicCoin> dupNewCoins1;
    std::vector<Scalar> dupSerials1;
    ExtractJoinSplit(dupJsTx1, dupNewCoins1, dupSerials1);

    std::vector<PublicCoin> newCoins1;
    std::vector<Scalar> serials1;
    ExtractJoinSplit(jsTx1, newCoins1, serials1);
    BOOST_CHECK_EQUAL(1, newCoins1.size());
    BOOST_CHECK_EQUAL(1, serials1.size());
    BOOST_CHECK(dupSerials1[0] == serials1[0]);

    auto blockIdx2 = GenerateBlock({jsTx1});
    BOOST_CHECK(blockIdx2);
    auto block2 = GetCBlock(blockIdx2);

    auto cacheChecker = checker;
    checker.coins.push_back(newCoins1.front());
    checker.serials.push_back(serials1.front());
    checker.last = blockIdx2;

    checker.Verify();

    // state should be rolled back
    DisconnectBlocks(1);
    BOOST_CHECK_EQUAL(chainActive.Tip()->nHeight, blockIdx2->nHeight - 1);
    cacheChecker.Verify();

    // reconnect
    reconnect(block2);
    checker.Verify();

    // add more block contain both mint and serial
    auto jsTx2 = GenerateJoinSplit({1 * COIN}, {CENT});
    std::vector<PublicCoin> newCoins2;
    std::vector<Scalar> serials2;
    ExtractJoinSplit(jsTx2, newCoins2, serials2);
    BOOST_CHECK_EQUAL(2, newCoins2.size());
    BOOST_CHECK_EQUAL(1, serials2.size());

    auto blockIdx3 = GenerateBlock({mintTxs[2], jsTx2});
    BOOST_CHECK(blockIdx3);
    auto block3 = GetCBlock(blockIdx3);

    checker.coins.insert(checker.coins.end(), newCoins2.begin(), newCoins2.end());
    checker.coins.push_back(hdMints[2].GetPubcoinValue());
    checker.serials.push_back(serials2[0]);
    checker.last = blockIdx3;

    checker.Verify();

    // Clear state and rebuild
    lelantusState->Reset();
    emptyChecker.Verify();

    BuildLelantusStateFromIndex(&chainActive);
    checker.Verify();

    // Disconnect all and reconnect
    std::vector<CBlock> blocks;
    while (chainActive.Tip() != chainActive.Genesis()) {
        blocks.push_back(GetCBlock(chainActive.Tip()));
        DisconnectBlocks(1);
    }

    emptyChecker.Verify();

    for (auto const &block : blocks) {
        reconnect(block);
    }

    checker.Verify();

    // double spend
    auto currentBlock = chainActive.Tip()->nHeight;
    BOOST_CHECK(!GenerateBlock({dupJsTx1}));
    BOOST_CHECK_EQUAL(currentBlock, chainActive.Tip()->nHeight);
    mempool.clear();
    lelantusState->Reset();
}

BOOST_AUTO_TEST_CASE(checktransaction)
{
    GenerateBlocks(400);

    // mints
    std::vector<CMutableTransaction> txs;
    auto mints = GenerateMints({1 * CENT}, txs);
    auto &tx = txs[0];

    CValidationState state;
    CLelantusTxInfo info;
    BOOST_CHECK(CheckLelantusTransaction(
        txs[0], state, tx.GetHash(), false, chainActive.Height(), true, true, NULL, &info));

    std::vector<std::pair<PublicCoin, std::pair<uint64_t, uint256>>> expectedCoins = {{mints[0].GetPubcoinValue(), {1 * CENT, info.mints[0].second.second}}};

    BOOST_CHECK(expectedCoins == info.mints);

    // join split
    txs.clear();
    mints = GenerateMints({10 * CENT, 11 * CENT, 100 * CENT}, txs);
    GenerateBlock(txs);
    GenerateBlocks(10);

    auto outputAmount = 8 * CENT;
    auto mintAmount = 2 * CENT - CENT; // a cent as fee

    CWalletTx wtx;
    pwalletMain->JoinSplitLelantus(
        {{script, outputAmount, false}},
        {mintAmount},
        wtx);

    CMutableTransaction joinsplitTx(wtx);
    auto joinsplit = ParseLelantusJoinSplit(joinsplitTx);

    // test get join split amounts
    BOOST_CHECK_EQUAL(1, GetSpendInputs(joinsplitTx));
    BOOST_CHECK_EQUAL(1, GetSpendInputs(joinsplitTx, joinsplitTx.vin[0]));

    info = CLelantusTxInfo();

    BOOST_CHECK(CheckLelantusTransaction(
        joinsplitTx, state, joinsplitTx.GetHash(), false, chainActive.Height(), false, true, NULL, &info));

    auto &serials = joinsplit->getCoinSerialNumbers();
    auto &ids = joinsplit->getCoinGroupIds();

    for (size_t i = 0; i != serials.size(); i++) {
        bool hasSerial = false;
        BOOST_CHECK_MESSAGE(hasSerial = (info.spentSerials.count(serials[i]) > 0), "No serial as expected");
        if (hasSerial) {
            BOOST_CHECK_MESSAGE(ids[i] == info.spentSerials[serials[i]], "Serials group id is invalid");
        }
    }

    info = CLelantusTxInfo();
    BOOST_CHECK(CheckLelantusTransaction(
        joinsplitTx, state, joinsplitTx.GetHash(), false, chainActive.Height(), false, true, NULL, &info));

    // test surge dection.
    while (!lelantusState->IsSurgeConditionDetected()) {
        Scalar s;
        s.randomize();

        lelantusState->AddSpend(s, 1);
    }

    BOOST_CHECK(!CheckLelantusTransaction(
        joinsplitTx, state, joinsplitTx.GetHash(), false, chainActive.Height(), false, true, NULL, &info));
}

BOOST_AUTO_TEST_CASE(move_to_v3_payload)
{
    int prevHeight;
    pwalletMain->SetBroadcastTransactions(true);

    for (int n=chainActive.Height(); n<700; n++)
        GenerateBlock({});

    std::vector<CMutableTransaction> lelantusMints;
    GenerateMints({1*COIN, 2*COIN, 3*COIN, 4*COIN, 5*COIN}, lelantusMints);
    GenerateBlock(lelantusMints);

    for (int i=0; i<6; i++)
        GenerateBlock({});

    // Shift HF block number to create joinsplit with v3 payload early
    Consensus::Params &mutableParams = const_cast<Consensus::Params &>(::Params().GetConsensus());
    int v3PayloadHFBackup = mutableParams.nLelantusV3PayloadStartBlock;
    mutableParams.nLelantusV3PayloadStartBlock = chainActive.Height();

    CWalletTx jsWalletTx1, jsWalletTx2, jsWalletTx3;

    pwalletMain->JoinSplitLelantus({{script, COIN/10, false}}, {}, jsWalletTx1);
    ::mempool.clear();

    // Test transaction structure
    BOOST_ASSERT(jsWalletTx1.tx->vin[0].scriptSig.size() == 1);

    CBlock blockWithPayloadJS = CreateBlock({*jsWalletTx1.tx}, coinbaseKey);

    mutableParams.nLelantusV3PayloadStartBlock = v3PayloadHFBackup;

    // transaction shouldn't get accepted into the mempool
    BOOST_ASSERT(!::CommitToMempool(*jsWalletTx1.tx));
    // block with this transaction shouldn't be accepted either
    prevHeight = chainActive.Height();
    ProcessNewBlock(::Params(), std::make_shared<CBlock>(blockWithPayloadJS), true, nullptr);
    BOOST_ASSERT(chainActive.Height() == prevHeight);

    // Create wallet transaction with lelantus data in scriptSig
    pwalletMain->JoinSplitLelantus({{script, COIN/10, false}}, {}, jsWalletTx2);
    // ensure it has lelantus data in scriptSig
    BOOST_ASSERT(jsWalletTx2.tx->vin[0].scriptSig.size() > 1);
    // should get into the mempool
    BOOST_ASSERT(::mempool.size() == 1);
    // should get into the block
    GenerateBlock({*jsWalletTx2.tx});
    BOOST_ASSERT(::mempool.size() == 0);

    // Create another wallet transaction with lelantus data in scriptSig
    pwalletMain->JoinSplitLelantus({{script, COIN/10, false}}, {}, jsWalletTx3);
    ::mempool.clear();

    // fast forward to HF
    for (int n=chainActive.Height(); n<mutableParams.nLelantusV3PayloadStartBlock; n++)
        GenerateBlock({});

    // non-payload tx shouldn't get into the mempool
    BOOST_ASSERT(!CommitToMempool(*jsWalletTx3.tx));
    // create a block with such tx and ensure it doesn't get accepted
    mutableParams.nLelantusV3PayloadStartBlock += 10;
    CBlock blockWithNonpayloadJS = CreateBlock({*jsWalletTx3.tx}, coinbaseKey);
    mutableParams.nLelantusV3PayloadStartBlock = v3PayloadHFBackup;
    prevHeight = chainActive.Height();
    ProcessNewBlock(::Params(), std::make_shared<CBlock>(blockWithNonpayloadJS), true, nullptr);
    BOOST_ASSERT(chainActive.Height() == prevHeight);
}

BOOST_AUTO_TEST_CASE(spend_limitation_per_tx)
{
    PrivateCoin coinOut(params, 0);
    JoinSplitScriptGenerator invalidG, validG;
    invalidG.fee = 0;
    invalidG.vout = 0;
    invalidG.coinsOut = {coinOut};
    invalidG.groupBlockHashes[1] = {ArithToUint256(0)};
    invalidG.txHash = ArithToUint256(0);

    validG.fee = 0;
    validG.vout = 0;
    validG.coinsOut = {coinOut};
    validG.groupBlockHashes[1] = ArithToUint256(0);
    validG.txHash = ArithToUint256(0);

    for (size_t i = 0; i != consensus.nMaxLelantusInputPerTransaction + 1; i++) {
        PrivateCoin coin(params, 0);
        invalidG.coins.emplace_back(coin, 1);
        invalidG.anons[1].push_back(coin.getPublicCoin());

        if (i != 0) { // skip first
            validG.coins.emplace_back(coin, 1);
            validG.anons[1].push_back(coin.getPublicCoin());
        }
    }

    CMutableTransaction invalidTx, validTx;
    invalidTx.vin.resize(1);
    invalidTx.vin[0].scriptSig = invalidG.Get().first;

    validTx.vin.resize(1);
    validTx.vin[0].scriptSig = validG.Get().first;

    CBlock invalidBlock, validBlock;
    invalidBlock.vtx.push_back(MakeTransactionRef(invalidTx));
    validBlock.vtx.push_back(MakeTransactionRef(validTx));

    CValidationState state;
    BOOST_CHECK(!CheckLelantusBlock(state, invalidBlock));
    BOOST_CHECK(CheckLelantusBlock(state, validBlock));
}

BOOST_AUTO_TEST_CASE(spend_limitation_per_block)
{
    CBlock block;
    size_t spends = 0;

    for (size_t i = 0; spends <= consensus.nMaxLelantusInputPerBlock; i++) {
        PrivateCoin coinOut(params, 0);
        JoinSplitScriptGenerator g;
        g.fee = 0;
        g.vout = 0;
        g.coinsOut = {coinOut};
        for (size_t i = 0; i != consensus.nMaxLelantusInputPerTransaction; i++) {
            PrivateCoin coin(params, 0);
            g.coins.emplace_back(coin, 1);
            g.anons[1].push_back(coin.getPublicCoin());

            spends++;
        }

        g.groupBlockHashes[1] = ArithToUint256(i);
        g.txHash = ArithToUint256(i);

        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vin[0].scriptSig = g.Get().first;


        block.vtx.push_back(MakeTransactionRef(tx));
    }

    CValidationState state;
    BOOST_CHECK(!CheckLelantusBlock(state, block));

    block.vtx.pop_back();
    BOOST_CHECK(CheckLelantusBlock(state, block));
}

BOOST_AUTO_TEST_CASE(parse_joinsplit)
{
    auto coins = GenerateMints({1 * COIN, 10 * COIN, 1 * COIN, 1 * COIN});

    JoinSplitScriptGenerator g;
    g.params = params;
    g.coins = {{coins[0], 1}, {coins[1], 1}, {coins[2], 2}};
    for (auto id : {1, 2}) {
        for (size_t i = 0; i != 10; i++) {
            GroupElement e;
            e.randomize();

            g.anons[id].emplace_back(e);
        }
    }

    g.anons[1][0] = coins[0].getPublicCoin();
    g.anons[1][1] = coins[1].getPublicCoin();
    g.anons[2][0] = coins[2].getPublicCoin();

    g.vout = 11 * COIN - CENT;
    g.coinsOut.push_back(coins[3]);
    g.fee = CENT;
    g.groupBlockHashes[1] = ArithToUint256(1);
    g.groupBlockHashes[2] = ArithToUint256(2);
    g.txHash = ArithToUint256(3);

    auto gs = g.Get();
    CTxIn inp(COutPoint(), gs.first);
    CMutableTransaction inpTx;
    inpTx.vin.push_back(inp);

    auto result = ParseLelantusJoinSplit(inpTx);

    BOOST_CHECK(gs.second.getCoinSerialNumbers() == result->getCoinSerialNumbers());
    BOOST_CHECK(gs.second.getFee() == result->getFee());
    BOOST_CHECK(gs.second.getCoinGroupIds() == result->getCoinGroupIds());
    BOOST_CHECK(gs.second.getIdAndBlockHashes() == result->getIdAndBlockHashes());
    BOOST_CHECK(gs.second.getVersion() == result->getVersion());
    BOOST_CHECK(gs.second.HasValidSerials() == result->HasValidSerials());

    BOOST_CHECK(gs.second.Verify(g.anons, {}, ExtractCoins(g.coinsOut), g.vout, g.txHash));
    BOOST_CHECK(result->Verify(g.anons, {}, ExtractCoins(g.coinsOut), g.vout, g.txHash));
}

BOOST_AUTO_TEST_CASE(coingroup)
{
    GenerateBlocks(400);

    // util function
    auto reconnect = [](CBlock const &block) {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        LOCK(mempool.cs);

        std::shared_ptr<CBlock const> sharedBlock =
        std::make_shared<CBlock const>(block);

        CValidationState state;
        ActivateBestChain(state, ::Params(), sharedBlock);
    };

    struct {
        // expected state.
        std::vector<PublicCoin> coins;

        // first group
        CBlockIndex *first = nullptr;
        CBlockIndex *last = nullptr;

        int lastId = 0;
        size_t lastGroupCoins = 0;

        // real state
        CLelantusState *state;

        void Verify(std::string stateName = "") const {
            auto const &mints = state->GetMints();
            BOOST_CHECK_EQUAL(coins.size(), mints.size());
            for (auto const &c : coins) {
                BOOST_CHECK_MESSAGE(mints.count(c), "public is not found on state : " + stateName);
            }

            auto retrievedId = state->GetLatestCoinID();

            CLelantusState::LelantusCoinGroupInfo group;
            state->GetCoinGroupInfo(retrievedId, group);

            BOOST_CHECK_EQUAL(lastId, retrievedId);
            BOOST_CHECK_EQUAL(first, group.firstBlock);
            BOOST_CHECK_EQUAL(last, group.lastBlock);
            BOOST_CHECK_EQUAL(lastGroupCoins, group.nCoins);
        }
    } checker;
    checker.state = lelantusState;

    lelantusState->~CLelantusState();
    new (lelantusState) CLelantusState(65, 16);
    lelantusState->Reset();

    // logic
    std::vector<CMutableTransaction> txs;
    std::vector<lelantus::PrivateCoin> coins;
    auto hdMints = GenerateMints(std::vector<CAmount>(66, 1), txs, coins);

    auto txRange = [&](size_t start, size_t end) -> std::vector<CMutableTransaction> {
        std::vector<CMutableTransaction> rangeTxs;
        for (auto i = start; i < end && i < txs.size(); i++) {
            rangeTxs.push_back(txs[i]);
        }

        return rangeTxs;
    };

    std::vector<PublicCoin> pubCoins;
    for (auto const &hdMint : hdMints) {
        pubCoins.push_back(hdMint.GetPubcoinValue());
    }

    auto emptyChecker = checker;
    emptyChecker.Verify();

    // add one block
    auto idx1 = GenerateBlock(txRange(0, 1));
    auto block1 = GetCBlock(idx1);

    checker.coins.push_back(pubCoins[0]);
    checker.lastId = 1;
    checker.first = idx1;
    checker.last = idx1;
    checker.lastGroupCoins = 1;
    checker.Verify();

    // add more
    auto idx2 = GenerateBlock(txRange(1, 32));
    auto block2 = GetCBlock(idx2);

    checker.coins.insert(checker.coins.end(), pubCoins.begin() + 1, pubCoins.begin() + 32);
    checker.last = idx2;
    checker.lastGroupCoins = 32;
    checker.Verify();

    auto cacheIdx2Checker = checker;

    // add more to fill group
    auto idx3 = GenerateBlock(txRange(32, 65));
    auto block3 = GetCBlock(idx3);

    checker.coins.insert(checker.coins.end(), pubCoins.begin() + 32, pubCoins.begin() + 65);
    checker.last = idx3;
    checker.lastGroupCoins = 65;
    checker.Verify();

    auto cacheIdx3Checker = checker;

    // add one more to create new group
    auto idx4 = GenerateBlock(txRange(65, 66));
    auto block4 = GetCBlock(idx4);

    checker.coins.push_back(pubCoins[65]);
    checker.lastId = 2;
    checker.lastGroupCoins = 34;
    checker.first = idx3;
    checker.last = idx4;

    checker.Verify();

    // remove last block check coingroup
    DisconnectBlocks(1);
    cacheIdx3Checker.Verify();

    // remove one more block
    DisconnectBlocks(1);
    cacheIdx2Checker.Verify();

    // reconnect them all and check state
    reconnect(block2);
    reconnect(block3);
    checker.Verify();

    lelantusState->~CLelantusState();
    new (lelantusState) CLelantusState();
    lelantusState->Reset();
}

BOOST_AUTO_TEST_SUITE_END()

};
