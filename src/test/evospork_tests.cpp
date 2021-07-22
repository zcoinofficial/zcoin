#include "test/test_bitcoin.h"
#include "test/fixtures.h"

#include "script/interpreter.h"
#include "script/standard.h"
#include "script/sign.h"
#include "utilmoneystr.h"
#include "base58.h"
#include "netbase.h"
#include "net.h"
#include "validation.h"
#include "txmempool.h"
#include "messagesigner.h"
#include "keystore.h"

#include "evo/specialtx.h"
#include "evo/spork.h"

#include "wallet/wallet.h"

#include <boost/test/unit_test.hpp>

typedef std::map<COutPoint, std::pair<int, CAmount>> SimpleUTXOMap;

static SimpleUTXOMap BuildSimpleUtxoMap(const std::vector<CTransaction>& txs)
{
    SimpleUTXOMap utxos;
    CAmount balance = 0;
    for (size_t i = 0; i < txs.size(); i++) {
        auto& tx = txs[i];
        size_t const znode_output = tx.vout.size() > 6 ? FindZnodeOutput(tx) : 0;
        for (size_t j = 0; j < tx.vout.size(); j++) {
            if(j == 0 || j == znode_output) {
                balance += tx.vout[j].nValue;
                utxos.emplace(COutPoint(tx.GetHash(), j), std::make_pair((int)i + 1, tx.vout[j].nValue));
            }
        }
    }
    return utxos;
}

static std::vector<COutPoint> SelectUTXOs(SimpleUTXOMap& utoxs, CAmount amount, CAmount& changeRet)
{
    changeRet = 0;

    std::vector<COutPoint> selectedUtxos;
    CAmount selectedAmount = 0;
    while (!utoxs.empty()) {
        bool found = false;
        for (auto it = utoxs.begin(); it != utoxs.end(); ++it) {
            if (chainActive.Height() - it->second.first < 101) {
                continue;
            }

            found = true;
            selectedAmount += it->second.second;
            selectedUtxos.emplace_back(it->first);
            utoxs.erase(it);
            break;
        }
        BOOST_ASSERT(found);
        if (selectedAmount >= amount) {
            changeRet = selectedAmount - amount;
            break;
        }
    }

    return selectedUtxos;
}

static void FundTransaction(CMutableTransaction& tx, SimpleUTXOMap& utoxs, const CScript& scriptPayout, CAmount amount, const CKey& coinbaseKey)
{
    CAmount change;
    auto inputs = SelectUTXOs(utoxs, amount, change);
    for (size_t i = 0; i < inputs.size(); i++) {
        tx.vin.emplace_back(CTxIn(inputs[i]));
    }
    tx.vout.emplace_back(CTxOut(amount, scriptPayout));
    if (change > COIN/10) {
        tx.vout.emplace_back(CTxOut(change-COIN/10, scriptPayout));
    }
}

static void SignTransaction(CMutableTransaction& tx, const CKey& coinbaseKey)
{
    CBasicKeyStore tempKeystore;
    tempKeystore.AddKeyPubKey(coinbaseKey, coinbaseKey.GetPubKey());

    for (size_t i = 0; i < tx.vin.size(); i++) {
        CTransactionRef txFrom;
        uint256 hashBlock;
        BOOST_ASSERT(GetTransaction(tx.vin[i].prevout.hash, txFrom, Params().GetConsensus(), hashBlock));
        bool result = SignSignature(tempKeystore, *txFrom, tx, i, SIGHASH_ALL);
        if(!result)
            std::cerr << i << std::endl;
    }
}

static CMutableTransaction CreateSporkTx(SimpleUTXOMap &utxos, const CKey &coinbaseKey, const std::vector<CSporkAction> &actions)
{
    CBitcoinSecret secretKey;
    secretKey.SetString("cW2YM2xaeCaebfpKguBahUAgEzLXgSserWRuD29kSyKHq1TTgwRQ");

    CSporkTx sporkTxPayload;
    sporkTxPayload.actions = actions;

    CMutableTransaction tx;
    tx.nVersion = 3;
    tx.nType = TRANSACTION_SPORK;

    CTxDestination txDest = coinbaseKey.GetPubKey().GetID();
    CScript scriptPayout = GetScriptForDestination(txDest);

    FundTransaction(tx, utxos, scriptPayout, COIN/10, coinbaseKey);
    sporkTxPayload.inputsHash = CalcTxInputsHash(tx);
    CHashSigner::SignHash(::SerializeHash(sporkTxPayload), secretKey.GetKey(), sporkTxPayload.vchSig);
    SetTxPayload(tx, sporkTxPayload);
    SignTransaction(tx, coinbaseKey);

    return tx;
}

static bool CommitToMempool(const CTransaction &tx)
{
    CWallet *wallet = pwalletMain;
    CWalletTx walletTx(wallet, MakeTransactionRef(tx));
    CReserveKey reserveKey(wallet);
    CValidationState state;
    wallet->CommitTransaction(walletTx, reserveKey, g_connman.get(), state);
    return mempool.exists(tx.GetHash());
}

BOOST_FIXTURE_TEST_SUITE(evospork_tests, LelantusTestingSetup)

BOOST_AUTO_TEST_CASE(general)
{
    int prevHeight;
    pwalletMain->SetBroadcastTransactions(true);

    for (int n=chainActive.Height(); n<300; n++)
        GenerateBlock({});

    auto utxos = BuildSimpleUtxoMap(coinbaseTxns);
    CMutableTransaction sporkTx1 = CreateSporkTx(utxos, coinbaseKey, {
        {CSporkAction::sporkDisable, CSporkAction::featureLelantus, 0, 1010}
    });
    CMutableTransaction sporkTx2 = CreateSporkTx(utxos, coinbaseKey, {
        {CSporkAction::sporkDisable, CSporkAction::featureLelantus, 0, 1020}
    });
    CMutableTransaction sporkTx3 = CreateSporkTx(utxos, coinbaseKey, {
        {CSporkAction::sporkEnable, CSporkAction::featureLelantus, 0, 0}
    });

    // should not accept spork tx before activation block
    BOOST_ASSERT(!CommitToMempool(sporkTx1));

    // should not accept block with spork tx either
    prevHeight = chainActive.Height();
    GenerateBlock({sporkTx1});
    BOOST_ASSERT(chainActive.Height() == prevHeight);

    for (int n=chainActive.Height(); n<1000; n++)
        GenerateBlock({});

    prevHeight = chainActive.Height();
    GenerateBlock({sporkTx1});
    // should be accepted now
    BOOST_ASSERT(chainActive.Height() == prevHeight+1);

    std::vector<CMutableTransaction> lelantusMints;
    GenerateMints({1*COIN, 2*COIN}, lelantusMints);

    prevHeight = chainActive.Height();
    GenerateBlock(lelantusMints);
    // can't accept lelantus tx anymore
    BOOST_ASSERT(chainActive.Height() == prevHeight);

    // wait until the spork expires
    for (int n=chainActive.Height(); n<1010; n++)
        GenerateBlock({});
    prevHeight = chainActive.Height();
    GenerateBlock({lelantusMints[0]});
    BOOST_ASSERT(chainActive.Height() == prevHeight+1);

    // another disabling spork
    GenerateBlock({sporkTx2});
    // ensure lelantus is disabled
    prevHeight = chainActive.Height();
    GenerateBlock({lelantusMints[1]});
    BOOST_ASSERT(chainActive.Height() == prevHeight);

    // block with enabling spork
    GenerateBlock({sporkTx3});
    // ensure lelantus is enabled now
    prevHeight = chainActive.Height();
    GenerateBlock({lelantusMints[1]});
    BOOST_ASSERT(chainActive.Height() == prevHeight+1);
}

BOOST_AUTO_TEST_CASE(mempool)
{
    int prevHeight;
    pwalletMain->SetBroadcastTransactions(true);

    for (int n=chainActive.Height(); n<1001; n++)
        GenerateBlock({});

    auto utxos = BuildSimpleUtxoMap(coinbaseTxns);
    CMutableTransaction sporkTx1 = CreateSporkTx(utxos, coinbaseKey, {
        {CSporkAction::sporkDisable, CSporkAction::featureLelantus, 0, 1010}
    });
    CMutableTransaction sporkTx2 = CreateSporkTx(utxos, coinbaseKey, {
        {CSporkAction::sporkDisable, CSporkAction::featureLelantus, 0, 1020}
    });

    std::vector<CMutableTransaction> lelantusMints;
    GenerateMints({1*COIN, 2*COIN}, lelantusMints);
    ::mempool.removeRecursive(lelantusMints[0]);
    ::mempool.removeRecursive(lelantusMints[1]);

    CBlock blockWithLelantusMint = CreateBlock({lelantusMints[0]}, coinbaseKey);

    // put one mint into the mempool
    CommitToMempool(lelantusMints[0]);

    // push spork to mempool
    CommitToMempool(sporkTx1);
    // spork should be in the mempool, lelantus mint should be pushed out of it
    BOOST_ASSERT(::mempool.size() == 1);
    BOOST_ASSERT(::mempool.exists(sporkTx1.GetHash()) && !::mempool.exists(lelantusMints[0].GetHash()));

    // another lelantus tx shouldn't get to the mempool
    CommitToMempool(lelantusMints[1]);
    BOOST_ASSERT(::mempool.size() == 1);

    // but should be accepted in block
    prevHeight = chainActive.Height();
    ProcessNewBlock(Params(), std::make_shared<CBlock>(blockWithLelantusMint), true, nullptr);
    BOOST_ASSERT(chainActive.Height() == prevHeight+1);

    // mine spork into the block
    CreateAndProcessBlock({sporkTx1}, coinbaseKey);
    // mempool should clear
    BOOST_ASSERT(::mempool.size() == 0);

    // because there is active spork at the tip lelantus mint shouldn't get into the mempool
    BOOST_ASSERT(!CommitToMempool(lelantusMints[1]));

    for (int n=chainActive.Height(); n<1010; n++)
        CreateAndProcessBlock({}, coinbaseKey);

    // spork expired, should accept now
    BOOST_ASSERT(CommitToMempool(lelantusMints[1]));
    // try and generate a block with second spork without it ever entering the mempool
    CreateAndProcessBlock({sporkTx2}, coinbaseKey);
    // now we have a mint in the mempool and active spork. Verify that miner correctly blocks the mint
    // from being mined
    fAllowMempoolTxsInCreateBlock = true;
    CBlock block = CreateBlock({}, coinbaseKey);
    for (CTransactionRef tx: block.vtx) {
        BOOST_ASSERT(!tx->IsLelantusTransaction());
    }
    BOOST_ASSERT(::mempool.exists(lelantusMints[1].GetHash()));
    prevHeight = chainActive.Height();
    ProcessNewBlock(Params(), std::make_shared<CBlock>(block), true, nullptr);
    BOOST_ASSERT(chainActive.Height() == prevHeight+1);
}

BOOST_AUTO_TEST_CASE(limit)
{
    int prevHeight;
    pwalletMain->SetBroadcastTransactions(true);

    for (int n=chainActive.Height(); n<1001; n++)
        GenerateBlock({});

    auto utxos = BuildSimpleUtxoMap(coinbaseTxns);
    CMutableTransaction sporkTx1 = CreateSporkTx(utxos, coinbaseKey, {
        {CSporkAction::sporkLimit, CSporkAction::featureLelantusTransparentLimit, 100*COIN, 1030}
    });

    std::vector<CMutableTransaction> lelantusMints;
    for (int i=0; i<10; i++) {
        std::vector<std::pair<CWalletTx, CAmount>> wtxAndFee;
        std::vector<CHDMint> mints;
        std::string error = pwalletMain->MintAndStoreLelantus(50*COIN, wtxAndFee, mints);
        BOOST_ASSERT(error.empty());
        for (auto &w: wtxAndFee)
            lelantusMints.emplace_back(*w.first.tx);
    }

    GenerateBlock(lelantusMints);

    for (int i=0; i<10; i++)
        GenerateBlock({});

    CWalletTx jsWalletTx;
    pwalletMain->JoinSplitLelantus({{script, 120*COIN, false}}, {}, jsWalletTx);

    CMutableTransaction jsTx = *jsWalletTx.tx;

    ::mempool.removeRecursive(jsTx);

    auto joinsplit = lelantus::ParseLelantusJoinSplit(jsTx);
    std::vector<Scalar> serials = joinsplit->getCoinSerialNumbers();

    // generate two smaller joinsplit txs
    CWalletTx jsSmallWalletTxs[2];
    pwalletMain->JoinSplitLelantus({{script, 70*COIN, false}}, {}, jsSmallWalletTxs[0]);
    pwalletMain->JoinSplitLelantus({{script, 70*COIN, false}}, {}, jsSmallWalletTxs[1]);

    CMutableTransaction jsSmallTxs[2] = {*jsSmallWalletTxs[0].tx, *jsSmallWalletTxs[1].tx};

    CommitToMempool(sporkTx1);
    BOOST_ASSERT(::mempool.size() == 3);    // two small joinsplits and spork

    fAllowMempoolTxsInCreateBlock = true;
    CBlock block = CreateBlock({}, script);
    // should only have one joinsplit transaction in the block
    int nJoinSplits = 0;
    for (CTransactionRef ptx: block.vtx) {
        if (ptx->IsLelantusJoinSplit())
            nJoinSplits++;
    }
    BOOST_ASSERT(nJoinSplits == 1);
    prevHeight = chainActive.Height();
    ProcessNewBlock(Params(), std::make_shared<CBlock>(block), true, nullptr);
    BOOST_ASSERT(chainActive.Height() == prevHeight+1);
    // one joinsplit should be left at the mempool
    BOOST_ASSERT(::mempool.size() == 1);

    // mine remaining joinsplit into the block
    prevHeight = chainActive.Height();
    GenerateBlock({});
    BOOST_ASSERT(chainActive.Height() == prevHeight+1);
    BOOST_ASSERT(::mempool.size() == 0);
    fAllowMempoolTxsInCreateBlock = false;

    // large joinsplit tx is out of range, should fail now
    BOOST_ASSERT(!CommitToMempool(jsTx));
    // should fail in block as well
    prevHeight = chainActive.Height();
    GenerateBlock({jsTx});
    BOOST_ASSERT(chainActive.Height() == prevHeight);

    // skip to 1030 (spork expiration block)
    for (int n=chainActive.Height(); n<1030; n++)
        GenerateBlock({});

    // should be accepted into the mempool
    BOOST_ASSERT(CommitToMempool(jsTx));
    // and be mined into the block
    prevHeight = chainActive.Height();
    GenerateBlock({jsTx});
    BOOST_ASSERT(chainActive.Height() == prevHeight+1);
    // mempool should be clear
    BOOST_ASSERT(::mempool.size() == 0);
    // serials should go into the state
    for (Scalar serial: serials)
        BOOST_ASSERT(lelantus::CLelantusState::GetState()->IsUsedCoinSerial(serial));
}

BOOST_AUTO_TEST_CASE(startstopblock)
{
    int prevHeight;
    pwalletMain->SetBroadcastTransactions(true);

    for (int n=chainActive.Height(); n<700; n++)
        GenerateBlock({});

    auto utxos = BuildSimpleUtxoMap(coinbaseTxns);
    CMutableTransaction sporkTx1 = CreateSporkTx(utxos, coinbaseKey, {
        {CSporkAction::sporkDisable, CSporkAction::featureLelantus, 0, 1010}
    });
    CMutableTransaction sporkTx2 = CreateSporkTx(utxos, coinbaseKey, {
        {CSporkAction::sporkDisable, CSporkAction::featureLelantus, 0, 0}
    });
    CMutableTransaction sporkTx3 = CreateSporkTx(utxos, coinbaseKey, {
        {CSporkAction::sporkDisable, CSporkAction::featureLelantus, 0, 2000}
    });

    // spork can't be put into the mempool/mined yet
    BOOST_ASSERT(!CommitToMempool(sporkTx1));
    prevHeight = chainActive.Height();
    CreateAndProcessBlock({sporkTx1}, coinbaseKey);
    BOOST_ASSERT(chainActive.Height() == prevHeight);

    for (int n=chainActive.Height(); n<1001; n++)
        GenerateBlock({});

    // now we can mine sporkTx1
    prevHeight = chainActive.Height();
    CreateAndProcessBlock({sporkTx1}, coinbaseKey);
    BOOST_ASSERT(chainActive.Height() == prevHeight+1);

    // sporkTx3 can't be mined because it's stopping block is beyond spork window
    prevHeight = chainActive.Height();
    CreateAndProcessBlock({sporkTx3}, coinbaseKey);
    BOOST_ASSERT(chainActive.Height() == prevHeight);

    std::vector<CMutableTransaction> lelantusMints;
    GenerateMints({1*COIN}, lelantusMints);

    GenerateBlock({});

    // can't get mints to the block
    prevHeight = chainActive.Height();
    CreateAndProcessBlock({lelantusMints[0]}, coinbaseKey);
    BOOST_ASSERT(chainActive.Height() == prevHeight);

    // mine spork tx without stop block
    prevHeight = chainActive.Height();
    CreateAndProcessBlock({sporkTx2}, coinbaseKey);
    BOOST_ASSERT(chainActive.Height() == prevHeight+1);

    // shouldn't bet able to get mint to the block
    prevHeight = chainActive.Height();
    CreateAndProcessBlock({lelantusMints[0]}, coinbaseKey);
    BOOST_ASSERT(chainActive.Height() == prevHeight);

    // go to the end of the spork window and try again
    for (int n=chainActive.Height(); n<1500; n++)
        GenerateBlock({});

    // should work now
    prevHeight = chainActive.Height();
    CreateAndProcessBlock({lelantusMints[0]}, coinbaseKey);
    BOOST_ASSERT(chainActive.Height() == prevHeight+1);

    // test if spork set is empty
    BOOST_ASSERT(chainActive.Tip()->activeDisablingSporks.empty());
}


BOOST_AUTO_TEST_SUITE_END()
