#include "utils_tx.h"

#include "../createpayload.h"
#include "../elysium.h"
#include "../packetencoder.h"
#include "../rules.h"
#include "../script.h"
#include "../tx.h"

#include "../../base58.h"
#include "../../coins.h"
#include "../../utilstrencodings.h"

#include "../../primitives/transaction.h"

#include "../../script/script.h"
#include "../../script/standard.h"

#include "../../test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

#include <limits>
#include <vector>

#include <inttypes.h>

namespace elysium {

BOOST_FIXTURE_TEST_SUITE(elysium_parsing_c_tests, BasicTestingSetup)

/** Creates a dummy transaction with the given inputs and outputs. */
static CTransaction TxClassC(const std::vector<CTxOut>& txInputs, const std::vector<CTxOut>& txOuts)
{
    CMutableTransaction mutableTx;

    // Inputs:
    for (std::vector<CTxOut>::const_iterator it = txInputs.begin(); it != txInputs.end(); ++it)
    {
        const CTxOut& txOut = *it;

        // Create transaction for input:
        CMutableTransaction inputTx;
        unsigned int nOut = 0;
        inputTx.vout.push_back(txOut);
        CTransaction tx(inputTx);

        // Populate transaction cache:
        ModifyCoin(view, COutPoint(tx.GetHash(), 0),
            [&txOut](Coin & coin){
                coin.out.scriptPubKey = txOut.scriptPubKey;
                coin.out.nValue = txOut.nValue;
            });

        // Add input:
        CTxIn txIn(tx.GetHash(), nOut);
        mutableTx.vin.push_back(txIn);
    }

    for (std::vector<CTxOut>::const_iterator it = txOuts.begin(); it != txOuts.end(); ++it)
    {
        const CTxOut& txOut = *it;
        mutableTx.vout.push_back(txOut);
    }

    return CTransaction(mutableTx);
}

/** Helper to create a CTxOut object. */
static CTxOut createTxOut(int64_t amount, const std::string& dest)
{
    return CTxOut(amount, GetScriptForDestination(CBitcoinAddress(dest).Get()));
}

BOOST_AUTO_TEST_CASE(reference_identification)
{
    {
        int nBlock = ConsensusParams().NULLDATA_BLOCK;

        std::vector<CTxOut> txInputs;
        txInputs.push_back(createTxOut(5000000, "ZzjEgpoT2pARc5Un7xRJAJ4LPSpA9qLQxd"));

        std::vector<CTxOut> txOutputs;
        txOutputs.push_back(OpReturn_SimpleSend());
        txOutputs.push_back(createTxOut(2700000, GetSystemAddress().ToString()));

        CTransaction dummyTx = TxClassC(txInputs, txOutputs);

        CMPTransaction metaTx;
        BOOST_CHECK(ParseTransaction(dummyTx, nBlock, 1, metaTx) == 0);
        BOOST_CHECK(metaTx.getReceiver().empty());
        BOOST_CHECK_EQUAL(metaTx.getFeePaid(), 2300000);
        BOOST_CHECK_EQUAL(metaTx.getSender(), "ZzjEgpoT2pARc5Un7xRJAJ4LPSpA9qLQxd");
        BOOST_CHECK_EQUAL(HexStr(metaTx.getRaw()), "00000000000000070000000006dac2c0");
    }
    {
        int nBlock = ConsensusParams().NULLDATA_BLOCK + 1000;

        std::vector<CTxOut> txInputs;
        txInputs.push_back(createTxOut(6000, "ZzjEgpoT2pARc5Un7xRJAJ4LPSpA9qLQxd"));

        std::vector<CTxOut> txOutputs;
        txOutputs.push_back(OpReturn_SimpleSend());
        txOutputs.push_back(createTxOut(6000, "a11WeUi6HFkHNdG5puD9LHCXTySddeNcu8"));

        CTransaction dummyTx = TxClassC(txInputs, txOutputs);

        CMPTransaction metaTx;
        BOOST_CHECK(ParseTransaction(dummyTx, nBlock, 1, metaTx) == 0);
        BOOST_CHECK_EQUAL(metaTx.getFeePaid(), 0);
        BOOST_CHECK_EQUAL(metaTx.getSender(), "ZzjEgpoT2pARc5Un7xRJAJ4LPSpA9qLQxd");
        BOOST_CHECK_EQUAL(metaTx.getReceiver(), "a11WeUi6HFkHNdG5puD9LHCXTySddeNcu8");
        BOOST_CHECK_EQUAL(HexStr(metaTx.getRaw()), "00000000000000070000000006dac2c0");
    }
    {
        int nBlock = std::numeric_limits<int>::max();

        std::vector<CTxOut> txInputs;
        txInputs.push_back(createTxOut(80000, "ZzjEgpoT2pARc5Un7xRJAJ4LPSpA9qLQxd"));

        std::vector<CTxOut> txOutputs;
        txOutputs.push_back(OpReturn_SimpleSend());
        txOutputs.push_back(createTxOut(6000, "ZzjEgpoT2pARc5Un7xRJAJ4LPSpA9qLQxd"));

        CTransaction dummyTx = TxClassC(txInputs, txOutputs);

        CMPTransaction metaTx;
        BOOST_CHECK(ParseTransaction(dummyTx, nBlock, 1, metaTx) == 0);
        BOOST_CHECK_EQUAL(metaTx.getFeePaid(), 74000);
        BOOST_CHECK_EQUAL(metaTx.getSender(), "ZzjEgpoT2pARc5Un7xRJAJ4LPSpA9qLQxd");
        BOOST_CHECK_EQUAL(metaTx.getReceiver(), "ZzjEgpoT2pARc5Un7xRJAJ4LPSpA9qLQxd");
        BOOST_CHECK_EQUAL(HexStr(metaTx.getRaw()), "00000000000000070000000006dac2c0");
    }
    {
        int nBlock = std::numeric_limits<int>::max();

        std::vector<CTxOut> txInputs;
        txInputs.push_back(createTxOut(80000, "ZzjEgpoT2pARc5Un7xRJAJ4LPSpA9qLQxd"));

        std::vector<CTxOut> txOutputs;
        txOutputs.push_back(OpReturn_SimpleSend());
        txOutputs.push_back(createTxOut(6000, "a1SNP5FDj2HykF2Yg2Jr3Kzu8vMbyuVoyV"));
        txOutputs.push_back(PayToPubKey_Unrelated());
        txOutputs.push_back(NonStandardOutput());
        txOutputs.push_back(createTxOut(6000, "a1ALDLF27Efz4NEAkQPLkfUXmBCG7YfwMN"));
        txOutputs.push_back(PayToBareMultisig_1of3());
        txOutputs.push_back(createTxOut(6000, "ZzjEgpoT2pARc5Un7xRJAJ4LPSpA9qLQxd"));

        CTransaction dummyTx = TxClassC(txInputs, txOutputs);

        CMPTransaction metaTx;
        BOOST_CHECK(ParseTransaction(dummyTx, nBlock, 1, metaTx) == 0);
        BOOST_CHECK_EQUAL(metaTx.getSender(), "ZzjEgpoT2pARc5Un7xRJAJ4LPSpA9qLQxd");
        BOOST_CHECK_EQUAL(metaTx.getReceiver(), "a1ALDLF27Efz4NEAkQPLkfUXmBCG7YfwMN");
    }
    {
        int nBlock = std::numeric_limits<int>::max();

        std::vector<CTxOut> txInputs;
        txInputs.push_back(createTxOut(55550, "ZzjEgpoT2pARc5Un7xRJAJ4LPSpA9qLQxd"));

        std::vector<CTxOut> txOutputs;
        txOutputs.push_back(createTxOut(6000, "a1ALDLF27Efz4NEAkQPLkfUXmBCG7YfwMN"));
        txOutputs.push_back(PayToPubKey_Unrelated());
        txOutputs.push_back(NonStandardOutput());
        txOutputs.push_back(createTxOut(6000, "ZzjEgpoT2pARc5Un7xRJAJ4LPSpA9qLQxd"));
        txOutputs.push_back(createTxOut(6000, "ZzjEgpoT2pARc5Un7xRJAJ4LPSpA9qLQxd"));
        txOutputs.push_back(PayToPubKeyHash_Elysium());
        txOutputs.push_back(OpReturn_SimpleSend());

        CTransaction dummyTx = TxClassC(txInputs, txOutputs);

        CMPTransaction metaTx;
        BOOST_CHECK(ParseTransaction(dummyTx, nBlock, 1, metaTx) == 0);
        BOOST_CHECK_EQUAL(metaTx.getSender(), "ZzjEgpoT2pARc5Un7xRJAJ4LPSpA9qLQxd");
        BOOST_CHECK_EQUAL(metaTx.getReceiver(), "ZzjEgpoT2pARc5Un7xRJAJ4LPSpA9qLQxd");
    }
}

BOOST_AUTO_TEST_CASE(empty_op_return)
{
    {
        int nBlock = std::numeric_limits<int>::max();

        std::vector<CTxOut> txInputs;
        txInputs.push_back(createTxOut(900000, "ZzjEgpoT2pARc5Un7xRJAJ4LPSpA9qLQxd"));

        std::vector<CTxOut> txOutputs;
        txOutputs.push_back(OpReturn_PlainMarker());
        txOutputs.push_back(PayToPubKeyHash_Unrelated());

        CTransaction dummyTx = TxClassC(txInputs, txOutputs);

        CMPTransaction metaTx;
        BOOST_CHECK(ParseTransaction(dummyTx, nBlock, 1, metaTx) == 0);
        BOOST_CHECK(metaTx.getRaw().empty());
        BOOST_CHECK_EQUAL(metaTx.getSender(), "ZzjEgpoT2pARc5Un7xRJAJ4LPSpA9qLQxd");
        // via PayToPubKeyHash_Unrelated:
        BOOST_CHECK_EQUAL(metaTx.getReceiver(), "a6FFPX9EvcDCtKCzootN4EMwMv2K9xnVcV");
    }
}


BOOST_AUTO_TEST_CASE(trimmed_op_return)
{
    {
        int nBlock = std::numeric_limits<int>::max();

        std::vector<CTxOut> txInputs;
        txInputs.push_back(createTxOut(100000, "ZzjEgpoT2pARc5Un7xRJAJ4LPSpA9qLQxd"));

        std::vector<CTxOut> txOutputs;

		unsigned CLASS_B_MAX_CHUNKS = 255;
		unsigned int COMPRESSED_PUBLIC_KEY_SIZE = 33;
		unsigned CLASS_B_CHUNK_SIZE = CPubKey::COMPRESSED_PUBLIC_KEY_SIZE - 2;

        std::vector<unsigned char> vchFiller(CLASS_B_MAX_CHUNKS * CLASS_B_CHUNK_SIZE, 0x07);
        std::vector<unsigned char> vchPayload(magic.begin(), magic.end());
        vchPayload.insert(vchPayload.end(), vchFiller.begin(), vchFiller.end());

        CScript scriptPubKey;
        scriptPubKey << OP_RETURN;
        scriptPubKey << vchPayload;
        CTxOut txOut = CTxOut(0, scriptPubKey);
        txOutputs.push_back(txOut);

        CTransaction dummyTx = TxClassC(txInputs, txOutputs);

        CMPTransaction metaTx;
        BOOST_CHECK(ParseTransaction(dummyTx, nBlock, 1, metaTx) == 0);
        BOOST_CHECK_EQUAL(metaTx.getSender(), "ZzjEgpoT2pARc5Un7xRJAJ4LPSpA9qLQxd");
        BOOST_CHECK_EQUAL(HexStr(metaTx.getRaw()), HexStr(vchFiller.begin(), vchFiller.end()));
        BOOST_CHECK_EQUAL(metaTx.getRaw().size(), CLASS_B_MAX_CHUNKS * CLASS_B_CHUNK_SIZE);
    }
}

BOOST_AUTO_TEST_CASE(multiple_op_return_short)
{
    {
        int nBlock = ConsensusParams().NULLDATA_BLOCK;

        std::vector<CTxOut> txInputs;
        txInputs.push_back(createTxOut(100000, "ZzjEgpoT2pARc5Un7xRJAJ4LPSpA9qLQxd"));

        std::vector<CTxOut> txOutputs;
        {
            CScript scriptPubKey;
            scriptPubKey << OP_RETURN << ParseHex("656c797369756d0000111122223333");
            CTxOut txOut = CTxOut(0, scriptPubKey);
            txOutputs.push_back(txOut);
        }
        {
            CScript scriptPubKey;
            scriptPubKey << OP_RETURN;
            CTxOut txOut = CTxOut(0, scriptPubKey);
            txOutputs.push_back(txOut);
        }
        {
            CScript scriptPubKey;
            scriptPubKey << OP_RETURN << ParseHex("656c797369756d0001000200030004");
            CTxOut txOut = CTxOut(0, scriptPubKey);
            txOutputs.push_back(txOut);
        }
        {
            CScript scriptPubKey;
            scriptPubKey << OP_RETURN << ParseHex("656c797369756d");
            CTxOut txOut = CTxOut(0, scriptPubKey);
            txOutputs.push_back(txOut);
        }
        CTransaction dummyTx = TxClassC(txInputs, txOutputs);

        CMPTransaction metaTx;
        BOOST_CHECK(ParseTransaction(dummyTx, nBlock, 1, metaTx) == 0);
        BOOST_CHECK_EQUAL(metaTx.getSender(), "ZzjEgpoT2pARc5Un7xRJAJ4LPSpA9qLQxd");
        BOOST_CHECK_EQUAL(HexStr(metaTx.getRaw()), "00001111222233330001000200030004");
    }
}

BOOST_AUTO_TEST_CASE(multiple_op_return)
{
    {
        int nBlock = ConsensusParams().NULLDATA_BLOCK;

        std::vector<CTxOut> txInputs;
        txInputs.push_back(createTxOut(100000, "ZzjEgpoT2pARc5Un7xRJAJ4LPSpA9qLQxd"));

        std::vector<CTxOut> txOutputs;
        {
            CScript scriptPubKey;
            scriptPubKey << OP_RETURN << ParseHex("656c797369756d1222222222222222222222222223");
            CTxOut txOut = CTxOut(0, scriptPubKey);
            txOutputs.push_back(txOut);
        }
        {
            CScript scriptPubKey;
            scriptPubKey << OP_RETURN << ParseHex("656c797369756d4555555555555555555555555556");
            CTxOut txOut = CTxOut(5, scriptPubKey);
            txOutputs.push_back(txOut);
        }
        {
            CScript scriptPubKey;
            scriptPubKey << OP_RETURN << ParseHex("656c797369756d788888888889");
            CTxOut txOut = CTxOut(0, scriptPubKey);
            txOutputs.push_back(txOut);
        }
        {
            CScript scriptPubKey; // has no marker and will be ignored!
            scriptPubKey << OP_RETURN << ParseHex("4d756c686f6c6c616e64204472697665");
            CTxOut txOut = CTxOut(0, scriptPubKey);
            txOutputs.push_back(txOut);
        }
        {
            CScript scriptPubKey;
            scriptPubKey << OP_RETURN << ParseHex("656c797369756dffff11111111111111111111"
                    "11111111111111111111111111111111111111111111111111111111111111"
                    "11111111111111111111111111111111111111111111111111111111111111"
                    "111111111111111111111111111111111111111111111117");
            CTxOut txOut = CTxOut(0, scriptPubKey);
            txOutputs.push_back(txOut);
        }

        CTransaction dummyTx = TxClassC(txInputs, txOutputs);

        CMPTransaction metaTx;
        BOOST_CHECK(ParseTransaction(dummyTx, nBlock, 1, metaTx) == 0);
        BOOST_CHECK_EQUAL(metaTx.getSender(), "ZzjEgpoT2pARc5Un7xRJAJ4LPSpA9qLQxd");
        BOOST_CHECK_EQUAL(HexStr(metaTx.getRaw()), "12222222222222222222222222234555555"
                "555555555555555555556788888888889ffff11111111111111111111111111111"
                "111111111111111111111111111111111111111111111111111111111111111111"
                "111111111111111111111111111111111111111111111111111111111111111111"
                "1111111111111111111111111111117");
    }
}

BOOST_AUTO_TEST_CASE(multiple_op_return_pushes)
{
    {
        int nBlock = std::numeric_limits<int>::max();

        std::vector<CTxOut> txInputs;
        txInputs.push_back(createTxOut(100000, "ZzjEgpoT2pARc5Un7xRJAJ4LPSpA9qLQxd"));
        txInputs.push_back(PayToBareMultisig_3of5());

        std::vector<CTxOut> txOutputs;
        txOutputs.push_back(OpReturn_SimpleSend());
        txOutputs.push_back(PayToScriptHash_Unrelated());
        txOutputs.push_back(OpReturn_MultiSimpleSend());

        CTransaction dummyTx = TxClassC(txInputs, txOutputs);

        CMPTransaction metaTx;
        BOOST_CHECK(ParseTransaction(dummyTx, nBlock, 1, metaTx) == 0);
        BOOST_CHECK_EQUAL(metaTx.getSender(), "ZzjEgpoT2pARc5Un7xRJAJ4LPSpA9qLQxd");
        BOOST_CHECK_EQUAL(HexStr(metaTx.getRaw()),
                // OpReturn_SimpleSend (without marker):
                "00000000000000070000000006dac2c0"
                // OpReturn_MultiSimpleSend (without marker):
                "00000000000000070000000000002329"
                "0062e907b15cbf27d5425399ebf6f0fb50ebb88f18"
                "000000000000001f0000000001406f40"
                "05da59767e81f4b019fe9f5984dbaa4f61bf197967");
    }
    {
        int nBlock = ConsensusParams().NULLDATA_BLOCK;

        std::vector<CTxOut> txInputs;
        txInputs.push_back(createTxOut(100000, "ZzjEgpoT2pARc5Un7xRJAJ4LPSpA9qLQxd"));

        std::vector<CTxOut> txOutputs;
        {
            CScript scriptPubKey;
            scriptPubKey << OP_RETURN;
            scriptPubKey << ParseHex("656c797369756d00000000000000010000000006dac2c0");
            scriptPubKey << ParseHex("00000000000000030000000000000d48");
            CTxOut txOut = CTxOut(0, scriptPubKey);
            txOutputs.push_back(txOut);
        }

        CTransaction dummyTx = TxClassC(txInputs, txOutputs);

        CMPTransaction metaTx;
        BOOST_CHECK(ParseTransaction(dummyTx, nBlock, 1, metaTx) == 0);
        BOOST_CHECK_EQUAL(metaTx.getSender(), "ZzjEgpoT2pARc5Un7xRJAJ4LPSpA9qLQxd");
        BOOST_CHECK_EQUAL(HexStr(metaTx.getRaw()),
                "00000000000000010000000006dac2c000000000000000030000000000000d48");
    }
    {
        int nBlock = std::numeric_limits<int>::max();

        std::vector<CTxOut> txInputs;
        txInputs.push_back(createTxOut(100000, "ZzjEgpoT2pARc5Un7xRJAJ4LPSpA9qLQxd"));

        std::vector<CTxOut> txOutputs;
        {
          CScript scriptPubKey;
          scriptPubKey << OP_RETURN;
          scriptPubKey << ParseHex("656c797369756d");
          scriptPubKey << ParseHex("00000000000000010000000006dac2c0");
          CTxOut txOut = CTxOut(0, scriptPubKey);
          txOutputs.push_back(txOut);
        }

        CTransaction dummyTx = TxClassC(txInputs, txOutputs);

        CMPTransaction metaTx;
        BOOST_CHECK(ParseTransaction(dummyTx, nBlock, 1, metaTx) == 0);
        BOOST_CHECK_EQUAL(HexStr(metaTx.getRaw()), "00000000000000010000000006dac2c0");
    }
    {
        /**
         * The following transaction is invalid, because the first pushed data
         * doesn't contain the class C marker.
         */
        int nBlock = ConsensusParams().NULLDATA_BLOCK;

        std::vector<CTxOut> txInputs;
        txInputs.push_back(createTxOut(100000, "3LzuqJs1deHYeFyJz5JXqrZXpuMk3GBEX2"));

        std::vector<CTxOut> txOutputs;
        {
            CScript scriptPubKey;
            scriptPubKey << OP_RETURN;
            scriptPubKey << ParseHex("6f6d");
            scriptPubKey << ParseHex("6e69");
            scriptPubKey << ParseHex("00000000000000010000000006dac2c0");
            CTxOut txOut = CTxOut(0, scriptPubKey);
            txOutputs.push_back(txOut);
        }

        CTransaction dummyTx = TxClassC(txInputs, txOutputs);

        CMPTransaction metaTx;
        BOOST_CHECK(ParseTransaction(dummyTx, nBlock, 1, metaTx) != 0);
    }
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace elysium
