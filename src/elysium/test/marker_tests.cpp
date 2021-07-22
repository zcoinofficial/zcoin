#include "utils_tx.h"

#include "../elysium.h"
#include "../packetencoder.h"
#include "../rules.h"
#include "../script.h"

#include "../../primitives/transaction.h"
#include "../../test/test_bitcoin.h"

#include <boost/optional/optional_io.hpp>
#include <boost/test/unit_test.hpp>

#include <limits>

namespace elysium {

BOOST_FIXTURE_TEST_SUITE(elysium_marker_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(class_no_marker)
{
    {
        int nBlock = std::numeric_limits<int>::max();

        CMutableTransaction mutableTx;
        CTransaction tx(mutableTx);

        BOOST_CHECK_EQUAL(DeterminePacketClass(tx, nBlock), boost::none);
    }
    {
        int nBlock = 0;

        CMutableTransaction mutableTx;
        mutableTx.vout.push_back(OpReturn_Unrelated());
        mutableTx.vout.push_back(PayToPubKeyHash_Unrelated());
        mutableTx.vout.push_back(NonStandardOutput());
        mutableTx.vout.push_back(OpReturn_UnrelatedShort());
        mutableTx.vout.push_back(OpReturn_Empty());
        mutableTx.vout.push_back(PayToPubKey_Unrelated());
        mutableTx.vout.push_back(PayToScriptHash_Unrelated());

        CTransaction tx(mutableTx);
        BOOST_CHECK_EQUAL(DeterminePacketClass(tx, nBlock), boost::none);
    }
    {
        int nBlock = std::numeric_limits<int>::max();

        CMutableTransaction mutableTx;
        mutableTx.vout.push_back(PayToPubKeyHash_Unrelated());
        mutableTx.vout.push_back(OpReturn_UnrelatedShort());
        mutableTx.vout.push_back(OpReturn_Unrelated());
        mutableTx.vout.push_back(PayToScriptHash_Unrelated());
        mutableTx.vout.push_back(PayToPubKey_Unrelated());
        mutableTx.vout.push_back(OpReturn_Empty());
        mutableTx.vout.push_back(NonStandardOutput());

        CTransaction tx(mutableTx);
        BOOST_CHECK_EQUAL(DeterminePacketClass(tx, nBlock), boost::none);
    }
    {
        int nBlock = std::numeric_limits<int>::max();

        CMutableTransaction mutableTx;
        mutableTx.vout.push_back(PayToPubKey_Unrelated());
        mutableTx.vout.push_back(PayToBareMultisig_3of5());
        mutableTx.vout.push_back(OpReturn_Unrelated());
        mutableTx.vout.push_back(NonStandardOutput());
        mutableTx.vout.push_back(OpReturn_UnrelatedShort());
        mutableTx.vout.push_back(PayToPubKeyHash_Unrelated());
        mutableTx.vout.push_back(PayToScriptHash_Unrelated());
        mutableTx.vout.push_back(OpReturn_Empty());
        mutableTx.vout.push_back(PayToBareMultisig_1of3());

        CTransaction tx(mutableTx);
        BOOST_CHECK_EQUAL(DeterminePacketClass(tx, nBlock), boost::none);
    }
}

/* BOOST_AUTO_TEST_CASE(class_class_b)
{
    {
        int nBlock = 0;

        CMutableTransaction mutableTx;
        mutableTx.vout.push_back(PayToPubKeyHash_Elysium());
        mutableTx.vout.push_back(PayToBareMultisig_1of3());

        CTransaction tx(mutableTx);
        BOOST_CHECK_EQUAL(DeterminePacketClass(tx, nBlock), PacketClass::B);
    }
    {
        int nBlock = ConsensusParams().NULLDATA_BLOCK;

        CMutableTransaction mutableTx;
        mutableTx.vout.push_back(PayToPubKey_Unrelated());
        mutableTx.vout.push_back(PayToBareMultisig_3of5());
        mutableTx.vout.push_back(PayToBareMultisig_3of5());
        mutableTx.vout.push_back(PayToPubKeyHash_Elysium());
        mutableTx.vout.push_back(PayToPubKey_Unrelated());

        CTransaction tx(mutableTx);
        BOOST_CHECK_EQUAL(DeterminePacketClass(tx, nBlock), PacketClass::B);
    }
    {
        int nBlock = 0;

        CMutableTransaction mutableTx;
        mutableTx.vout.push_back(OpReturn_Empty());
        mutableTx.vout.push_back(PayToPubKey_Unrelated());
        mutableTx.vout.push_back(PayToBareMultisig_1of3());
        mutableTx.vout.push_back(OpReturn_UnrelatedShort());
        mutableTx.vout.push_back(PayToPubKeyHash_Unrelated());
        mutableTx.vout.push_back(PayToBareMultisig_3of5());
        mutableTx.vout.push_back(OpReturn_Unrelated());
        mutableTx.vout.push_back(NonStandardOutput());
        mutableTx.vout.push_back(PayToScriptHash_Unrelated());
        mutableTx.vout.push_back(PayToPubKeyHash_Elysium());

        CTransaction tx(mutableTx);
        BOOST_CHECK_EQUAL(DeterminePacketClass(tx, nBlock), PacketClass::B);
    }
    {
        int nBlock = std::numeric_limits<int>::max();

        CMutableTransaction mutableTx;
        mutableTx.vout.push_back(OpReturn_UnrelatedShort());
        mutableTx.vout.push_back(PayToPubKeyHash_Elysium());
        mutableTx.vout.push_back(OpReturn_Empty());
        mutableTx.vout.push_back(PayToPubKey_Unrelated());
        mutableTx.vout.push_back(PayToPubKeyHash_Unrelated());
        mutableTx.vout.push_back(NonStandardOutput());
        mutableTx.vout.push_back(PayToBareMultisig_1of3());
        mutableTx.vout.push_back(PayToScriptHash_Unrelated());
        mutableTx.vout.push_back(OpReturn_Unrelated());

        CTransaction tx(mutableTx);
        BOOST_CHECK_EQUAL(DeterminePacketClass(tx, nBlock), PacketClass::B);
    }
}*/

BOOST_AUTO_TEST_CASE(class_class_c)
{
    {
        int nBlock = ConsensusParams().NULLDATA_BLOCK;

        CMutableTransaction mutableTx;
        mutableTx.vout.push_back(OpReturn_PlainMarker());

        CTransaction tx(mutableTx);
        BOOST_CHECK_EQUAL(DeterminePacketClass(tx, nBlock), PacketClass::C);
    }
    {
        int nBlock = std::numeric_limits<int>::max();

        CMutableTransaction mutableTx;
        mutableTx.vout.push_back(OpReturn_SimpleSend());
        mutableTx.vout.push_back(PayToScriptHash_Unrelated());
        mutableTx.vout.push_back(PayToScriptHash_Unrelated());

        CTransaction tx(mutableTx);
        BOOST_CHECK_EQUAL(DeterminePacketClass(tx, nBlock), PacketClass::C);
    }
    {
        int nBlock = std::numeric_limits<int>::max();

        CMutableTransaction mutableTx;
        mutableTx.vout.push_back(NonStandardOutput());
        mutableTx.vout.push_back(PayToScriptHash_Unrelated());
        mutableTx.vout.push_back(OpReturn_PlainMarker());
        mutableTx.vout.push_back(PayToPubKeyHash_Unrelated());
        mutableTx.vout.push_back(OpReturn_Empty());
        mutableTx.vout.push_back(OpReturn_Unrelated());
        mutableTx.vout.push_back(PayToPubKey_Unrelated());
        mutableTx.vout.push_back(OpReturn_UnrelatedShort());

        CTransaction tx(mutableTx);
        BOOST_CHECK_EQUAL(DeterminePacketClass(tx, nBlock), PacketClass::C);
    }
    {
        int nBlock = ConsensusParams().NULLDATA_BLOCK;

        CMutableTransaction mutableTx;
        mutableTx.vout.push_back(PayToScriptHash_Unrelated());
        mutableTx.vout.push_back(OpReturn_Unrelated());
        mutableTx.vout.push_back(OpReturn_UnrelatedShort());
        mutableTx.vout.push_back(OpReturn_Empty());
        mutableTx.vout.push_back(PayToPubKeyHash_Unrelated());
        mutableTx.vout.push_back(PayToBareMultisig_1of3());
        mutableTx.vout.push_back(NonStandardOutput());
        mutableTx.vout.push_back(PayToPubKey_Unrelated());
        mutableTx.vout.push_back(OpReturn_MultiSimpleSend());
        mutableTx.vout.push_back(PayToBareMultisig_3of5());

        CTransaction tx(mutableTx);
        BOOST_CHECK_EQUAL(DeterminePacketClass(tx, nBlock), PacketClass::C);
    }
    {
        int nBlock = std::numeric_limits<int>::max();

        CMutableTransaction mutableTx;
        mutableTx.vout.push_back(OpReturn_UnrelatedShort());
        mutableTx.vout.push_back(PayToPubKey_Unrelated());
        mutableTx.vout.push_back(OpReturn_Unrelated());
        mutableTx.vout.push_back(OpReturn_Empty());
        mutableTx.vout.push_back(PayToPubKeyHash_Unrelated());
        mutableTx.vout.push_back(PayToScriptHash_Unrelated());
        mutableTx.vout.push_back(NonStandardOutput());
        mutableTx.vout.push_back(OpReturn_PlainMarker());

        CTransaction tx(mutableTx);
        BOOST_CHECK_EQUAL(DeterminePacketClass(tx, nBlock), PacketClass::C);
    }
    {
        int nBlock = ConsensusParams().NULLDATA_BLOCK;

        CMutableTransaction mutableTx;
        mutableTx.vout.push_back(PayToPubKey_Unrelated());
        mutableTx.vout.push_back(OpReturn_MultiSimpleSend());
        mutableTx.vout.push_back(PayToBareMultisig_1of3());
        mutableTx.vout.push_back(PayToBareMultisig_1of3());
        mutableTx.vout.push_back(OpReturn_SimpleSend());
        mutableTx.vout.push_back(PayToPubKeyHash_Unrelated());
        mutableTx.vout.push_back(PayToScriptHash_Unrelated());
        mutableTx.vout.push_back(NonStandardOutput());
        mutableTx.vout.push_back(OpReturn_PlainMarker());
        mutableTx.vout.push_back(PayToPubKeyHash_Elysium());

        CTransaction tx(mutableTx);
        BOOST_CHECK_EQUAL(DeterminePacketClass(tx, nBlock), PacketClass::C);
    }
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace elysium
