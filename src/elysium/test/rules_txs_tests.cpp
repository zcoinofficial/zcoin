#include "../rules.h"
#include "../tx.h"

#include "../../test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

#include <limits>

#include <inttypes.h>

namespace elysium {

const int MAX_BLOCK = std::numeric_limits<int>::max();
const int MAX_VERSION = std::numeric_limits<uint16_t>::max();

BOOST_FIXTURE_TEST_SUITE(elysium_rules_txs_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(simple_send_restrictions)
{
    int ELYSIUM_SEND_BLOCK = ConsensusParams().ELYSIUM_SEND_BLOCK;

    BOOST_CHECK(!IsTransactionTypeAllowed(0,                ELYSIUM_PROPERTY_FIRO,  ELYSIUM_TYPE_SIMPLE_SEND, MP_TX_PKT_V0));
    BOOST_CHECK(!IsTransactionTypeAllowed(ELYSIUM_SEND_BLOCK,   ELYSIUM_PROPERTY_FIRO,  ELYSIUM_TYPE_SIMPLE_SEND, MP_TX_PKT_V0));
    BOOST_CHECK(!IsTransactionTypeAllowed(MAX_BLOCK,        ELYSIUM_PROPERTY_FIRO,  ELYSIUM_TYPE_SIMPLE_SEND, MAX_VERSION));
    BOOST_CHECK(!IsTransactionTypeAllowed(0,                ELYSIUM_PROPERTY_ELYSIUM,  ELYSIUM_TYPE_SIMPLE_SEND, MAX_VERSION));
    BOOST_CHECK(!IsTransactionTypeAllowed(ELYSIUM_SEND_BLOCK-1, ELYSIUM_PROPERTY_ELYSIUM,  ELYSIUM_TYPE_SIMPLE_SEND, MP_TX_PKT_V0));
    BOOST_CHECK(!IsTransactionTypeAllowed(MAX_BLOCK,        ELYSIUM_PROPERTY_ELYSIUM,  ELYSIUM_TYPE_SIMPLE_SEND, MP_TX_PKT_V1));
    BOOST_CHECK(!IsTransactionTypeAllowed(ELYSIUM_SEND_BLOCK,   ELYSIUM_PROPERTY_TELYSIUM, ELYSIUM_TYPE_SIMPLE_SEND, MAX_VERSION));
    BOOST_CHECK(!IsTransactionTypeAllowed(MAX_BLOCK,        ELYSIUM_PROPERTY_TELYSIUM, ELYSIUM_TYPE_SIMPLE_SEND, MP_TX_PKT_V1));

    BOOST_CHECK(IsTransactionTypeAllowed(ELYSIUM_SEND_BLOCK,    ELYSIUM_PROPERTY_ELYSIUM,  ELYSIUM_TYPE_SIMPLE_SEND, MP_TX_PKT_V0));
    BOOST_CHECK(IsTransactionTypeAllowed(MAX_BLOCK,         ELYSIUM_PROPERTY_ELYSIUM,  ELYSIUM_TYPE_SIMPLE_SEND, MP_TX_PKT_V0));
    BOOST_CHECK(IsTransactionTypeAllowed(0,                 ELYSIUM_PROPERTY_TELYSIUM, ELYSIUM_TYPE_SIMPLE_SEND, MP_TX_PKT_V0));
    BOOST_CHECK(IsTransactionTypeAllowed(MAX_BLOCK,         ELYSIUM_PROPERTY_TELYSIUM, ELYSIUM_TYPE_SIMPLE_SEND, MP_TX_PKT_V0));
}

BOOST_AUTO_TEST_SUITE_END()

}
