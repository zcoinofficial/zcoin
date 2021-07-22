#include "elysium/consensushash.h"
#include "elysium/sp.h"
#include "elysium/elysium.h"
#include "elysium/rules.h"
#include "elysium/tally.h"

#include "arith_uint256.h"
#include "sync.h"
#include "test/test_bitcoin.h"
#include "uint256.h"

#include <boost/test/unit_test.hpp>

#include <stdint.h>
#include <string>

namespace elysium
{
extern std::string GenerateConsensusString(const CMPTally& tallyObj, const std::string& address, const uint32_t propertyId); // done
extern std::string GenerateConsensusString(const uint32_t propertyId, const std::string& address);
}

extern void clear_all_state();

using namespace elysium;

BOOST_FIXTURE_TEST_SUITE(elysium_checkpoint_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(consensus_string_tally)
{
    CMPTally tally;
    BOOST_CHECK_EQUAL("", GenerateConsensusString(tally, "3CwZ7FiQ4MqBenRdCkjjc41M5bnoKQGC2b", 1));
    BOOST_CHECK_EQUAL("", GenerateConsensusString(tally, "3CwZ7FiQ4MqBenRdCkjjc41M5bnoKQGC2b", 3));

    BOOST_CHECK(tally.updateMoney(3, 7, BALANCE));
    BOOST_CHECK_EQUAL("3CwZ7FiQ4MqBenRdCkjjc41M5bnoKQGC2b|3|7",
            GenerateConsensusString(tally, "3CwZ7FiQ4MqBenRdCkjjc41M5bnoKQGC2b", 3));

    BOOST_CHECK(tally.updateMoney(3, 7, BALANCE));
    BOOST_CHECK(tally.updateMoney(3, (-int64_t(9223372036854775807LL)-1), PENDING)); // ignored
    BOOST_CHECK_EQUAL("3CwZ7FiQ4MqBenRdCkjjc41M5bnoKQGC2b|3|14",
            GenerateConsensusString(tally, "3CwZ7FiQ4MqBenRdCkjjc41M5bnoKQGC2b", 3));
}


BOOST_AUTO_TEST_CASE(consensus_string_property_issuer)
{
    BOOST_CHECK_EQUAL("5|3CwZ7FiQ4MqBenRdCkjjc41M5bnoKQGC2b",
            GenerateConsensusString(5, "3CwZ7FiQ4MqBenRdCkjjc41M5bnoKQGC2b"));
}

BOOST_AUTO_TEST_SUITE_END()
