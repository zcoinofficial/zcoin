#include "../packetencoder.h"
#include "../script.h"

#include "../../utilstrencodings.h"

#include "../../script/script.h"

#include "../../test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

#include <string>
#include <utility>
#include <vector>

#include <inttypes.h>

using namespace elysium;

// Is resetted to a norm value in each test
extern unsigned nMaxDatacarrierBytes;

BOOST_FIXTURE_TEST_SUITE(elysium_encoding_c_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(class_c_marker)
{
    // Store initial data carrier size
    unsigned nMaxDatacarrierBytesOriginal = nMaxDatacarrierBytes;

    nMaxDatacarrierBytes = 40; // byte

    std::vector<unsigned char> vchMarker;
    vchMarker.push_back('e');
    vchMarker.push_back('l');
    vchMarker.push_back('y');
    vchMarker.push_back('s');
    vchMarker.push_back('i');
    vchMarker.push_back('u');
    vchMarker.push_back('m');

    std::vector<unsigned char> vchPayload = ParseHex(
        "00000000000000010000000006dac2c0");

    auto scriptData = EncodeClassC(vchPayload.begin(), vchPayload.end()).scriptPubKey;

    std::vector<std::vector<unsigned char>> pushes;
    GetPushedValues(scriptData, std::back_inserter(pushes));
    BOOST_CHECK_EQUAL(pushes.size(), 1);

    // The embedded data has a size of the payload plus marker
    BOOST_CHECK_EQUAL(
            pushes[0].size(),
            vchMarker.size() + vchPayload.size());

    // The output script really starts with the marker
    for (size_t n = 0; n < vchMarker.size(); ++n) {
        BOOST_CHECK_EQUAL(vchMarker[n], pushes[0][n]);
    }

    // The output script really ends with the payload
    std::vector<unsigned char> vchEmbeddedPayload(
        pushes[0].begin() + vchMarker.size(),
        pushes[0].end());

    BOOST_CHECK_EQUAL(HexStr(vchEmbeddedPayload), HexStr(vchPayload));

    // Restore original data carrier size settings
    nMaxDatacarrierBytes = nMaxDatacarrierBytesOriginal;
}

BOOST_AUTO_TEST_CASE(class_c_with_empty_payload)
{
    // Store initial data carrier size
    unsigned nMaxDatacarrierBytesOriginal = nMaxDatacarrierBytes;

    const std::vector<unsigned char> vchEmptyPayload;

    // Even less than the size of the marker
    nMaxDatacarrierBytes = 0; // byte

    BOOST_CHECK_THROW(EncodeClassC(vchEmptyPayload.begin(), vchEmptyPayload.end()), std::invalid_argument);

    // Exactly the size of the marker
    nMaxDatacarrierBytes = 9; // byte

    BOOST_CHECK_NO_THROW(EncodeClassC(vchEmptyPayload.begin(), vchEmptyPayload.end()));

    // Restore original data carrier size settings
    nMaxDatacarrierBytes = nMaxDatacarrierBytesOriginal;
}


BOOST_AUTO_TEST_SUITE_END()
