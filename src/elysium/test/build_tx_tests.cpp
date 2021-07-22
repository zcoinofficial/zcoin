#include "../createtx.h"
#include "../errors.h"
#include "../elysium.h"
#include "../packetencoder.h"
#include "../utilsbitcoin.h"
#include "../wallettxs.h"

#include "../../base58.h"
#include "../../coins.h"
#include "../../core_io.h"
#include "../../validation.h"
#include "../../utilstrencodings.h"

#include "../../primitives/transaction.h"

#include "../../script/script.h"
#include "../../script/standard.h"

#include "../../test/test_bitcoin.h"
#include "../../test/fixtures.h"

#include "../../wallet/wallet.h"

#include <boost/optional/optional_io.hpp>
#include <boost/test/unit_test.hpp>

#include <string>
#include <utility>
#include <vector>

#include <inttypes.h>

using namespace std;

namespace elysium {

BOOST_FIXTURE_TEST_SUITE(elysium_build_tx_tests, ZerocoinTestingSetup200)

BOOST_AUTO_TEST_CASE(wallettxbuilder_create_normal_c)
{
    std::vector<unsigned char> data(80);

    std::string fromAddress = CBitcoinAddress(pubkey.GetID()).ToString();

    uint256 txid;
    std::string rawHex;
    BOOST_CHECK_EQUAL(
        0, // No error
        elysium::WalletTxBuilder(fromAddress, "", "", 0, data, txid, rawHex, false)
    );

    CMutableTransaction decTx;
    BOOST_CHECK(DecodeHexTx(decTx, rawHex));

    // BOOST_CHECK(!CTransaction(decTx).IsSigmaSpend());

    BOOST_CHECK_EQUAL(
        PacketClass::C,
        DeterminePacketClass(decTx, chainActive.Height())
    );
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace elysium
