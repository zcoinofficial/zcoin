#include "../createpayload.h"
#include "../elysium.h"

#include "../../test/test_bitcoin.h"
#include "../../utilstrencodings.h"

#include <boost/test/unit_test.hpp>

#include <vector>
#include <string>

#include <inttypes.h>

namespace elysium {

BOOST_FIXTURE_TEST_SUITE(elysium_create_payload_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(payload_simple_send)
{
    // Simple send [type 0, version 0]
    std::vector<unsigned char> vch = CreatePayload_SimpleSend(
        static_cast<uint32_t>(1),          // property: MSC
        static_cast<int64_t>(100000000));  // amount to transfer: 1.0 MSC (in willets)

    BOOST_CHECK_EQUAL(HexStr(vch), "00000000000000010000000005f5e100");
}

BOOST_AUTO_TEST_CASE(payload_send_to_owners)
{
    // Send to owners [type 3, version 0] (same property)
    std::vector<unsigned char> vch = CreatePayload_SendToOwners(
        static_cast<uint32_t>(1),          // property: OMNI
        static_cast<int64_t>(100000000),   // amount to transfer: 1.0 OMNI (in willets)
        static_cast<uint32_t>(1));         // property: OMNI

    BOOST_CHECK_EQUAL(HexStr(vch), "00000003000000010000000005f5e100");
}

BOOST_AUTO_TEST_CASE(payload_send_to_owners_v1)
{
    // Send to owners [type 3, version 1] (cross property)
    std::vector<unsigned char> vch = CreatePayload_SendToOwners(
        static_cast<uint32_t>(1),          // property: OMNI
        static_cast<int64_t>(100000000),   // amount to transfer: 1.0 OMNI (in willets)
        static_cast<uint32_t>(3));         // property: SP#3

    BOOST_CHECK_EQUAL(HexStr(vch), "00010003000000010000000005f5e10000000003");
}

BOOST_AUTO_TEST_CASE(payload_send_all)
{
    // Send to owners [type 4, version 0]
    std::vector<unsigned char> vch = CreatePayload_SendAll(
        static_cast<uint8_t>(2));          // ecosystem: Test

    BOOST_CHECK_EQUAL(HexStr(vch), "0000000402");
}

BOOST_AUTO_TEST_CASE(payload_create_property)
{
    // Create property [type 50, version 0]
    std::vector<unsigned char> vch = CreatePayload_IssuanceFixed(
        static_cast<uint8_t>(1),             // ecosystem: main
        static_cast<uint16_t>(1),            // property type: indivisible tokens
        static_cast<uint32_t>(0),            // previous property: none
        std::string("Companies"),            // category
        std::string("Bitcoin Mining"),       // subcategory
        std::string("Quantum Miner"),        // label
        std::string("builder.bitwatch.co"),  // website
        std::string(""),                     // additional information
        static_cast<int64_t>(1000000));      // number of units to create

    BOOST_CHECK_EQUAL(HexStr(vch),
        "0000003201000100000000436f6d70616e69657300426974636f696e204d696e696e67"
        "005175616e74756d204d696e6572006275696c6465722e62697477617463682e636f00"
        "0000000000000f4240");
}

BOOST_AUTO_TEST_CASE(payload_create_property_empty)
{
    // Create property [type 50, version 0]
    std::vector<unsigned char> vch = CreatePayload_IssuanceFixed(
        static_cast<uint8_t>(1),         // ecosystem: main
        static_cast<uint16_t>(1),        // property type: indivisible tokens
        static_cast<uint32_t>(0),        // previous property: none
        std::string(""),                 // category
        std::string(""),                 // subcategory
        std::string(""),                 // label
        std::string(""),                 // website
        std::string(""),                 // additional information
        static_cast<int64_t>(1000000));  // number of units to create

    BOOST_CHECK_EQUAL(vch.size(), 24);
}

BOOST_AUTO_TEST_CASE(payload_create_property_full)
{
    // Create property [type 50, version 0]
    std::vector<unsigned char> vch = CreatePayload_IssuanceFixed(
        static_cast<uint8_t>(1),         // ecosystem: main
        static_cast<uint16_t>(1),        // property type: indivisible tokens
        static_cast<uint32_t>(0),        // previous property: none
        std::string(700, 'x'),           // category
        std::string(700, 'x'),           // subcategory
        std::string(700, 'x'),           // label
        std::string(700, 'x'),           // website
        std::string(700, 'x'),           // additional information
        static_cast<int64_t>(1000000));  // number of units to create

    BOOST_CHECK_EQUAL(vch.size(), 1299);
}

BOOST_AUTO_TEST_CASE(payload_create_managed_property)
{
    // create managed property [type 54, version 0]
    std::vector<unsigned char> vch = CreatePayload_IssuanceManaged(
        static_cast<uint8_t>(1),             // ecosystem: main
        static_cast<uint16_t>(1),            // property type: indivisible tokens
        static_cast<uint32_t>(0),            // previous property: none
        std::string("Companies"),            // category
        std::string("Bitcoin Mining"),       // subcategory
        std::string("Quantum Miner"),        // label
        std::string("builder.bitwatch.co"),  // website
        std::string(""));                    // additional information

    BOOST_CHECK_EQUAL(HexStr(vch),
        "0000003601000100000000436f6d70616e69657300426974636f696e204d696e696e67"
        "005175616e74756d204d696e6572006275696c6465722e62697477617463682e636f00"
        "00");
}

BOOST_AUTO_TEST_CASE(payload_create_managed_property_empty)
{
    // create managed property [type 54, version 0]
    std::vector<unsigned char> vch = CreatePayload_IssuanceManaged(
        static_cast<uint8_t>(1),   // ecosystem: main
        static_cast<uint16_t>(1),  // property type: indivisible tokens
        static_cast<uint32_t>(0),  // previous property: none
        std::string(""),           // category
        std::string(""),           // subcategory
        std::string(""),           // label
        std::string(""),           // website
        std::string(""));          // additional information

    BOOST_CHECK_EQUAL(vch.size(), 16);
}

BOOST_AUTO_TEST_CASE(payload_create_managed_property_full)
{
    // create managed property [type 54, version 0]
    std::vector<unsigned char> vch = CreatePayload_IssuanceManaged(
        static_cast<uint8_t>(1),   // ecosystem: main
        static_cast<uint16_t>(1),  // property type: indivisible tokens
        static_cast<uint32_t>(0),  // previous property: none
        std::string(700, 'x'),     // category
        std::string(700, 'x'),     // subcategory
        std::string(700, 'x'),     // label
        std::string(700, 'x'),     // website
        std::string(700, 'x'));    // additional information

    BOOST_CHECK_EQUAL(vch.size(), 1291);
}

BOOST_AUTO_TEST_CASE(payload_grant_tokens)
{
    // Grant tokens [type 55, version 0]
    std::vector<unsigned char> vch = CreatePayload_Grant(
        static_cast<uint32_t>(8),                  // property: SP #8
        static_cast<int64_t>(1000),                // number of units to issue
        std::string("First Milestone Reached!"));  // additional information

    BOOST_CHECK_EQUAL(HexStr(vch),
        "000000370000000800000000000003e84669727374204d696c6573746f6e6520526561"
        "636865642100");
}

BOOST_AUTO_TEST_CASE(payload_grant_tokens_empty)
{
    // Grant tokens [type 55, version 0]
    std::vector<unsigned char> vch = CreatePayload_Grant(
        static_cast<uint32_t>(8),                  // property: SP #8
        static_cast<int64_t>(1000),                // number of units to issue
        std::string(""));                          // additional information

    BOOST_CHECK_EQUAL(vch.size(), 17);
}

BOOST_AUTO_TEST_CASE(payload_grant_tokens_full)
{
    // Grant tokens [type 55, version 0]
    std::vector<unsigned char> vch = CreatePayload_Grant(
        static_cast<uint32_t>(8),                  // property: SP #8
        static_cast<int64_t>(1000),                // number of units to issue
        std::string(700, 'x'));                    // additional information

    BOOST_CHECK_EQUAL(vch.size(), 272);
}

BOOST_AUTO_TEST_CASE(payload_revoke_tokens)
{
    // Revoke tokens [type 56, version 0]
    std::vector<unsigned char> vch = CreatePayload_Revoke(
        static_cast<uint32_t>(8),                                   // property: SP #8
        static_cast<int64_t>(1000),                                 // number of units to revoke
        std::string("Redemption of tokens for Bob, Thanks Bob!"));  // additional information

    BOOST_CHECK_EQUAL(HexStr(vch),
        "000000380000000800000000000003e8526564656d7074696f6e206f6620746f6b656e"
        "7320666f7220426f622c205468616e6b7320426f622100");
}

BOOST_AUTO_TEST_CASE(payload_revoke_tokens_empty)
{
    // Revoke tokens [type 56, version 0]
    std::vector<unsigned char> vch = CreatePayload_Revoke(
        static_cast<uint32_t>(8),    // property: SP #8
        static_cast<int64_t>(1000),  // number of units to revoke
        std::string(""));            // additional information

    BOOST_CHECK_EQUAL(vch.size(), 17);
}

BOOST_AUTO_TEST_CASE(payload_revoke_tokens_full)
{
    // Revoke tokens [type 56, version 0]
    std::vector<unsigned char> vch = CreatePayload_Revoke(
        static_cast<uint32_t>(8),    // property: SP #8
        static_cast<int64_t>(1000),  // number of units to revoke
        std::string(700, 'x'));      // additional information

    BOOST_CHECK_EQUAL(vch.size(), 272);
}

BOOST_AUTO_TEST_CASE(payload_change_property_manager)
{
    // Change property manager [type 70, version 0]
    std::vector<unsigned char> vch = CreatePayload_ChangeIssuer(
        static_cast<uint32_t>(13));  // property: SP #13

    BOOST_CHECK_EQUAL(HexStr(vch), "000000460000000d");
}

BOOST_AUTO_TEST_CASE(payload_enable_freezing)
{
    // Enable freezing [type 71, version 0]
    std::vector<unsigned char> vch = CreatePayload_EnableFreezing(
        static_cast<uint32_t>(4));                 // property: SP #4

    BOOST_CHECK_EQUAL(HexStr(vch), "0000004700000004");
}

BOOST_AUTO_TEST_CASE(payload_disable_freezing)
{
    // Disable freezing [type 72, version 0]
    std::vector<unsigned char> vch = CreatePayload_DisableFreezing(
        static_cast<uint32_t>(4));                 // property: SP #4

    BOOST_CHECK_EQUAL(HexStr(vch), "0000004800000004");
}

BOOST_AUTO_TEST_CASE(payload_freeze_tokens)
{
    // Freeze tokens [type 185, version 0]
    std::vector<unsigned char> vch = CreatePayload_FreezeTokens(
        static_cast<uint32_t>(4),                                   // property: SP #4
        static_cast<int64_t>(1000),                                 // amount to freeze (unused)
        std::string("1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P"));         // reference address

    BOOST_CHECK_EQUAL(HexStr(vch),
        "000000b90000000400000000000003e800946cb2e08075bcbaf157e47bcb67eb2b2339d242");
}

BOOST_AUTO_TEST_CASE(payload_unfreeze_tokens)
{
    // Freeze tokens [type 186, version 0]
    std::vector<unsigned char> vch = CreatePayload_UnfreezeTokens(
        static_cast<uint32_t>(4),                                   // property: SP #4
        static_cast<int64_t>(1000),                                 // amount to freeze (unused)
        std::string("1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P"));         // reference address

    BOOST_CHECK_EQUAL(HexStr(vch),
        "000000ba0000000400000000000003e800946cb2e08075bcbaf157e47bcb67eb2b2339d242");
}

BOOST_AUTO_TEST_CASE(payload_feature_deactivation)
{
    // Elysium Core feature activation [type 65533, version 65535]
    std::vector<unsigned char> vch = CreatePayload_DeactivateFeature(
        static_cast<uint16_t>(1));        // feature identifier: 1 (OP_RETURN)

    BOOST_CHECK_EQUAL(HexStr(vch), "fffffffd0001");
}

BOOST_AUTO_TEST_CASE(payload_feature_activation)
{
    // Elysium Core feature activation [type 65534, version 65535]
    std::vector<unsigned char> vch = CreatePayload_ActivateFeature(
        static_cast<uint16_t>(1),        // feature identifier: 1 (OP_RETURN)
        static_cast<uint32_t>(370000),   // activation block
        static_cast<uint32_t>(999));     // min client version

    BOOST_CHECK_EQUAL(HexStr(vch), "fffffffe00010005a550000003e7");
}

BOOST_AUTO_TEST_CASE(payload_elysium_alert_block)
{
    // Elysium Core client notification [type 65535, version 65535]
    std::vector<unsigned char> vch = CreatePayload_ElysiumAlert(
        static_cast<int32_t>(1),            // alert target: by block number
        static_cast<uint64_t>(300000),      // expiry value: 300000
        static_cast<std::string>("test"));  // alert message: test

    BOOST_CHECK_EQUAL(HexStr(vch), "ffffffff0001000493e07465737400");
}

BOOST_AUTO_TEST_CASE(payload_elysium_alert_blockexpiry)
{
    // Elysium Core client notification [type 65535, version 65535]
    std::vector<unsigned char> vch = CreatePayload_ElysiumAlert(
        static_cast<int32_t>(2),            // alert target: by block time
        static_cast<uint64_t>(1439528630),  // expiry value: 1439528630
        static_cast<std::string>("test"));  // alert message: test

    BOOST_CHECK_EQUAL(HexStr(vch), "ffffffff000255cd76b67465737400");
}

BOOST_AUTO_TEST_CASE(payload_elysium_alert_minclient)
{
    // Elysium Core client notification [type 65535, version 65535]
    std::vector<unsigned char> vch = CreatePayload_ElysiumAlert(
        static_cast<int32_t>(3),            // alert target: by client version
        static_cast<uint64_t>(900100),      // expiry value: v0.0.9.1
        static_cast<std::string>("test"));  // alert message: test

    BOOST_CHECK_EQUAL(HexStr(vch), "ffffffff0003000dbc047465737400");
}


BOOST_AUTO_TEST_CASE(payload_create_lelantus_mint)
{
    std::string data = "353408b8878f73271f391935a2d628087010d82d3066a0f2262af686681a3b960000";
    std::string data2 = "62f60f65fdcf293c616fccab2a7caf6ecaf6c412321e52cc4737e1c09afa282beb000012cd84cfa478f74f46af852d3d97692d34b983fee6dc3e9ad7945ef810e73747d3cbb6a40fb4c53ebb267831b65de7981335e43caa7211a2be3b81d4c5e0e059";
    std::string data3 = "0100000000000000000000000000000000000000000000000000000000000000";

    lelantus::PublicCoin pubcoin;
    std::vector<unsigned char> schnorrProof;
    MintEntryId id;

    CDataStream(ParseHex(data), SER_NETWORK, CLIENT_VERSION) >> pubcoin;
    CDataStream(ParseHex(data2), SER_NETWORK, CLIENT_VERSION) >> schnorrProof;
    CDataStream(ParseHex(data3), SER_NETWORK, CLIENT_VERSION) >> id;

    // Simple mint [type 1027, version 0]
    std::vector<unsigned char> vch = CreatePayload_CreateLelantusMint(1, pubcoin, id, 100, schnorrProof);

    BOOST_CHECK_EQUAL(HexStr(vch),
        "0000040300000001" \
        "353408b8878f73271f391935a2d628087010d82d3066a0f2262af686681a3b960000" \
        "0100000000000000000000000000000000000000000000000000000000000000" \
        "0000000000000064" \
        "f60f65fdcf293c616fccab2a7caf6ecaf6c412321e52cc4737e1c09afa282beb000012cd84cfa478f74f46af852d3d97692d34b983fee6dc3e9ad7945ef810e73747d3cbb6a40fb4c53ebb267831b65de7981335e43caa7211a2be3b81d4c5e0e059"
    );
}

BOOST_AUTO_TEST_CASE(payload_create_lelantus_mint_invalid_schnorrproof_size)
{
    std::string data = "353408b8878f73271f391935a2d628087010d82d3066a0f2262af686681a3b960000";
    std::string data2 = "0100000000000000000000000000000000000000000000000000000000000000";

    lelantus::PublicCoin pubcoin;
    MintEntryId id;

    CDataStream(ParseHex(data), SER_NETWORK, CLIENT_VERSION) >> pubcoin;
    CDataStream(ParseHex(data2), SER_NETWORK, CLIENT_VERSION) >> id;

    BOOST_CHECK_THROW(CreatePayload_CreateLelantusMint(1, pubcoin, id, 100, std::vector<unsigned char>(32, 0x00)), std::invalid_argument);
    BOOST_CHECK_THROW(CreatePayload_CreateLelantusMint(1, pubcoin, id, 100, std::vector<unsigned char>(97, 0x00)), std::invalid_argument);
    BOOST_CHECK_NO_THROW(CreatePayload_CreateLelantusMint(1, pubcoin, id, 100, std::vector<unsigned char>(98, 0x00)));
    BOOST_CHECK_THROW(CreatePayload_CreateLelantusMint(1, pubcoin, id, 100, std::vector<unsigned char>(99, 0x00)), std::invalid_argument);
    BOOST_CHECK_THROW(CreatePayload_CreateLelantusMint(1, pubcoin, id, 100, std::vector<unsigned char>(1000, 0x00)), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(payload_create_lelantus_spend_without_change)
{
    // std::vector<std::pair<lelantus::PrivateCoin, uint32_t>> coins;
    // std::map<uint32_t, std::vector<lelantus::PublicCoin>> anonss;
    // LelantusAmount amount;
    // std::vector<lelantus::PrivateCoin> coinOuts;
    // std::map<uint32_t, uint256> groupBlockHashs;
    // uint256 metaData;

    // auto js = ::CreateJoinSplit(coins, anonss, 100, coinOuts, groupBlockHashs, metaData);
    // lelantus::

    // Simple mint [type 1027, version 0]
    // std::vector<unsigned char> vch = CreatePayload_CreateLelantusJoinSplit(1, 100);

    // BOOST_CHECK_EQUAL(HexStr(vch),
    //     "0000040300000001" \
    //     "353408b8878f73271f391935a2d628087010d82d3066a0f2262af686681a3b960000" \
    //     "0100000000000000000000000000000000000000000000000000000000000000" \
    //     "0000000000000064" \
    //     "f60f65fdcf293c616fccab2a7caf6ecaf6c412321e52cc4737e1c09afa282beb000012cd84cfa478f74f46af852d3d97692d34b983fee6dc3e9ad7945ef810e73747d3cbb6a40fb4c53ebb267831b65de7981335e43caa7211a2be3b81d4c5e0e059"
    // );
}

BOOST_AUTO_TEST_CASE(payload_create_change_lelantus_status)
{
    // Change property lelantus status [type 1029, version 0]
    std::vector<unsigned char> vch = CreatePayload_ChangeLelantusStatus(
        static_cast<uint32_t>(13), // property: SP #13
        LelantusStatus::SoftDisabled); // 0x00

    BOOST_CHECK_EQUAL(HexStr(vch), "000004050000000d00");
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace elysium
