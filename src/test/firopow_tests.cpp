#include "test/testutil.h"
#include "test/fixtures.h"

#include <boost/test/unit_test.hpp>
#include <crypto/progpow/firopow_test_vectors.hpp>
#include <crypto/progpow/lib/ethash/ethash-internal.hpp>
#include <crypto/progpow/include/ethash/progpow.hpp>
#include <crypto/progpow/helpers.hpp>

BOOST_FIXTURE_TEST_SUITE(firpow_tests, BasicTestingSetup)
BOOST_AUTO_TEST_CASE(firopow_hash_and_verify) {

    ethash::epoch_context_ptr context{nullptr, nullptr};
    for(auto& t : firopow_hash_test_cases) {

        const auto epoch_number{ethash::get_epoch_number(t.block_number)};
        if (!context || context->epoch_number != epoch_number) {
            context = ethash::create_epoch_context(epoch_number);
        }

        const ethash::hash256 header{to_hash256(t.header_hash_hex)};
        const ethash::hash256 boundary{to_hash256(t.boundary_hex)};
        const uint64_t nonce{std::stoull(t.nonce_hex, nullptr, 16)};
        ethash::hash256 mix_hash{to_hash256(t.mix_hash_hex)};
        const ethash::hash256 final_hash{to_hash256(t.final_hash_hex)};

        auto result{progpow::hash(*context, t.block_number, header, nonce)};
        BOOST_CHECK(ethash::is_less_or_equal(result.final_hash, boundary)); // Must be below boundary
        BOOST_CHECK(ethash::is_equal(result.final_hash, final_hash));       // Must be equal to test case final_hash
        BOOST_CHECK(ethash::is_equal(result.mix_hash, mix_hash));           // Must be equal to test case mix_hash

        // Run verification
        BOOST_CHECK(progpow::verify(*context, t.block_number, header, mix_hash, nonce, boundary));

        // Tamper mix and rerun verification
        ++mix_hash.bytes[3];
        BOOST_CHECK_EQUAL(progpow::verify(*context, t.block_number, header, mix_hash, nonce, boundary), false);

    }
}

BOOST_AUTO_TEST_SUITE_END()
