#include "lelantus_test_fixture.h"

#include "../range_prover.h"
#include "../range_verifier.h"

#include <boost/test/unit_test.hpp>

namespace lelantus {

BOOST_FIXTURE_TEST_SUITE(lelantus_range_proof_tests, LelantusTestingSetup)

// A single valid aggregated range proof
BOOST_AUTO_TEST_CASE(prove_verify_single)
{
    // Parameters
    std::size_t n = 64;
    std::size_t max_m = 8;

    // Generators
    secp_primitives::GroupElement g_gen, h_gen1, h_gen2;
    g_gen.randomize();
    h_gen1.randomize();
    h_gen2.randomize();

    auto prove_verify = [&] (std::size_t m) {
        auto g_ = RandomizeGroupElements(n * m);
        auto h_ = RandomizeGroupElements(n * m);

        // Input data
        auto serials = RandomizeScalars(m);
        auto randoms = RandomizeScalars(m);

        std::vector<secp_primitives::Scalar> v_s;
        std::vector<secp_primitives::GroupElement> V;
        for (std::size_t i = 0; i < m; ++i){
            v_s.emplace_back(i);
            V.push_back(g_gen * v_s.back() +  h_gen1 * randoms[i] + h_gen2 * serials[i]);
        }

        // Prove
        RangeProver rangeProver(g_gen, h_gen1, h_gen2, g_, h_, n, LELANTUS_TX_VERSION_4_5);
        RangeProof proof;
        rangeProver.proof(v_s, serials, randoms, V, proof);

        // Verify
        RangeVerifier rangeVerifier(g_gen, h_gen1, h_gen2, g_, h_, n, LELANTUS_TX_VERSION_4_5);
        BOOST_CHECK(rangeVerifier.verify(V, V, proof));
    };

    // Test powers of 2
    std::size_t i = 1;
    while (i <= max_m) {
        prove_verify(i);
        i *= 2;
    }

}

// A batch of valid aggregated range proofs of different size
BOOST_AUTO_TEST_CASE(prove_verify_batch)
{
    // Parameters
    const std::size_t n = 64;
    const std::vector<std::size_t> m = {1,2,4,8};

    // Generators
    secp_primitives::GroupElement g_gen, h_gen1, h_gen2;
    g_gen.randomize();
    h_gen1.randomize();
    h_gen2.randomize();
    std::size_t max_m = *std::max_element(m.begin(), m.end());
    auto g_ = RandomizeGroupElements(n * max_m);
    auto h_ = RandomizeGroupElements(n * max_m);

    // Proofs
    std::vector<std::vector<GroupElement> > V_batch;
    V_batch.reserve(m.size());
    std::vector<RangeProof> proof_batch;
    proof_batch.reserve(m.size());
    for (std::size_t i = 0; i < m.size(); i++) {
        RangeProver rangeProver(g_gen, h_gen1, h_gen2, std::vector<GroupElement>(g_.begin(), g_.begin() + n * m[i]), std::vector<GroupElement>(h_.begin(), h_.begin() + n * m[i]), n, LELANTUS_TX_VERSION_4_5);

        // Input data
        auto serials = RandomizeScalars(m[i]);
        auto randoms = RandomizeScalars(m[i]);

        std::vector<secp_primitives::Scalar> v_s;
        std::vector<secp_primitives::GroupElement> V;
        for (std::size_t j = 0; j < m[i]; ++j){
            v_s.emplace_back(j);
            V.push_back(g_gen * v_s.back() +  h_gen1 * randoms[j] + h_gen2 * serials[j]);
        }

        // Prove
        RangeProof proof;
        rangeProver.proof(v_s, serials, randoms, V, proof);
        V_batch.emplace_back(V);
        proof_batch.emplace_back(proof);
    }

    // Verify
    RangeVerifier rangeVerifier(g_gen, h_gen1, h_gen2, g_, h_, n, LELANTUS_TX_VERSION_4_5);
    BOOST_CHECK(rangeVerifier.verify(V_batch, V_batch, proof_batch));
}

// A single out-of-range aggregated range proof
BOOST_AUTO_TEST_CASE(out_of_range_single_proof)
{
    // Parameters
    std::size_t n = 4;
    std::size_t m = 4;

    // Generators
    secp_primitives::GroupElement g_gen, h_gen1, h_gen2;
    g_gen.randomize();
    h_gen1.randomize();
    h_gen2.randomize();
    auto g_ = RandomizeGroupElements(n * m);
    auto h_ = RandomizeGroupElements(n * m);

    // Input data
    auto randoms = RandomizeScalars(m);
    auto serials = RandomizeScalars(m);

    auto testF = [&] (std::vector<Scalar> const v_s) {
        std::vector<GroupElement> V;
        for (std::size_t i = 0; i < m; ++i) {
            V.push_back(g_gen * v_s[i] +  h_gen1 * randoms[i] + h_gen2 * serials[i]);
        }

        lelantus::RangeProver rangeProver(g_gen, h_gen1, h_gen2, g_, h_, n, LELANTUS_TX_VERSION_4_5);
        lelantus::RangeProof proof;
        rangeProver.proof(v_s, serials, randoms, V, proof );

        lelantus::RangeVerifier rangeVerifier(g_gen, h_gen1, h_gen2, g_, h_, n, LELANTUS_TX_VERSION_4_5);
        BOOST_CHECK(!rangeVerifier.verify(V, V, proof));
    };

    // All values are out of range
    std::vector<Scalar> vs;
    for(std::size_t i = 0; i < m; ++i){
        vs.emplace_back((1 << n) + i);
    }
    testF(vs);

    // [0, 2 ^ n - 1]
    Scalar l(uint64_t(0));
    Scalar r((1 << n) - 1);

    // One value is out of range
    vs = {l, l + 1, r, r + 1};
    testF(vs);

    vs = {l - 1, l, r - 1, r};
    testF(vs);
}

// A single aggreated range proof, with successively invalid proof elements
BOOST_AUTO_TEST_CASE(invalid_elements)
{
    // Parameters
    std::size_t n = 64;
    std::size_t m = 4;

    // Generators
    secp_primitives::GroupElement g_gen, h_gen1, h_gen2;
    g_gen.randomize();
    h_gen1.randomize();
    h_gen2.randomize();
    auto g_ = RandomizeGroupElements(n * m);
    auto h_ = RandomizeGroupElements(n * m);

    // Inputs
    auto randoms = RandomizeScalars(m);
    auto serials = RandomizeScalars(m);

    // Set up valid proof
    std::vector<secp_primitives::Scalar> v_s;
    std::vector<secp_primitives::GroupElement> V;
    for(std::size_t i = 0; i < m; ++i){
        v_s.emplace_back(i);
        V.push_back(g_gen * v_s.back() +  h_gen1 * randoms[i] + h_gen2 * serials[i]);
    }

    // Initial correctness check
    RangeProver rangeProver(g_gen, h_gen1, h_gen2, g_, h_, n, LELANTUS_TX_VERSION_4_5);
    RangeProof proof;
    rangeProver.proof(v_s, serials, randoms, V, proof);
    RangeVerifier rangeVerifier(g_gen, h_gen1, h_gen2, g_, h_, n, LELANTUS_TX_VERSION_4_5);
    BOOST_CHECK(rangeVerifier.verify(V, V, proof));

    // Invalidate successive values and then restore them
    GroupElement group;
    Scalar scalar;

    group = GroupElement(proof.A);
    proof.A.randomize();
    BOOST_CHECK(!rangeVerifier.verify(V, V, proof));
    proof.A = GroupElement(group);
    BOOST_CHECK(rangeVerifier.verify(V, V, proof));

    group = GroupElement(proof.S);
    proof.S.randomize();
    BOOST_CHECK(!rangeVerifier.verify(V, V, proof));
    proof.S = GroupElement(group);
    BOOST_CHECK(rangeVerifier.verify(V, V, proof));

    group = GroupElement(proof.T1);
    proof.T1.randomize();
    BOOST_CHECK(!rangeVerifier.verify(V, V, proof));
    proof.T1 = GroupElement(group);
    BOOST_CHECK(rangeVerifier.verify(V, V, proof));

    group = GroupElement(proof.T2);
    proof.T2.randomize();
    BOOST_CHECK(!rangeVerifier.verify(V, V, proof));
    proof.T2 = GroupElement(group);
    BOOST_CHECK(rangeVerifier.verify(V, V, proof));

    for (std::size_t j = 0; j < proof.innerProductProof.L_.size(); j++) {
        group = GroupElement(proof.innerProductProof.L_[j]);
        proof.innerProductProof.L_[j].randomize();
        BOOST_CHECK(!rangeVerifier.verify(V, V, proof));
        proof.innerProductProof.L_[j] = GroupElement(group);
        BOOST_CHECK(rangeVerifier.verify(V, V, proof));

        group = GroupElement(proof.innerProductProof.R_[j]);
        proof.innerProductProof.R_[j].randomize();
        BOOST_CHECK(!rangeVerifier.verify(V, V, proof));
        proof.innerProductProof.R_[j] = GroupElement(group);
        BOOST_CHECK(rangeVerifier.verify(V, V, proof));
    }

    scalar = Scalar(proof.T_x1);
    proof.T_x1.randomize();
    BOOST_CHECK(!rangeVerifier.verify(V, V, proof));
    proof.T_x1 = Scalar(scalar);
    BOOST_CHECK(rangeVerifier.verify(V, V, proof));

    scalar = Scalar(proof.T_x2);
    proof.T_x2.randomize();
    BOOST_CHECK(!rangeVerifier.verify(V, V, proof));
    proof.T_x2 = Scalar(scalar);
    BOOST_CHECK(rangeVerifier.verify(V, V, proof));

    scalar = Scalar(proof.u);
    proof.u.randomize();
    BOOST_CHECK(!rangeVerifier.verify(V, V, proof));
    proof.u = Scalar(scalar);
    BOOST_CHECK(rangeVerifier.verify(V, V, proof));

    scalar = Scalar(proof.innerProductProof.a_);
    proof.innerProductProof.a_.randomize();
    BOOST_CHECK(!rangeVerifier.verify(V, V, proof));
    proof.innerProductProof.a_ = Scalar(scalar);
    BOOST_CHECK(rangeVerifier.verify(V, V, proof));

    scalar = Scalar(proof.innerProductProof.b_);
    proof.innerProductProof.b_.randomize();
    BOOST_CHECK(!rangeVerifier.verify(V, V, proof));
    proof.innerProductProof.b_ = Scalar(scalar);
    BOOST_CHECK(rangeVerifier.verify(V, V, proof));

    scalar = Scalar(proof.innerProductProof.c_);
    proof.innerProductProof.c_.randomize();
    BOOST_CHECK(!rangeVerifier.verify(V, V, proof));
    proof.innerProductProof.c_ = Scalar(scalar);
    BOOST_CHECK(rangeVerifier.verify(V, V, proof));
}

// A batch of range proofs, one of which is invalid
BOOST_AUTO_TEST_CASE(invalid_batch)
{
    // Parameters
    const std::size_t n = 64;
    const std::vector<std::size_t> m = {1,2,4,8};

    // Generators
    secp_primitives::GroupElement g_gen, h_gen1, h_gen2;
    g_gen.randomize();
    h_gen1.randomize();
    h_gen2.randomize();
    std::size_t max_m = *std::max_element(m.begin(), m.end());
    auto g_ = RandomizeGroupElements(n * max_m);
    auto h_ = RandomizeGroupElements(n * max_m);

    // Proofs
    std::vector<std::vector<GroupElement> > V_batch;
    V_batch.reserve(m.size());
    std::vector<RangeProof> proof_batch;
    proof_batch.reserve(m.size());
    for (std::size_t i = 0; i < m.size(); i++) {
        RangeProver rangeProver(g_gen, h_gen1, h_gen2, std::vector<GroupElement>(g_.begin(), g_.begin() + n * m[i]), std::vector<GroupElement>(h_.begin(), h_.begin() + n * m[i]), n, LELANTUS_TX_VERSION_4_5);

        // Input data
        auto serials = RandomizeScalars(m[i]);
        auto randoms = RandomizeScalars(m[i]);

        std::vector<secp_primitives::Scalar> v_s;
        std::vector<secp_primitives::GroupElement> V;
        for (std::size_t j = 0; j < m[i]; ++j){
            v_s.emplace_back(j);
            V.push_back(g_gen * v_s.back() +  h_gen1 * randoms[j] + h_gen2 * serials[j]);
        }

        // Prove
        RangeProof proof;
        rangeProver.proof(v_s, serials, randoms, V, proof);
        V_batch.emplace_back(V);
        proof_batch.emplace_back(proof);
    }

    // Invalidate one of the proofs
    proof_batch[0].A.randomize();

    // Verify
    RangeVerifier rangeVerifier(g_gen, h_gen1, h_gen2, g_, h_, n, LELANTUS_TX_VERSION_4_5);
    BOOST_CHECK(!rangeVerifier.verify(V_batch, V_batch, proof_batch));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace lelantus