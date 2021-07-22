#include "../params.h"
#include "../sigmaplus_prover.h"
#include "../sigmaplus_verifier.h"

#include <boost/test/unit_test.hpp>

#include "../../test/fixtures.h"

BOOST_FIXTURE_TEST_SUITE(sigma_protocol_tests, ZerocoinTestingSetup200)

BOOST_AUTO_TEST_CASE(one_out_of_n)
{
    auto params = sigma::Params::get_default();
    std::size_t N = 16384;
    std::size_t n = params->get_n();
    std::size_t m = params->get_m();
    std::size_t index = 0;

    secp_primitives::GroupElement g;
    g.randomize();
    std::vector<secp_primitives::GroupElement> h_gens;
    h_gens.resize(n * m);
    for (std::size_t i = 0; i < n * m; ++i ){
        h_gens[i].randomize();
    }
    secp_primitives::Scalar r;
    r.randomize();
    sigma::SigmaPlusProver<secp_primitives::Scalar,secp_primitives::GroupElement> prover(g,h_gens, n, m);

    std::vector<secp_primitives::GroupElement> commits;
    for (std::size_t i = 0; i < N; ++i) {
        if (i == index) {
            secp_primitives::GroupElement c;
            secp_primitives::Scalar zero(uint64_t(0));
            c = sigma::SigmaPrimitives<secp_primitives::Scalar,secp_primitives::GroupElement>::commit(g, zero, h_gens[0], r);
            commits.push_back(c);

        }
        else {
            commits.push_back(secp_primitives::GroupElement());
            commits[i].randomize();
        }
    }
    sigma::SigmaPlusProof<secp_primitives::Scalar,secp_primitives::GroupElement> proof(n, m);

    prover.proof(commits, index, r, true, proof);

    sigma::SigmaPlusVerifier<secp_primitives::Scalar,secp_primitives::GroupElement> verifier(g, h_gens, n, m);

    BOOST_CHECK(verifier.verify(commits, proof, true));
}

BOOST_AUTO_TEST_CASE(one_out_of_n_batch)
{
    auto params = sigma::Params::get_default();
    const secp_primitives::Scalar zero(uint64_t(0));
    const std::size_t N = 16000; // n^m == 16384
    const std::size_t n = params->get_n();
    const std::size_t m = params->get_m();
    const std::vector<std::size_t> index = { 0, 1, 2, N - 1 };
    const std::vector<std::size_t> set_sizes = { N, N - 1, N - 1, 16 };
    const std::vector<secp_primitives::Scalar> serials = { zero, zero, zero, zero };
    const std::vector<bool> fPadding = { true, true, true, true };

    // Generators
    secp_primitives::GroupElement g;
    g.randomize();
    std::vector<secp_primitives::GroupElement> h_gens;
    h_gens.resize(n * m);
    for (std::size_t i = 0; i < n * m; ++i ){
        h_gens[i].randomize();
    }
    sigma::SigmaPlusProver<secp_primitives::Scalar,secp_primitives::GroupElement> prover(g, h_gens, n, m);

    std::vector<secp_primitives::GroupElement> commits;

    // All commitments
    for (std::size_t i = 0; i < N; ++i) {
        commits.push_back(secp_primitives::GroupElement());
        commits[i].randomize();
    }

    // Known commitments
    std::vector<Scalar> r;
    r.resize(index.size());
    for (std::size_t i = 0; i < index.size(); i++) {
        r[i].randomize();
        commits[index[i]] = h_gens[0] * r[i];
    }

    // Build the proofs
    std::vector<sigma::SigmaPlusProof<secp_primitives::Scalar,secp_primitives::GroupElement>> proofs;
    proofs.reserve(index.size());
    sigma::SigmaPlusVerifier<secp_primitives::Scalar,secp_primitives::GroupElement> verifier(g, h_gens, n, m);
    for (std::size_t i = 0; i < index.size(); i++) {
        sigma::SigmaPlusProof<secp_primitives::Scalar,secp_primitives::GroupElement> proof(n, m);
        std::vector<secp_primitives::GroupElement> commits_(commits.begin() + N - set_sizes[i], commits.end());

        // Check commitment validity and prove
        BOOST_CHECK(h_gens[0] * r[i] == commits[index[i]]);
        BOOST_CHECK(h_gens[0] * r[i] == commits_[index[i] - (N - set_sizes[i])]);
        prover.proof(commits_, index[i] - (N - set_sizes[i]), r[i], true, proof);
        proofs.emplace_back(proof);

        // Test individual verification
        BOOST_CHECK(verifier.verify(commits_, proof, true));
        BOOST_CHECK(verifier.verify(commits, proof, true, set_sizes[i]));
    }

    // Test batch verification
    BOOST_CHECK(verifier.batch_verify(commits, serials, fPadding, set_sizes, proofs));

    // Invalidate the batch
    proofs[0] = proofs[1];
    BOOST_CHECK(!verifier.batch_verify(commits, serials, fPadding, set_sizes, proofs));
}

BOOST_AUTO_TEST_CASE(one_out_of_n_padding)
{
    auto params = sigma::Params::get_default();
    int N = 10000;
    int n = params->get_n();
    int m = params->get_m();
    int index = 9999;

    secp_primitives::GroupElement g;
    g.randomize();
    std::vector<secp_primitives::GroupElement> h_gens;
    h_gens.resize(n * m);
    for(int i = 0; i < n * m; ++i ){
        h_gens[i].randomize();
    }
    secp_primitives::Scalar r;
    r.randomize();
    sigma::SigmaPlusProver<secp_primitives::Scalar,secp_primitives::GroupElement> prover(g,h_gens, n, m);

    std::vector<secp_primitives::GroupElement> commits;
    for(int i = 0; i < N; ++i){
        if(i == index){
            secp_primitives::GroupElement c;
            secp_primitives::Scalar zero(uint64_t(0));
            c = sigma::SigmaPrimitives<secp_primitives::Scalar,secp_primitives::GroupElement>::commit(g, zero, h_gens[0], r);
            commits.push_back(c);

        }
        else{
            commits.push_back(secp_primitives::GroupElement());
            commits[i].randomize();
        }
    }
    sigma::SigmaPlusProof<secp_primitives::Scalar,secp_primitives::GroupElement> proof(n, m);

    prover.proof(commits, index, r, true, proof);

    sigma::SigmaPlusVerifier<secp_primitives::Scalar,secp_primitives::GroupElement> verifier(g, h_gens, n, m);

    BOOST_CHECK(verifier.verify(commits, proof, true));

    sigma::SigmaPlusProof<secp_primitives::Scalar,secp_primitives::GroupElement> proofNew(n, m);
    prover.proof(commits, 11111, r, true, proofNew);
    BOOST_CHECK(verifier.verify(commits, proofNew, true));
}

BOOST_AUTO_TEST_CASE(prove_and_verify_in_different_set)
{
    auto params = sigma::Params::get_default();
    int N = 16384;
    int n = params->get_n();
    int m = params->get_m();
    int index = 0;

    secp_primitives::GroupElement g;
    g.randomize();
    std::vector<secp_primitives::GroupElement> h_gens;
    h_gens.resize(n * m);
    for(int i = 0; i < n * m; ++i ){
        h_gens[i].randomize();
    }
    secp_primitives::Scalar r;
    r.randomize();
    sigma::SigmaPlusProver<secp_primitives::Scalar,secp_primitives::GroupElement> prover(g,h_gens, n, m);

    std::vector<secp_primitives::GroupElement> commits;
    for(int i = 0; i < N; ++i){
        if(i == index){
            secp_primitives::GroupElement c;
            secp_primitives::Scalar zero(uint64_t(0));
            c = sigma::SigmaPrimitives<secp_primitives::Scalar,secp_primitives::GroupElement>::commit(g, zero, h_gens[0], r);
            commits.push_back(c);

        }
        else{
            commits.push_back(secp_primitives::GroupElement());
            commits[i].randomize();
        }
    }

    sigma::SigmaPlusProof<secp_primitives::Scalar,secp_primitives::GroupElement> proof(n, m);

    prover.proof(commits, index, r, true, proof);

    sigma::SigmaPlusVerifier<secp_primitives::Scalar,secp_primitives::GroupElement> verifier(g, h_gens, n, m);

    // Add more commit
    secp_primitives::GroupElement c;
    secp_primitives::Scalar zero(uint64_t(0));
    c = sigma::SigmaPrimitives<secp_primitives::Scalar,secp_primitives::GroupElement>::commit(g, zero, h_gens[0], r);
    commits.push_back(c);

    BOOST_CHECK(!verifier.verify(commits, proof, true));
}

BOOST_AUTO_TEST_CASE(prove_coin_out_of_index)
{
    auto params = sigma::Params::get_default();
    int N = 16384;
    int n = params->get_n();
    int m = params->get_m();

    secp_primitives::GroupElement g;
    g.randomize();
    std::vector<secp_primitives::GroupElement> h_gens;
    h_gens.resize(n * m);
    for(int i = 0; i < n * m; ++i ){
        h_gens[i].randomize();
    }
    secp_primitives::Scalar r;
    r.randomize();
    sigma::SigmaPlusProver<secp_primitives::Scalar,secp_primitives::GroupElement> prover(g,h_gens, n, m);

    std::vector<secp_primitives::GroupElement> commits;
    for(int i = 0; i < N; ++i){
        commits.push_back(secp_primitives::GroupElement());
        commits[i].randomize();
    }

    sigma::SigmaPlusProof<secp_primitives::Scalar,secp_primitives::GroupElement> proof(n, m);

    prover.proof(commits, commits.size(), r, true, proof);

    sigma::SigmaPlusVerifier<secp_primitives::Scalar,secp_primitives::GroupElement> verifier(g, h_gens, n, m);
    BOOST_CHECK(!verifier.verify(commits, proof, true));
}

BOOST_AUTO_TEST_CASE(prove_coin_not_in_set)
{
    auto params = sigma::Params::get_default();
    int N = 16384;
    int n = params->get_n();
    int m = params->get_m();
    int index = 0;
    secp_primitives::GroupElement g;
    g.randomize();
    std::vector<secp_primitives::GroupElement> h_gens;
    h_gens.resize(n * m);
    for(int i = 0; i < n * m; ++i ){
        h_gens[i].randomize();
    }
    secp_primitives::Scalar r;
    r.randomize();
    sigma::SigmaPlusProver<secp_primitives::Scalar,secp_primitives::GroupElement> prover(g,h_gens, n, m);

    std::vector<secp_primitives::GroupElement> commits;
    for(int i = 0; i < N; ++i){
        commits.push_back(secp_primitives::GroupElement());
        commits[i].randomize();
    }

    sigma::SigmaPlusProof<secp_primitives::Scalar,secp_primitives::GroupElement> proof(n, m);

    prover.proof(commits, index, r, true, proof);

    sigma::SigmaPlusVerifier<secp_primitives::Scalar,secp_primitives::GroupElement> verifier(g, h_gens, n, m);
    BOOST_CHECK(!verifier.verify(commits, proof, true));
}

BOOST_AUTO_TEST_SUITE_END()
