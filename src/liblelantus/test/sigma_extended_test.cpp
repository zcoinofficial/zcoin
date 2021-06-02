#include "../sigmaextended_prover.h"
#include "../sigmaextended_verifier.h"

#include "lelantus_test_fixture.h"

#include <boost/test/unit_test.hpp>

namespace lelantus {

class SigmaExtendedTests : public LelantusTestingSetup {
public:
    struct Secret {
    public:
        Secret(std::size_t l) : l(l) {
            s.randomize();
            v.randomize();
            r.randomize();
        }

    public:
        std::size_t l;
        Scalar s, v, r;
    };

public:
    typedef SigmaExtendedProver Prover;
    typedef SigmaExtendedProof Proof;
    typedef SigmaExtendedVerifier Verifier;

public:
    SigmaExtendedTests() {}

public:
    void GenerateParams(std::size_t _N, std::size_t _n, std::size_t _m = 0) {
        N = _N;
        n = _n;
        m = _m;
        if (!m) {
            if (n <= 1) {
                throw std::logic_error("Try to get value of m from invalid n");
            }

            m = (std::size_t)std::round(log(N) / log(n));
        }

        h_gens = RandomizeGroupElements(n * m);
        g.randomize();
    }

    void GenerateBatchProof(
        Prover &prover,
        std::vector<GroupElement> const &coins,
        std::size_t l,
        Scalar const &s,
        Scalar const &v,
        Scalar const &r,
        Scalar const &x,
        Proof &proof
    ) {
        auto gs = g * s.negate();
        std::vector<GroupElement> commits(coins.begin(), coins.end());
        for (auto &c : commits) {
            c += gs;
        }

        Scalar rA, rB, rC, rD;
        rA.randomize();
        rB.randomize();
        rC.randomize();
        rD.randomize();

        std::vector<Scalar> sigma;
        std::vector<Scalar> Tk, Pk, Yk;
        Tk.resize(m);
        Pk.resize(m);
        Yk.resize(m);

        std::vector<Scalar> a;
        a.resize(n * m);

        prover.sigma_commit(
            commits, l, rA, rB, rC, rD, a, Tk, Pk, Yk, sigma, proof);

        prover.sigma_response(
            sigma, a, rA, rB, rC, rD, v, r, Tk, Pk, x, proof);
    }

public:
    std::size_t N;
    std::size_t n;
    std::size_t m;

    std::vector<GroupElement> h_gens;
    GroupElement g;
};

BOOST_FIXTURE_TEST_SUITE(lelantus_sigma_tests, SigmaExtendedTests)

BOOST_AUTO_TEST_CASE(one_out_of_N_variable_batch)
{
    GenerateParams(64, 4);

    std::size_t commit_size = 60; // require padding
    auto commits = RandomizeGroupElements(commit_size);

    // Generate
    std::vector<Secret> secrets;
    std::vector<std::size_t> indexes = { 0, 1, 3, 59 };
    std::vector<std::size_t> set_sizes = { 60, 60, 59, 16 };
    
    for (auto index : indexes) {
        secrets.emplace_back(index);

        auto &s = secrets.back();

        commits[index] = Primitives::double_commit(
            g, s.s, h_gens[1], s.v, h_gens[0], s.r
        );
    }

    Prover prover(g, h_gens, n, m);
    Verifier verifier(g, h_gens, n, m);
    std::vector<Proof> proofs;
    std::vector<Scalar> serials;
    std::vector<Scalar> challenges;

    for (std::size_t i = 0; i < indexes.size(); i++) {
        Scalar x;
        x.randomize();
        proofs.emplace_back();
        serials.push_back(secrets[i].s);
        std::vector<GroupElement> commits_(commits.begin() + commit_size - set_sizes[i], commits.end());
        GenerateBatchProof(
            prover,
            commits_,
            secrets[i].l - (commit_size - set_sizes[i]),
            secrets[i].s,
            secrets[i].v,
            secrets[i].r,
            x,
            proofs.back()
        );
        challenges.emplace_back(x);

        // Verify individual proofs as a sanity check
        BOOST_CHECK(verifier.singleverify(commits, x, secrets[i].s, set_sizes[i], proofs.back()));
        BOOST_CHECK(verifier.singleverify(commits_, x, secrets[i].s, proofs.back()));
    }

    BOOST_CHECK(verifier.batchverify(commits, challenges, serials, set_sizes, proofs));
}

BOOST_AUTO_TEST_CASE(one_out_of_N_batch)
{
    GenerateParams(16, 4);

    auto commits = RandomizeGroupElements(N);

    // Generate
    std::vector<Secret> secrets;

    for (auto index : {1, 3, 5, 9, 15}) {
        secrets.emplace_back(index);

        auto &s = secrets.back();

        commits[index] = Primitives::double_commit(
            g, s.s, h_gens[1], s.v, h_gens[0], s.r);
    }

    Prover prover(g, h_gens, n, m);
    std::vector<Proof> proofs;
    std::vector<Scalar> serials;

    Scalar x;
    x.randomize();

    for (auto const &s : secrets) {
        proofs.emplace_back();
        serials.push_back(s.s);
        GenerateBatchProof(
            prover, commits, s.l, s.s, s.v, s.r, x, proofs.back());
    }

    Verifier verifier(g, h_gens, n, m);
    BOOST_CHECK(verifier.batchverify(commits, x, serials, proofs));

    // verify subset of valid proofs should success also
    serials.pop_back();
    proofs.pop_back();
    BOOST_CHECK(verifier.batchverify(commits, x, serials, proofs));
}

BOOST_AUTO_TEST_CASE(one_out_of_N_batch_with_some_invalid_proof)
{
    GenerateParams(16, 4);

    auto commits = RandomizeGroupElements(N);

    // Generate
    std::vector<Secret> secrets;

    for (auto index : {1, 3}) {
        secrets.emplace_back(index);

        auto &s = secrets.back();

        commits[index] = Primitives::double_commit(
            g, s.s, h_gens[1], s.v, h_gens[0], s.r);
    }

    Prover prover(g, h_gens, n, m);
    std::vector<Proof> proofs;
    std::vector<Scalar> serials;

    Scalar x;
    x.randomize();

    for (auto const &s : secrets) {
        proofs.emplace_back();
        serials.push_back(s.s);
        GenerateBatchProof(
            prover, commits, s.l, s.s, s.v, s.r, x, proofs.back());
    }

    // Add an invalid
    proofs.push_back(proofs.back());

    serials.emplace_back(serials.back());
    serials.back().randomize();

    Verifier verifier(g, h_gens, n, m);
    BOOST_CHECK(!verifier.batchverify(commits, x, serials, proofs));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace lelantus