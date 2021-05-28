#include "range_verifier.h"
#include "challenge_generator_impl.h"

// This is based on the 1 Jul 2018 revision of the Bulletproofs preprint:
// https://eprint.iacr.org/2017/1066

namespace lelantus {
    
RangeVerifier::RangeVerifier(
        const GroupElement& g,
        const GroupElement& h1,
        const GroupElement& h2,
        const std::vector<GroupElement>& g_vector,
        const std::vector<GroupElement>& h_vector,
        std::size_t n,
        unsigned int v)
        : g (g)
        , h1 (h1)
        , h2 (h2)
        , g_(g_vector)
        , h_(h_vector)
        , n (n)
        , version (v)
{}

// Verify a single proof by building a trivial batch
bool RangeVerifier::verify(const std::vector<GroupElement>& V, const std::vector<GroupElement>& commitments, const RangeProof& proof) {
    std::vector<std::vector<GroupElement> > V_batch = {V};
    std::vector<std::vector<GroupElement> > commitments_batch = {commitments};
    std::vector<RangeProof> proof_batch = {proof};

    return verify(V_batch, commitments_batch, proof_batch);
}

bool RangeVerifier::verify(const std::vector<std::vector<GroupElement> >& V, const std::vector<std::vector<GroupElement> >& commitments, const std::vector<RangeProof>& proofs) {
    // Preprocess all proofs
    if (V.size() != commitments.size() || commitments.size() != proofs.size()) {
        return false;
    }
    std::size_t N_proofs = proofs.size();
    std::size_t max_m = 0; // maximum number of aggregated values

    // Check aggregated input consistency
    for (std::size_t k = 0; k < N_proofs; k++) {
        std::size_t m = V[k].size(); // number of aggregated inputs

        // Require a power of 2 (if no commitments, valid by default)
        if (m == 0) {
            return true;
        }
        if ((m & (m - 1)) != 0) {
            return false;
        }

        // Track maximum value
        if (m > max_m) {
            max_m = m;
        }

        // Check inner product proof size consistency
        std::size_t log_mn = proofs[k].innerProductProof.L_.size();
        if (proofs[k].innerProductProof.R_.size() != log_mn) {
            return false;
        }
        if (RangeProof::int_log2(m*n) != log_mn) {
            return false;
        }
        
        // Group membership checks
        if (!membership_checks(proofs[k])) {
            return false;
        }
    }

    // Ensure this batch is within bounds
    if (max_m*n > g_.size() || max_m*n > h_.size()) {
        return false;
    }

    // Set up final multiscalar multiplication and common scalars
    std::vector<GroupElement> points;
    std::vector<Scalar> scalars;
    Scalar g_scalar(uint64_t(0));
    Scalar h1_scalar(uint64_t(0));
    Scalar h2_scalar(uint64_t(0));

    // Elements from g- and h-vectors are interleaved in order at the start of the final vectors
    for (std::size_t i = 0; i < max_m*n; i++) {
        points.emplace_back(g_[i]);
        scalars.emplace_back(uint64_t(0));
        points.emplace_back(h_[i]);
        scalars.emplace_back(uint64_t(0));
    }

    // Process each proof and add to the batch
    for (std::size_t k_proofs = 0; k_proofs < N_proofs; k_proofs++) {
        const RangeProof proof = proofs[k_proofs];
        const std::size_t m = V[k_proofs].size(); // number of aggregated inputs
        const std::size_t log_mn = proof.innerProductProof.L_.size(); // round count

        // Choose random nonzero weights for batching purposes
        // Each weight is used for one of the two verifier equations (98 and 105)
        Scalar w1; // equation (98)
        w1.randomize();
        Scalar w2; // equation (105)
        w2.randomize();

        // Reconstruct all challenges from this proof
        // NOTE: This does _not_ properly account for all inner product statement parameters! These need to be accounted for prior to deploying
        Scalar x, x_u, y, z;
        std::unique_ptr<ChallengeGenerator> challengeGenerator;

        // Newer proofs use domain separation and statement parameters
        if (version >= LELANTUS_TX_VERSION_4_5) {
            challengeGenerator = std::make_unique<ChallengeGeneratorImpl<CHash256>>(1);
            std::string domain_separator = "RANGE_PROOF" + std::to_string(version);
            std::vector<unsigned char> pre(domain_separator.begin(), domain_separator.end());
            challengeGenerator->add(pre);
            challengeGenerator->add(commitments[k_proofs]);
        }  else {
            challengeGenerator = std::make_unique<ChallengeGeneratorImpl<CSHA256>>(0);
        }
        challengeGenerator->add({proof.A, proof.S});
        challengeGenerator->get_challenge(y);
        challengeGenerator->get_challenge(z);

        challengeGenerator->add({proof.T1, proof.T2});
        challengeGenerator->get_challenge(x);
        Scalar x_neg = x.negate();

        challengeGenerator->add({proof.T_x1, proof.T_x2, proof.u});
        challengeGenerator->get_challenge(x_u);

        const InnerProductProof& innerProductProof = proof.innerProductProof;
        std::vector<Scalar> x_j, x_j_inv;
        x_j.resize(log_mn);
        x_j_inv.reserve(log_mn);

        // Newer proofs use domain separation
        if (version >= LELANTUS_TX_VERSION_4_5) {
            std::string domain_separator = "INNER_PRODUCT";
            std::vector<unsigned char> pre(domain_separator.begin(), domain_separator.end());
            challengeGenerator->add(pre);
        }

        for (std::size_t i = 0; i < log_mn; ++i)
        {
            std::vector<GroupElement> group_elements_i = {innerProductProof.L_[i], innerProductProof.R_[i]};

            // if(version >= LELANTUS_TX_VERSION_4_5) we should be using CHash256,
            // we want to link transcripts from range proof and from previous iteration in each step, so we are not restarting in that case,
            if (version < LELANTUS_TX_VERSION_4_5) {
                challengeGenerator.reset(new ChallengeGeneratorImpl<CSHA256>(0));
            }

            challengeGenerator->add(group_elements_i);
            challengeGenerator->get_challenge(x_j[i]);
        }

        // In the event of an attempt to invert a zero scalar, the batch is bad
        try {
            x_j_inv = LelantusPrimitives::invert(x_j); // NOTE: these could be batched across proofs as well for improved efficiency
        } catch (const std::runtime_error&) {
            return false;
        }

        Scalar z_square_neg = (z.square()).negate();
        Scalar delta = LelantusPrimitives::delta(y, z, n, m);

        NthPower z_m(z);
        for (std::size_t j = 0; j < m; ++j)
        {
            points.emplace_back(V[k_proofs][j]);
            scalars.emplace_back(z_square_neg * z_m.pow * w1);
            z_m.go_next();
        }

        NthPower y_n_(y.inverse());
        NthPower z_j(z, z.square());

        NthPower two_n_(uint64_t(2));
        std::vector<Scalar> two_n;
        two_n.reserve(n);
        for (std::size_t k = 0; k < n; ++k)
        {
            two_n.emplace_back(two_n_.pow);
            two_n_.go_next();
        }

        for (std::size_t t = 0; t < m ; ++t)
        {
            for (std::size_t k = 0; k < n; ++k)
            {
                std::size_t i = t * n + k;
                Scalar x_il(uint64_t(1));
                Scalar x_ir(uint64_t(1));
                for (std::size_t j = 0; j < log_mn; ++j)
                {
                    if ((i >> j) & 1) {
                        x_il *= x_j[log_mn - j - 1];
                        x_ir *= x_j_inv[log_mn - j - 1];
                    } else {
                        x_il *= x_j_inv[log_mn - j - 1];
                        x_ir *= x_j[log_mn - j - 1];
                    }

                }

                // g-vector
                scalars[2*i] += (x_il * innerProductProof.a_ + z) * w2;

                // h-vector
                scalars[2*i + 1] += (y_n_.pow * (x_ir * innerProductProof.b_ - (z_j.pow * two_n[k])) - z) * w2;

                y_n_.go_next();
            }
            z_j.go_next();
        }

        // Update common scalars
        g_scalar += (innerProductProof.c_ - delta) * w1;
        g_scalar += x_u * (innerProductProof.a_ * innerProductProof.b_ - innerProductProof.c_) * w2;
        h1_scalar += proof.T_x1 * w1;
        h1_scalar += proof.u * w2;
        h2_scalar += proof.T_x2 * w1;

        // Add per-proof elements
        points.emplace_back(proof.A);
        scalars.emplace_back(w2.negate());
        points.emplace_back(proof.T1);
        scalars.emplace_back(x_neg * w1);
        points.emplace_back(proof.T2);
        scalars.emplace_back((x.square()).negate() * w1);
        points.emplace_back(proof.S);
        scalars.emplace_back(x_neg * w2);

        for (std::size_t j = 0; j < log_mn; ++j)
        {
            points.emplace_back(innerProductProof.L_[j]);
            scalars.emplace_back(x_j[j].square().negate() * w2);
            points.emplace_back(innerProductProof.R_[j]);
            scalars.emplace_back(x_j_inv[j].square().negate() * w2);
        }
    }

    // Add common elements
    points.emplace_back(g);
    scalars.emplace_back(g_scalar);
    points.emplace_back(h1);
    scalars.emplace_back(h1_scalar);
    points.emplace_back(h2);
    scalars.emplace_back(h2_scalar);

    // Perform the batch check
    secp_primitives::MultiExponent mult(points, scalars);
    if(!mult.get_multiple().isInfinity()) {
        return false;
    }
    return true;
}

bool RangeVerifier::membership_checks(const RangeProof& proof) {
    if(!(proof.A.isMember()
         && proof.S.isMember()
         && proof.T1.isMember()
         && proof.T2.isMember()
         && proof.T_x1.isMember()
         && proof.T_x2.isMember()
         && proof.u.isMember()
         && proof.innerProductProof.a_.isMember()
         && proof.innerProductProof.b_.isMember()
         && proof.innerProductProof.c_.isMember()))
        return false;

    for (std::size_t i = 0; i < proof.innerProductProof.L_.size(); ++i)
    {
        if (!(proof.innerProductProof.L_[i].isMember() && proof.innerProductProof.R_[i].isMember())) {
            return false;
        }
    }
    return true;
}


}//namespace lelantus