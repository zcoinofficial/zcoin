#include "innerproduct_proof_verifier.h"

namespace lelantus {
    
InnerProductProofVerifier::InnerProductProofVerifier(
        const std::vector<GroupElement>& g,
        const std::vector<GroupElement>& h,
        const GroupElement& u,
        const GroupElement& P,
        int version)
        : g_(g)
        , h_(h)
        , u_(u)
        , P_(P)
        , version_(version)
{
}

bool InnerProductProofVerifier::verify(
        const Scalar& x,
        const InnerProductProof& proof,
        std::unique_ptr<ChallengeGenerator>& challengeGenerator) {
    auto itr_l = proof.L_.begin();
    auto itr_r = proof.R_.begin();
    u_  *= x;
    P_ += u_ * proof.c_;
    return verify_util(proof, itr_l, itr_r, challengeGenerator);
}

bool InnerProductProofVerifier::verify_util(
        const InnerProductProof& proof,
        typename std::vector<GroupElement>::const_iterator itr_l,
        typename std::vector<GroupElement>::const_iterator itr_r,
        std::unique_ptr<ChallengeGenerator>& challengeGenerator) {
    if(itr_l == proof.L_.end()){
        Scalar c = proof.a_ * proof.b_;
        GroupElement uc = u_ * c;
        GroupElement P = g_[0] * proof.a_ + h_[0] * proof.b_ + uc;
        return P_ == P;
    }

    //Get challenge x
    Scalar x;
    std::vector<GroupElement> group_elements = {*itr_l, *itr_r};

    // if(version >= 2) we should be using CHash256,
    // we want to link transcripts from previous iteration in each step, so we are not restarting in that case,
    if (version_ < 2) {
        challengeGenerator.reset(new ChallengeGeneratorImpl<CSHA256>(0));
    }
    challengeGenerator->add(group_elements);
    challengeGenerator->get_challenge(x);

    //Compute g prime and p prime
    std::vector<GroupElement> g_p;
    LelantusPrimitives::g_prime(g_, x, g_p);
    std::vector<GroupElement> h_p;
    LelantusPrimitives::h_prime(h_, x, h_p);

    //Compute P prime
    GroupElement p_p = LelantusPrimitives::p_prime(P_, *itr_l, *itr_r, x);
    return InnerProductProofVerifier(g_p, h_p, u_, p_p, version_).verify_util(proof, itr_l + 1, itr_r + 1, challengeGenerator);
}

bool InnerProductProofVerifier::verify_fast(std::size_t n, const Scalar& x, const InnerProductProof& proof, std::unique_ptr<ChallengeGenerator>& challengeGenerator) {
    u_  *= x;
    P_ += u_ * proof.c_;
    return verify_fast_util(n, proof, challengeGenerator);
}

bool InnerProductProofVerifier::verify_fast_util(
        std::size_t n,
        const InnerProductProof& proof,
        std::unique_ptr<ChallengeGenerator>& challengeGenerator){
    std::size_t log_n = proof.L_.size();
    std::vector<Scalar> x_j;
    x_j.resize(log_n);
    for (std::size_t i = 0; i < log_n; ++i)
    {
        std::vector<GroupElement> group_elements = {proof.L_[i], proof.R_[i]};

        // if(version_ >= 2) we should be using CHash256,
        // we want to link transcripts from previous iteration in each step, so we are not restarting in that case,
        if (version_ < 2) {
            challengeGenerator.reset(new ChallengeGeneratorImpl<CSHA256>(0));
        }
        challengeGenerator->add(group_elements);
        challengeGenerator->get_challenge(x_j[i]);
    }
    std::vector<Scalar> s, s_inv;
    s.resize(n);
    s_inv.resize(n);
    for (std::size_t i = 0; i < n; ++i)
    {
        Scalar x_i(uint64_t(1));
        for (std::size_t j = 0; j < log_n; ++j)
        {
            if((i >> j) & 1) {
                x_i *= x_j[log_n - j - 1];
            } else{
                x_i *= x_j[log_n - j - 1].inverse();
            }

        }
        s[i] =  x_i;
        s_inv[i] = x_i.inverse();
    }

    secp_primitives::MultiExponent g_mult(g_, s);
    secp_primitives::MultiExponent h_mult(h_, s_inv);
    GroupElement g = g_mult.get_multiple();
    GroupElement h = h_mult.get_multiple();

    GroupElement left;
    left += g * proof.a_ +  h * proof.b_ + u_ * (proof.a_ * proof.b_);
    GroupElement right = P_;
    GroupElement multi;
    for (std::size_t j = 0; j < log_n; ++j)
        multi += (proof.L_[j] * (x_j[j].square()) + proof.R_[j] * (x_j[j].square().inverse()));
    right += multi;
    if(left != right)
        return false;
    return true;
}

}// namespace lelantus