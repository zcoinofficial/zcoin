#include "lelantus_verifier.h"
#include "../amount.h"
#include "chainparams.h"
#include "util.h"

namespace lelantus {

LelantusVerifier::LelantusVerifier(const Params* p, unsigned int v) : params(p), version(v) {
}

bool LelantusVerifier::verify(
        const std::map<uint32_t, std::vector<PublicCoin>>& anonymity_sets,
        const std::vector<std::vector<unsigned char>>& anonymity_set_hashes,
        const std::vector<Scalar>& serialNumbers,
        const std::vector<std::vector<unsigned char>>& ecdsaPubkeys,
        const std::vector<uint32_t>& groupIds,
        const Scalar& Vin,
        uint64_t Vout,
        uint64_t fee,
        const std::vector<PublicCoin>& Cout,
        const LelantusProof& proof,
        const SchnorrProof& qkSchnorrProof) {
    Scalar x;
    bool fSkipVerification = 0;
    return verify(anonymity_sets, anonymity_set_hashes, serialNumbers, ecdsaPubkeys, groupIds, Vin, Vout, fee, Cout, proof, qkSchnorrProof, x, fSkipVerification);
}

bool LelantusVerifier::verify(
        const std::map<uint32_t, std::vector<PublicCoin>>& anonymity_sets,
        const std::vector<std::vector<unsigned char>>& anonymity_set_hashes,
        const std::vector<Scalar>& serialNumbers,
        const std::vector<std::vector<unsigned char>>& ecdsaPubkeys,
        const std::vector<uint32_t>& groupIds,
        const Scalar& Vin,
        uint64_t Vout,
        uint64_t fee,
        const std::vector<PublicCoin>& Cout,
        const LelantusProof& proof,
        const SchnorrProof& qkSchnorrProof,
        Scalar& x,
        bool fSkipVerification,
        boost::optional<int64_t> nMaxValueLelantusSpendPerTransaction) {
    if (!nMaxValueLelantusSpendPerTransaction.is_initialized()) {
        nMaxValueLelantusSpendPerTransaction = ::Params().GetConsensus().nMaxValueLelantusSpendPerTransaction;
    }

    //check the overflow of Vout and fee
    if (!(Vout <= uint64_t(nMaxValueLelantusSpendPerTransaction.get()) && fee < (1000 * CENT))) { // 1000 * CENT is the value of max fee defined at validation.h
        LogPrintf("Lelantus verification failed due to transparent values check failed.");
        return false;
    }

    // number of serials should be equal to number of sigma proofs, we need one proof for each serial
    if (serialNumbers.size() != proof.sigma_proofs.size()) {
        LogPrintf("Lelantus verification failed due to sizes of serials  and sigma proofs are not equal.");
        return false;
    }

    // max possible number of output coins is 8,
    if (Cout.size() > (params->get_bulletproofs_max_m() / 2)) {
        LogPrintf("Number of output coins are more than allowed.");
        return false;
    }

    std::vector<std::vector<PublicCoin>> vAnonymity_sets;
    std::vector<std::vector<Scalar>> vSin;
    vAnonymity_sets.reserve(anonymity_sets.size());
    vSin.resize(anonymity_sets.size());

    size_t i = 0;
    auto itr = vSin.begin();
    for (const auto& set : anonymity_sets) {
        vAnonymity_sets.emplace_back(set.second);

        while (i < groupIds.size() && groupIds[i] == set.first) {
            itr->push_back(serialNumbers[i++]);
        }
        itr++;
    }

    Scalar zV, zR;
    std::unique_ptr<ChallengeGenerator> challengeGenerator;
    try {
        // we are passing challengeGenerator ptr here, as after LELANTUS_TX_VERSION_4_5 we need  it back, with filled data, to use in schnorr proof,
        if (!(verify_sigma(vAnonymity_sets, anonymity_set_hashes, vSin, serialNumbers, ecdsaPubkeys, Cout, proof.sigma_proofs, qkSchnorrProof, x, challengeGenerator, zV, zR, fSkipVerification) &&
             verify_rangeproof(Cout, proof.bulletproofs) &&
             verify_schnorrproof(x, zV, zR, Vin, Vout, fee, Cout, proof, challengeGenerator)))
            return false;
    } catch (std::invalid_argument&) {
        return false;
    }

    return true;
}

bool LelantusVerifier::verify_sigma(
        const std::vector<std::vector<PublicCoin>>& anonymity_sets,
        const std::vector<std::vector<unsigned char>>& anonymity_set_hashes,
        const std::vector<std::vector<Scalar>>& Sin,
        const std::vector<Scalar>& serialNumbers,
        const std::vector<std::vector<unsigned char>>& ecdsaPubkeys,
        const std::vector<PublicCoin>& Cout,
        const std::vector<SigmaExtendedProof> &sigma_proofs,
        const SchnorrProof& qkSchnorrProof,
        Scalar& x,
        std::unique_ptr<ChallengeGenerator>& challengeGenerator,
        Scalar& zV,
        Scalar& zR,
        bool fSkipVerification) {
    std::vector<GroupElement> PubcoinsOut;
    PubcoinsOut.reserve(Cout.size());
    for (auto coin : Cout)
        PubcoinsOut.emplace_back(coin.getValue());

    LelantusPrimitives::generate_Lelantus_challenge(
            sigma_proofs,
            anonymity_set_hashes,
            serialNumbers,
            ecdsaPubkeys,
            PubcoinsOut,
            version,
            challengeGenerator,
            x);

    SigmaExtendedVerifier sigmaVerifier(params->get_g(), params->get_sigma_h(), params->get_sigma_n(),
                                                          params->get_sigma_m());

    if (Sin.size() != anonymity_sets.size())
        throw std::invalid_argument("Number of anonymity sets and number of vectors containing serial numbers must be equal");

    int t = 0;
    for (std::size_t k = 0; k < Sin.size(); k++) {

        std::vector<SigmaExtendedProof> sigma_proofs_k;
        for (std::size_t i = 0; i < Sin[k].size(); ++i, ++t) {
            zV += sigma_proofs[t].zV_;
            zR += sigma_proofs[t].zR_;
            sigma_proofs_k.emplace_back(sigma_proofs[t]);
        }

        //skip verification if we are collecting proofs for later batch verification
        if (fSkipVerification)
            continue;

        std::vector<GroupElement> C_;
        C_.reserve(anonymity_sets[k].size());
        for (std::size_t j = 0; j < anonymity_sets[k].size(); ++j)
            C_.emplace_back(anonymity_sets[k][j].getValue());

        if (!sigmaVerifier.batchverify(C_, x, Sin[k], sigma_proofs_k)) {
            LogPrintf("Lelantus verification failed due sigma verification failed.\n");
            return false;
        }
    }

    // verify schnorr proof to verify that Q_k is generated honestly;
    if (version >= LELANTUS_TX_VERSION_4_5) {
        Scalar q_k_x;
        challengeGenerator->get_challenge(q_k_x);

        NthPower qK_x_n(q_k_x);
        GroupElement Gk_sum;
        std::vector<GroupElement> Qks;
        Qks.reserve(sigma_proofs.size() * params->get_sigma_m());
        for (std::size_t t = 0; t < sigma_proofs.size(); ++t)
        {
            const std::vector<GroupElement>& Qk = sigma_proofs[t].Qk;
            for (std::size_t k = 0; k < Qk.size(); ++k)
            {
                Gk_sum += (Qk[k]) * qK_x_n.pow;
                qK_x_n.go_next();

                Qks.emplace_back(Qk[k]);
            }
        }

        SchnorrVerifier schnorrVerifier(params->get_h1(), params->get_h0(), version >= LELANTUS_TX_VERSION_4_5);
        if (!schnorrVerifier.verify(Gk_sum, Qks, qkSchnorrProof)) {
            LogPrintf("Lelantus verification failed due to Qk schnorr proof verification failed.");
            return false;
        }
    }

    return true;
}

bool LelantusVerifier::verify_rangeproof(
        const std::vector<PublicCoin>& Cout,
        const RangeProof& bulletproofs) {
    if (Cout.empty())
        return true;

    std::size_t n = params->get_bulletproofs_n();
    std::size_t m = Cout.size() * 2;

    while (m & (m - 1))
        m++;

    std::vector<GroupElement> g_, h_;
    g_.reserve(n * m);
    h_.reserve(n * m);
    g_.insert(g_.end(), params->get_bulletproofs_g().begin(), params->get_bulletproofs_g().begin() + (n * m));
    h_.insert(h_.end(), params->get_bulletproofs_h().begin(), params->get_bulletproofs_h().begin() + (n * m));

    std::vector<GroupElement> V;
    V.reserve(m);
    std::vector<GroupElement> commitments(Cout.size());
    for (std::size_t i = 0; i < Cout.size(); ++i) {
        V.push_back(Cout[i].getValue());
        V.push_back(Cout[i].getValue() + params->get_h1_limit_range());
        commitments.emplace_back(Cout[i].getValue());
    }

    for (std::size_t i = Cout.size() * 2; i < m; ++i)
        V.push_back(GroupElement());

    RangeVerifier  rangeVerifier(params->get_h1(), params->get_h0(), params->get_g(), g_, h_, n, version);
    if (!rangeVerifier.verify_batch(V, commitments, bulletproofs)) {
        LogPrintf("Lelantus verification failed due range proof verification failed.");
        return false;
    }
    return true;
}

bool LelantusVerifier::verify_schnorrproof(
        const Scalar& x,
        const Scalar& zV,
        const Scalar& zR,
        const Scalar& Vin,
        const Scalar& Vout,
        const Scalar fee,
        const std::vector<PublicCoin>& Cout,
        const LelantusProof& proof,
        std::unique_ptr<ChallengeGenerator>& challengeGenerator) {
    // x^m
    Scalar x_m = x.exponent(params->get_sigma_m());

    // A is computed directly, to take advantage of point addition
    GroupElement A;
    for (std::size_t j = 0; j < Cout.size(); ++j) {
        A += Cout[j].getValue();
    }
    A += params->get_h1() * (Vout + fee);
    A *= x_m;

    // B is computed via multiscalar multiplication
    std::vector<GroupElement> B_points;
    std::vector<Scalar> B_scalars;
    B_points.emplace_back(params->get_h1());
    B_scalars.emplace_back(Vin*x_m + zV);
    B_points.emplace_back(params->get_h0());
    B_scalars.emplace_back(zR);

    NthPower x_k(x);
    std::vector<Scalar> x_ks;
    x_ks.reserve(params->get_sigma_m());
    for (int k = 0; k < params->get_sigma_m(); ++k)
    {
        x_ks.emplace_back(x_k.pow);
        x_k.go_next();
    }

    for (std::size_t t = 0; t < proof.sigma_proofs.size(); ++t)
    {
        const std::vector<GroupElement>& Qk = proof.sigma_proofs[t].Qk;
        for (std::size_t k = 0; k < Qk.size(); ++k)
        {
            B_points.emplace_back(Qk[k]);
            B_scalars.emplace_back(x_ks[k]);
        }
    }

    GroupElement B = secp_primitives::MultiExponent(B_points, B_scalars).get_multiple();

    SchnorrVerifier schnorrVerifier(params->get_g(), params->get_h0(), version >= LELANTUS_TX_VERSION_4_5);
    const SchnorrProof& schnorrProof = proof.schnorrProof;
    GroupElement Y = A + B * (Scalar(uint64_t(1)).negate());
    // after LELANTUS_TX_VERSION_4_5 we are getting challengeGenerator with filled data from sigma,
    if (!schnorrVerifier.verify(Y, A, B, schnorrProof, challengeGenerator)) {
        LogPrintf("Lelantus verification failed due schnorr proof verification failed.");
        return false;
    }
    return true;
}

}//namespace lelantus