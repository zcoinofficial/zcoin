#include "lelantus_prover.h"

namespace lelantus {

LelantusProver::LelantusProver(const Params* p, unsigned int v) : params(p), version(v) {
}

void LelantusProver::proof(
        const std::map<uint32_t, std::vector<PublicCoin>>& anonymity_sets,
        const std::vector<std::vector<unsigned char>>& anonymity_set_hashes,
        const Scalar& Vin,
        const std::vector<std::pair<PrivateCoin, uint32_t>>& Cin,
        const std::vector<size_t>& indexes,
        const std::vector<std::vector<unsigned char>>& ecdsaPubkeys,
        const Scalar& Vout,
        const std::vector<PrivateCoin>& Cout,
        const Scalar& fee,
        LelantusProof& proof_out,
        SchnorrProof& qkSchnorrProof) {
    Scalar input = Vin;
    for (std::size_t i = 0; i < Cin.size(); ++i)
        input += Cin[i].first.getV();

    Scalar out = Vout;
    for (std::size_t i = 0; i < Cout.size(); ++i)
        out += Cout[i].getV();
    out += fee;

    if (input != out)
        throw std::runtime_error("Input and output are not equal");

    Scalar x;
    std::vector<Scalar> Yk_sum;
    Yk_sum.resize(Cin.size());
    // we are passing challengeGenerator ptr here, as after LELANTUS_TX_VERSION_4_5 we need  it back, with filled data, to use in schnorr proof,
    std::unique_ptr<ChallengeGenerator> challengeGenerator;
    generate_sigma_proofs(anonymity_sets, anonymity_set_hashes, Cin, Cout, indexes, ecdsaPubkeys, x, challengeGenerator, Yk_sum, proof_out.sigma_proofs, qkSchnorrProof);

    generate_bulletproofs(Cout, proof_out.bulletproofs);

    Scalar x_m = x.exponent(params->get_sigma_m());

    Scalar X_;
    Scalar So;
    Scalar Ro;
    GroupElement A;
    for (std::size_t i = 0; i < Cout.size(); ++i)
    {
        So += Cout[i].getSerialNumber();
        Ro += Cout[i].getRandomness();
        A += Cout[i].getPublicCoin().getValue();
    }
    X_ = So * x_m;
    A *= x_m;
    A += params->get_h1() * ((Vout + fee) * x_m);
    Scalar Y_;
    Scalar Ri;
    Scalar Vi = Vin;
    for (std::size_t i = 0; i < Cin.size(); ++i)
    {
        Ri += Cin[i].first.getRandomness() * x_m + Yk_sum[i];
        Vi += Cin[i].first.getVScalar();
    }
    Y_ = Ro * x_m - Ri;
    Vi *=  x_m;
    // we are calculating A, B amd Y here as after LELANTUS_TX_VERSION_4_5 we need them for challenge generation in schnorr proof
    // also we are getting challengeGenerator with filled data from sigma,
    GroupElement B = params->get_h1() * Vi + params->get_h0() * Ri;
    GroupElement Y = A + B.inverse();
    SchnorrProver schnorrProver(params->get_g(), params->get_h0(), version >= LELANTUS_TX_VERSION_4_5);
    schnorrProver.proof(X_, Y_, Y, A, B, challengeGenerator, proof_out.schnorrProof);
}

void LelantusProver::generate_sigma_proofs(
        const std::map<uint32_t, std::vector<PublicCoin>>& c,
        const std::vector<std::vector<unsigned char>>& anonymity_set_hashes,
        const std::vector<std::pair<PrivateCoin, uint32_t>>& Cin,
        const std::vector<PrivateCoin>& Cout,
        const std::vector<size_t>& indexes,
        const std::vector<std::vector<unsigned char>>& ecdsaPubkeys,
        Scalar& x,
        std::unique_ptr<ChallengeGenerator>& challengeGenerator,
        std::vector<Scalar>& Yk_sum,
        std::vector<SigmaExtendedProof>& sigma_proofs,
        SchnorrProof& qkSchnorrProof) {
    SigmaExtendedProver sigmaProver(params->get_g(), params->get_sigma_h(), params->get_sigma_n(), params->get_sigma_m());
    sigma_proofs.resize(Cin.size());
    std::size_t N = Cin.size();
    std::vector<Scalar> rA, rB, rC, rD;
    rA.resize(N);
    rB.resize(N);
    rC.resize(N);
    rD.resize(N);
    std::vector<std::vector<Scalar>> sigma;
    sigma.resize(N);
    std::vector<std::vector<Scalar>> Tk, Pk, Yk;
    Tk.resize(N);
    Pk.resize(N);
    Yk.resize(N);
    std::vector<std::vector<Scalar>> a;
    a.resize(N);
    std::vector<Scalar> serialNumbers;
    serialNumbers.reserve(N);
    for (std::size_t i = 0; i < N; ++i)
    {
        if (!c.count(Cin[i].second))
            throw std::invalid_argument("No such anonymity set or id is not correct");

        GroupElement gs = (params->get_g() * Cin[i].first.getSerialNumber().negate());
        serialNumbers.emplace_back(Cin[i].first.getSerialNumber());
        std::vector<GroupElement> C_;
        C_.reserve(c.size());

        const auto& set = c.find(Cin[i].second);
        if (set == c.end())
            throw std::invalid_argument("No such anonymity set");

        for (auto const &coin : set->second)
            C_.emplace_back(coin.getValue() + gs);

        rA[i].randomize();
        rB[i].randomize();
        rC[i].randomize();
        rD[i].randomize();
        Tk[i].resize(params->get_sigma_m());
        Pk[i].resize(params->get_sigma_m());
        Yk[i].resize(params->get_sigma_m());
        a[i].resize(params->get_sigma_n() * params->get_sigma_m());
        sigmaProver.sigma_commit(C_, indexes[i], rA[i], rB[i], rC[i], rD[i], a[i], Tk[i], Pk[i], Yk[i], sigma[i], sigma_proofs[i]);
    }

    std::vector<GroupElement> PubcoinsOut;
    PubcoinsOut.reserve(Cout.size());
    for(auto coin : Cout)
        PubcoinsOut.emplace_back(coin.getPublicCoin().getValue());
    LelantusPrimitives::generate_Lelantus_challenge(
            sigma_proofs,
            anonymity_set_hashes,
            serialNumbers,
            ecdsaPubkeys,
            PubcoinsOut,
            version,
            challengeGenerator,
            x);

    std::vector<Scalar> x_ks;
    x_ks.reserve(params->get_sigma_m());
    NthPower x_k(x);
    for (int k = 0; k < params->get_sigma_m(); ++k) {
        x_ks.emplace_back(x_k.pow);
        x_k.go_next();
    }

    for (std::size_t i = 0; i < N; ++i) {
        for (int k = 0; k < params->get_sigma_m(); ++k) {
            Yk_sum[i] += Yk[i][k] * x_ks[k];
        }
    }

    for (std::size_t i = 0; i < N; ++i){
        const Scalar& v = Cin[i].first.getV();
        const Scalar& r = Cin[i].first.getRandomness();
        sigmaProver.sigma_response(sigma[i], a[i], rA[i], rB[i], rC[i], rD[i], v, r, Tk[i], Pk[i], x, sigma_proofs[i]);
    }

    // generate schnorr proof to prove that Q_k is generated honestly;
    if (version >= LELANTUS_TX_VERSION_4_5) {
        Scalar q_k_x;
        challengeGenerator->get_challenge(q_k_x);
        NthPower qk_x_n(q_k_x);

        Scalar Pk_sum(uint64_t(0));
        Scalar Tk_Yk_sum(uint64_t(0));
        std::vector<GroupElement> Qk;
        Qk.reserve(N * params->get_sigma_m());
        for (std::size_t i = 0; i < N; ++i) {
            for (std::size_t j = 0; j < params->get_sigma_m(); ++j) {
                Pk_sum += (Pk[i][j] * qk_x_n.pow);
                Tk_Yk_sum += ((Tk[i][j] + Yk[i][j]) * qk_x_n.pow);
                qk_x_n.go_next();
                Qk.emplace_back(sigma_proofs[i].Qk[j]);
            }
        }

        SchnorrProver schnorrProver(params->get_h1(), params->get_h0(), true);
        schnorrProver.proof(Pk_sum, Tk_Yk_sum, Qk, qkSchnorrProof);
    }
}

void LelantusProver::generate_bulletproofs(
        const std::vector<PrivateCoin>& Cout,
        RangeProof& bulletproofs) {
    if (Cout.empty())
        return;

    std::vector<secp_primitives::Scalar> v_s, serials, randoms;
    std::size_t n = params->get_bulletproofs_n();
    std::size_t m = Cout.size() * 2;

    while (m & (m - 1))
        m++;

    v_s.reserve(m);
    serials.reserve(m);
    randoms.reserve(m);
    // NOTE: this prepends zero-value group elements, apparently as an earlier coding error
    // This doesn't hurt anything, and so is retained here for compatibility reasons
    std::vector<GroupElement> commitments(Cout.size());
    for (std::size_t i = 0; i < Cout.size(); ++i)
    {
        v_s.push_back(Cout[i].getV()); // Ensure that v >= 0
        v_s.push_back(Cout[i].getVScalar() +  params->get_limit_range()); // Ensure that v <= ZC_LELANTUS_MAX_MINT
        serials.insert(serials.end(), 2, Cout[i].getSerialNumber());
        randoms.insert(randoms.end(), 2, Cout[i].getRandomness());
        commitments.emplace_back(Cout[i].getPublicCoin().getValue());
    }

    v_s.resize(m);
    serials.resize(m);
    randoms.resize(m);

    std::vector<GroupElement> g_, h_;
    g_.reserve(n * m);
    h_.reserve(n * m);


    g_.insert(g_.end(), params->get_bulletproofs_g().begin(), params->get_bulletproofs_g().begin() + (n * m));
    h_.insert(h_.end(), params->get_bulletproofs_h().begin(), params->get_bulletproofs_h().begin() + (n * m));

    RangeProver rangeProver(params->get_h1(), params->get_h0(), params->get_g(), g_, h_, n, version);
    rangeProver.proof(v_s, serials, randoms, commitments, bulletproofs);

}

}//namespace lelantus