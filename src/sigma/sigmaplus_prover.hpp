#include <math.h>
namespace sigma {

template<class Exponent, class GroupElement>
SigmaPlusProver<Exponent, GroupElement>::SigmaPlusProver(
        const GroupElement& g,
        const std::vector<GroupElement>& h_gens,
        std::size_t n,
        std::size_t m)
    : g_(g)
    , h_(h_gens)
    , n_(n)
    , m_(m) {
}

template<class Exponent, class GroupElement>
void SigmaPlusProver<Exponent, GroupElement>::proof(
        const std::vector<GroupElement>& commits,
        std::size_t l,
        const Exponent& r,
        bool fPadding,
        SigmaPlusProof<Exponent, GroupElement>& proof_out) {
    std::size_t setSize = commits.size();
    assert(setSize > 0);

    Exponent rB;
    rB.randomize();

    // Create table sigma of nxm bits.
    std::vector<Exponent> sigma;
    SigmaPrimitives<Exponent, GroupElement>::convert_to_sigma(l, n_, m_, sigma);

    // Values of Ro_k from Figure 5.
    std::vector<Exponent> Pk;
    Pk.resize(m_);
    for (std::size_t k = 0; k < m_; ++k) {
        Pk[k].randomize();
    }
    R1ProofGenerator<secp_primitives::Scalar, secp_primitives::GroupElement> r1prover(g_, h_, sigma, rB, n_, m_);
    proof_out.B_ = r1prover.get_B();
    std::vector<Exponent> a;
    r1prover.proof(a, proof_out.r1Proof_, true /*Skip generation of final response*/);

    // Compute coefficients of Polynomials P_I(x), for all I from [0..N].
    std::size_t N = setSize;
    std::vector <std::vector<Exponent>> P_i_k;
    P_i_k.resize(N);

    // last polynomial is special case if fPadding is true
    for (std::size_t i = 0; i < (fPadding ? N-1 : N); ++i) {
        std::vector<Exponent>& coefficients = P_i_k[i];
        std::vector<std::size_t> I = SigmaPrimitives<Exponent, GroupElement>::convert_to_nal(i, n_, m_);
        coefficients.push_back(a[I[0]]);
        coefficients.push_back(sigma[I[0]]);
        for (std::size_t j = 1; j < m_; ++j) {
            SigmaPrimitives<Exponent, GroupElement>::new_factor(sigma[j * n_ + I[j]], a[j * n_ + I[j]], coefficients);
        }
    }

    if (fPadding) {
        /*
         * To optimize calculation of sum of all polynomials indices 's' = setSize-1 through 'n^m-1' we use the
         * fact that sum of all of elements in each row of 'a' array is zero. Computation is done by going
         * through n-ary representation of 's' and increasing "digit" at each position to 'n-1' one by one.
         * During every step digits at higher positions are fixed and digits at lower positions go through all
         * possible combinations with a total corresponding polynomial sum of 'x^j'.
         *
         * The math behind optimization (TeX notation):
         *
         * \sum_{i=s+1}^{N-1}p_i(x) = 
         *   \sum_{j=0}^{m-1}
         *     \left[
         *       \left( \sum_{i=s_j+1}^{n-1}(\delta_{l_j,i}x+a_{j,i}) \right)
         *       \left( \prod_{k=j}^{m-1}(\delta_{l_k,s_k}x+a_{k,s_k}) \right)
         *       x^j
         *     \right]
         */

        std::vector<std::size_t> I = SigmaPrimitives<Exponent, GroupElement>::convert_to_nal(N-1, n_, m_);
        std::vector<std::size_t> lj = SigmaPrimitives<Exponent, GroupElement>::convert_to_nal(l, n_, m_);

        std::vector<Exponent> p_i_sum;
        p_i_sum.emplace_back(uint64_t(1));
        std::vector<std::vector<Exponent>> partial_p_s;

        // Pre-calculate product parts and calculate p_s(x) at the same time, put the latter into p_i_sum
        for (std::ptrdiff_t j = m_ - 1; j >= 0; j--) {
            partial_p_s.push_back(p_i_sum);
            SigmaPrimitives<Exponent, GroupElement>::new_factor(sigma[j*n_ + I[j]], a[j*n_ + I[j]], p_i_sum);
        }

        for (std::size_t j = 0; j < m_; j++) {
            // \sum_{i=s_j+1}^{n-1}(\delta_{l_j,i}x+a_{j,i})
            Exponent a_sum(uint64_t(0));
            for (std::size_t i = I[j] + 1; i < n_; i++)
                a_sum += a[j * n_ + i];
            Exponent x_sum(uint64_t(lj[j] >= I[j]+1 ? 1 : 0));

            // Multiply by \prod_{k=j}^{m-1}(\delta_{l_k,s_k}x+a_{k,s_k})
            std::vector<Exponent> &polynomial = partial_p_s[m_ - j - 1];
            SigmaPrimitives<Exponent, GroupElement>::new_factor(x_sum, a_sum, polynomial);

            // Multiply by x^j and add to the result
            for (std::size_t k = 0; k < m_ - j; k++)
                p_i_sum[j + k] += polynomial[k];
        }

        P_i_k[N-1] = p_i_sum;
    }

    //computing G_k`s;
    std::vector <GroupElement> Gk;
    Gk.reserve(m_);
    for (std::size_t k = 0; k < m_; ++k) {
        std::vector <Exponent> P_i;
        P_i.reserve(N);
        for (std::size_t i = 0; i < N; ++i) {
            P_i.emplace_back(P_i_k[i][k]);
        }
        secp_primitives::MultiExponent mult(commits, P_i);
        GroupElement c_k = mult.get_multiple();
        c_k += SigmaPrimitives<Exponent, GroupElement>::commit(g_, Exponent(uint64_t(0)), h_[0], Pk[k]);
        Gk.emplace_back(c_k);
    }
    proof_out.Gk_ = Gk;

    // Compute value of challenge X, then continue R1 proof and sigma final response proof.
    std::vector<GroupElement> group_elements = {
        proof_out.r1Proof_.A_, proof_out.B_, proof_out.r1Proof_.C_, proof_out.r1Proof_.D_};

    group_elements.insert(group_elements.end(), Gk.begin(), Gk.end());
    Exponent x;
    SigmaPrimitives<Exponent, GroupElement>::generate_challenge(group_elements, x);
    r1prover.generate_final_response(a, x, proof_out.r1Proof_);

    //computing z
    Exponent z;
    z = r * x.exponent(uint64_t(m_));
    Exponent sum;
    Exponent x_k(uint64_t(1));
    for (std::size_t k = 0; k < m_; ++k) {
        sum += (Pk[k] * x_k);
        x_k *= x;
    }
    z -= sum;
    proof_out.z_ = z;
}

} // namespace sigma
