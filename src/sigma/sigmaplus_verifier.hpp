#include <math.h>

namespace sigma {

template<class Exponent, class GroupElement>
SigmaPlusVerifier<Exponent, GroupElement>::SigmaPlusVerifier(
        const GroupElement& g,
        const std::vector<GroupElement>& h_gens,
        std::size_t n,
        std::size_t m)
    : g_(g)
    , h_(h_gens)
    , n(n)
    , m(m){
}

template<class Exponent, class GroupElement>
bool SigmaPlusVerifier<Exponent, GroupElement>::verify(
        const std::vector<GroupElement>& commits,
        const SigmaPlusProof<Exponent, GroupElement>& proof,
        bool fPadding) const {
    // Prepare a batch with a single proof
    std::vector<Exponent> serials = { Exponent(uint64_t(0)) };
    std::vector<bool> fPadding_ = { fPadding };
    std::vector<std::size_t> setSizes = { commits.size() };
    std::vector<SigmaPlusProof<Exponent, GroupElement>> proofs = { proof };

    return batch_verify(
        commits, serials, fPadding_, setSizes, proofs
    );
}

template<class Exponent, class GroupElement>
bool SigmaPlusVerifier<Exponent, GroupElement>::verify(
        const std::vector<GroupElement>& commits,
        const SigmaPlusProof<Exponent, GroupElement>& proof,
        bool fPadding,
        std::size_t setSize) const {
    // Prepare a batch with a single proof
    std::vector<Exponent> serials = { Exponent(uint64_t(0)) };
    std::vector<bool> fPadding_ = { fPadding };
    std::vector<std::size_t> setSizes = { setSize };
    std::vector<SigmaPlusProof<Exponent, GroupElement>> proofs = { proof };

    return batch_verify(
        commits, serials, fPadding_, setSizes, proofs
    );
}

// Verify a batch of one-of-many proofs
template<class Exponent, class GroupElement>
bool SigmaPlusVerifier<Exponent, GroupElement>::batch_verify(
        const std::vector<GroupElement>& commits,
        const std::vector<Exponent>& serials,
        const std::vector<bool>& fPadding,
        const std::vector<std::size_t>& setSizes,
        const std::vector<SigmaPlusProof<Exponent, GroupElement>>& proofs) const {
    // Sanity checks
    if (n < 2 || m < 2) {
        LogPrintf("Verifier parameters are invalid");
        return false;
    }
    std::size_t M = proofs.size();
    std::size_t N = (std::size_t)pow(n,m);

    if (commits.size() == 0) {
        LogPrintf("Cannot have empty commitment set");
        return false;
    }
    if (commits.size() > N) {
        LogPrintf("Commitment set is too large");
        return false;
    }
    if (h_.size() != n * m) {
        LogPrintf("Generator vector size is invalid");
        return false;
    }
    if (serials.size() != M) {
        LogPrintf("Invalid number of serials provided");
        return false;
    }
    if (fPadding.size() != M) {
        LogPrintf("Padding vector size is invalid");
        return false;
    }
    
    // All proof elements must be valid
    for (std::size_t t = 0; t < M; ++t) {
        if (!membership_checks(proofs[t])) {
            LogPrintf("Sigma verification failed due to membership check failed.");
            return false;
        }
    }

    // Final batch multiscalar multiplication
    Scalar g_scalar = Scalar(uint64_t(0)); // associated to g_
    Scalar h_scalar = Scalar(uint64_t(0)); // associated to h_
    std::vector<Scalar> h_scalars; // associated to (h_)
    std::vector<Scalar> commit_scalars; // associated to commitment list
    h_scalars.reserve(n * m);
    h_scalars.resize(n * m);
    for (std::size_t i = 0; i < n * m; i++) {
        h_scalars[i] = Scalar(uint64_t(0));
    }
    commit_scalars.reserve(commits.size());
    commit_scalars.resize(commits.size());
    for (std::size_t i = 0; i < commits.size(); i++) {
        commit_scalars[i] = Scalar(uint64_t(0));
    }

    // Set up the final batch elements
    std::vector<GroupElement> points;
    std::vector<Scalar> scalars;
    std::size_t final_size = 2 + m * n + commits.size(); // g, h, (h_), (commits)
    for (std::size_t t = 0; t < M; t++) {
        final_size += 4 + proofs[t].Gk_.size(); // A, B, C, D, (G)
    }
    points.reserve(final_size);
    scalars.reserve(final_size);

    // Index decomposition, which is common among all proofs
    std::vector<std::vector<std::size_t>> I_;
    I_.reserve(N);
    I_.resize(N);
    for (std::size_t i = 0; i < commits.size(); i++) {
        I_[i] = SigmaPrimitives<Exponent, GroupElement>::convert_to_nal(i, n, m);
    }

    // Process all proofs
    for (std::size_t t = 0; t < M; t++) {
        SigmaPlusProof<Exponent, GroupElement> proof = proofs[t];

        // Compute the challenge
        Exponent x;
        std::vector<GroupElement> challenge_elements = {
            proof.r1Proof_.A_,
            proof.B_,
            proof.r1Proof_.C_,
            proof.r1Proof_.D_,
        };
        challenge_elements.insert(challenge_elements.end(), proof.Gk_.begin(), proof.Gk_.end());
        SigmaPrimitives<Exponent, GroupElement>::generate_challenge(challenge_elements, x);

        // Generate random verifier weights
        Scalar w1, w2, w3;
        w1.randomize();
        w2.randomize();
        w3.randomize();

        // Reconstruct f-matrix
        std::vector<Exponent> f_;
        if (!compute_fs(proof, x, f_)) {
            LogPrintf("Invalid matrix reconstruction");
            return false;
        }

        // A, B, C, D (and associated commitments)
        points.emplace_back(proof.r1Proof_.A_);
        scalars.emplace_back(w1.negate());
        points.emplace_back(proof.B_);
        scalars.emplace_back(x.negate() * w1);
        points.emplace_back(proof.r1Proof_.C_);
        scalars.emplace_back(x.negate() * w2);
        points.emplace_back(proof.r1Proof_.D_);
        scalars.emplace_back(w2.negate());

        g_scalar += proof.r1Proof_.ZA_ * w1 + proof.r1Proof_.ZC_ * w2;
        for (std::size_t i = 0; i < m * n; i++) {
            h_scalars[i] += f_[i] * (w1 + (x - f_[i]) * w2);
        }

        // Input sets
        h_scalar += proof.z_ * w3.negate();

        Scalar f_i(uint64_t(1));
        Scalar e;
        std::size_t size = setSizes[t];
        std::size_t start = commits.size() - size;

        std::vector<Scalar>::iterator ptr = commit_scalars.begin() + start;
        compute_batch_fis(f_i, m, f_, w3, e, ptr, ptr, ptr + size - 1);

        if(fPadding[t]) {
            Scalar pow(uint64_t(1));
            std::vector <Scalar> f_part_product;
            for (std::ptrdiff_t j = m - 1; j >= 0; j--) {
                f_part_product.push_back(pow);
                pow *= f_[j*n + I_[size - 1][j]];
            }

            NthPower<Exponent> xj(x);
            for (std::size_t j = 0; j < m; j++) {
                Scalar fi_sum(uint64_t(0));
                for (std::size_t i = I_[size - 1][j] + 1; i < n; i++)
                    fi_sum += f_[j*n + i];
                pow += fi_sum * xj.pow * f_part_product[m - j - 1];
                xj.go_next();
            }

            commit_scalars[commits.size() - 1] += pow * w3;
            e += pow;
        } else {
            f_i = (uint64_t(1));
            for (std::size_t j = 0; j < m; ++j)
            {
                f_i *= f_[j*n + I_[size - 1][j]];
            }

            commit_scalars[commits.size() - 1] += f_i * w3;
            e += f_i;
        }

        e *= serials[t] * w3.negate();
        g_scalar += e;

        NthPower<Exponent> x_k(x);
        for (std::size_t k = 0; k < m; k++) {
            points.emplace_back(proof.Gk_[k]);
            scalars.emplace_back(x_k.pow.negate() * w3);
            x_k.go_next();
        }
    }

    // Add common generators
    points.emplace_back(g_);
    scalars.emplace_back(g_scalar);
    points.emplace_back(h_[0]);
    scalars.emplace_back(h_scalar);
    for (std::size_t i = 0; i < m * n; i++) {
        points.emplace_back(h_[i]);
        scalars.emplace_back(h_scalars[i]);
    }
    for (std::size_t i = 0; i < commits.size(); i++) {
        points.emplace_back(commits[i]);
        scalars.emplace_back(commit_scalars[i]);
    }

    // Verify the batch
    if(points.size() != scalars.size() || points.size() != final_size) {
        LogPrintf("Unexpected final evaluation size");
        return false;
    }
    secp_primitives::MultiExponent result(points, scalars);
    if (result.get_multiple().isInfinity()) {
        return true;
    }
    return false;
}

template<class Exponent, class GroupElement>
bool SigmaPlusVerifier<Exponent, GroupElement>::membership_checks(const SigmaPlusProof<Exponent, GroupElement>& proof) const {
    if(!(proof.r1Proof_.A_.isMember() &&
         proof.B_.isMember() &&
         proof.r1Proof_.C_.isMember() &&
         proof.r1Proof_.D_.isMember()) ||
        (proof.r1Proof_.A_.isInfinity() ||
         proof.B_.isInfinity() ||
         proof.r1Proof_.C_.isInfinity() ||
         proof.r1Proof_.D_.isInfinity()))
        return false;

    for (std::size_t i = 0; i < proof.r1Proof_.f_.size(); i++)
    {
        if (!proof.r1Proof_.f_[i].isMember() || proof.r1Proof_.f_[i].isZero())
            return false;
    }
    const std::vector <GroupElement>& Gk = proof.Gk_;
    for (std::size_t k = 0; k < m; ++k)
    {
        if (!Gk[k].isMember() || Gk[k].isInfinity())
            return false;
    }
    if(!(proof.r1Proof_.ZA_.isMember() &&
         proof.r1Proof_.ZC_.isMember() &&
         proof.z_.isMember()) ||
        (proof.r1Proof_.ZA_.isZero() ||
         proof.r1Proof_.ZC_.isZero() ||
         proof.z_.isZero()))
        return false;
    return true;
}

template<class Exponent, class GroupElement>
bool SigmaPlusVerifier<Exponent, GroupElement>::compute_fs(
        const SigmaPlusProof<Exponent, GroupElement>& proof,
        const Exponent& x,
        std::vector<Exponent>& f_) const {
    for (std::size_t j = 0; j < proof.r1Proof_.f_.size(); ++j) {
        if (proof.r1Proof_.f_[j] == x)
            return false;
    }

    f_.reserve(n * m);
    for (std::size_t j = 0; j < m; ++j)
    {
        f_.push_back(Scalar(uint64_t(0)));
        Scalar temp;
        std::size_t k = n - 1;
        for (std::size_t i = 0; i < k; ++i)
        {
            temp += proof.r1Proof_.f_[j * k + i];
            f_.emplace_back(proof.r1Proof_.f_[j * k + i]);
        }
        f_[j * n] = x - temp;
    }
    return true;
}

template<class Exponent, class GroupElement>
void SigmaPlusVerifier<Exponent, GroupElement>::compute_fis(int j, const std::vector<Exponent>& f, std::vector<Exponent>& f_i_) const {
    Exponent f_i(uint64_t(1));
    typename std::vector<Exponent>::iterator ptr = f_i_.begin();
    compute_fis(f_i, m, f, ptr, f_i_.end());
}

template<class Exponent, class GroupElement>
void SigmaPlusVerifier<Exponent, GroupElement>::compute_fis(const Exponent& f_i, int j, const std::vector<Exponent>& f, typename std::vector<Exponent>::iterator& ptr, typename std::vector<Exponent>::iterator end_ptr) const {
    j--;
    if (j == -1)
    {
        if (ptr < end_ptr)
            *ptr++ += f_i;
        return;
    }

    Scalar t;

    for (std::size_t i = 0; i < n; i++)
    {
        t = f[j * n + i];
        t *= f_i;

        compute_fis(t, j, f, ptr, end_ptr);
    }
}

template<class Exponent, class GroupElement>
void SigmaPlusVerifier<Exponent, GroupElement>::compute_batch_fis(
        const Exponent& f_i,
        int j,
        const std::vector<Exponent>& f,
        const Exponent& y,
        Exponent& e,
        typename std::vector<Exponent>::iterator& ptr,
        typename std::vector<Exponent>::iterator start_ptr,
        typename std::vector<Exponent>::iterator end_ptr)const {
    j--;
    if (j == -1)
    {
        if (ptr >= start_ptr && ptr < end_ptr){
            *ptr++ += f_i * y;
            e += f_i;
        }
        return;
    }

    Exponent t;

    for (std::size_t i = 0; i < n; i++)
    {
        t = f[j * n + i];
        t *= f_i;
        compute_batch_fis(t, j, f, y, e, ptr, start_ptr, end_ptr);
    }
}

} // namespace sigma