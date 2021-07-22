#include "sigmaextended_verifier.h"
#include "util.h"

namespace lelantus {

SigmaExtendedVerifier::SigmaExtendedVerifier(
        const GroupElement& g,
        const std::vector<GroupElement>& h_gens,
        uint64_t n,
        uint64_t m)
        : g_(g)
        , h_(h_gens)
        , n(n)
        , m(m){
}

bool SigmaExtendedVerifier::batchverify(
        const std::vector<GroupElement>& commits,
        const Scalar& x,
        const std::vector<Scalar>& serials,
        const std::vector<SigmaExtendedProof>& proofs) const {
    int M = proofs.size();
    int N = commits.size();

    if (commits.empty()) {
        LogPrintf("Sigma verification failed due to commits are empty.\n");
        return false;
    }

    for(int t = 0; t < M; ++t) {
        if(!membership_checks(proofs[t])) {
            LogPrintf("Sigma verification failed due to membership checks failed.\n");
            return false;
        }
    }

    std::vector<std::vector<Scalar>> f_;
    f_.resize(M);
    for (int t = 0; t < M; ++t)
    {
        if(!compute_fs(proofs[t], x, f_[t]) || !abcd_checks(proofs[t], x, f_[t])) {
            LogPrintf("Sigma verification failed due to f computations or abcd checks failed.\n");
            return false;
        }
    }

    std::vector<Scalar> y;
    y.resize(M);
    for (int t = 0; t < M; ++t)
        y[t].randomize();

    std::vector<Scalar> f_i_t;
    f_i_t.resize(N);
    GroupElement right;
    Scalar exp;

    std::vector <std::vector<uint64_t>> I_;
    I_.resize(N);
    for (int i = 0; i < N ; ++i)
        I_[i] = LelantusPrimitives::convert_to_nal(i, n, m);

    for (int t = 0; t < M; ++t)
    {
        right += (LelantusPrimitives::double_commit(g_, Scalar(uint64_t(0)), h_[1], proofs[t].zV_, h_[0], proofs[t].zR_)) * y[t];
        Scalar e;

        Scalar f_i(uint64_t(1));
        std::vector<Scalar>::iterator ptr = f_i_t.begin();
        compute_batch_fis(f_i, m, f_[t], y[t], e, ptr, ptr, ptr + N - 1);
        /*
        * Optimization for getting power for last 'commits' array element is done similarly to the one used in creating
        * a proof. The fact that sum of any row in 'f' array is 'x' (challenge value) is used.
        *
        * Math (in TeX notation):
        *
        * \sum_{i=s+1}^{N-1} \prod_{j=0}^{m-1}f_{j,i_j} =
        *   \sum_{j=0}^{m-1}
        *     \left[
        *       \left( \sum_{i=s_j+1}^{n-1}f_{j,i} \right)
        *       \left( \prod_{k=j}^{m-1}f_{k,s_k} \right)
        *       x^j
        *     \right]
        */

        Scalar pow(uint64_t(1));
        std::vector<Scalar> f_part_product;    // partial product of f array elements for lastIndex
        for (int j = m - 1; j >= 0; j--) {
            f_part_product.push_back(pow);
            pow *= f_[t][j * n + I_[N - 1][j]];
        }

        NthPower xj(x);
        for (std::size_t j = 0; j < m; j++) {
            Scalar fi_sum(uint64_t(0));
            for (std::size_t i = I_[N - 1][j] + 1; i < n; i++)
                fi_sum += f_[t][j*n + i];
            pow += fi_sum * xj.pow * f_part_product[m - j - 1];
            xj.go_next();
        }

        f_i_t[N - 1] += pow * y[t];
        e += pow;

        e *= serials[t] * y[t];
        exp += e;
    }

    secp_primitives::MultiExponent mult(commits, f_i_t);
    GroupElement t1 = mult.get_multiple();

    std::vector<Scalar> x_k_neg;
    x_k_neg.reserve(m);
    NthPower x_k(x);
    for (uint64_t k = 0; k < m; ++k) {
        x_k_neg.emplace_back(x_k.pow.negate());
        x_k.go_next();
    }

    GroupElement t2;
    for (int t = 0; t < M; ++t) {
        const std::vector <GroupElement>& Gk = proofs[t].Gk_;
        const std::vector <GroupElement>& Qk = proofs[t].Qk;
        GroupElement term;
        for (std::size_t k = 0; k < m; ++k)
        {
            term += ((Gk[k] + Qk[k]) * x_k_neg[k]);
        }
        term *= y[t];
        t2 += term;
    }
    GroupElement left(t1 + t2);

    right += g_ * exp;
    if(left != right) {
        LogPrintf("Sigma verification failed due to last check failed.\n");
        return false;
    }

    return true;
}

bool SigmaExtendedVerifier::batchverify(
        const std::vector<GroupElement>& commits,
        const std::vector<Scalar>& challenges,
        const std::vector<Scalar>& serials,
        const std::vector<size_t>& setSizes,
        const std::vector<SigmaExtendedProof>& proofs) const {
    int M = proofs.size();
    int N = commits.size();

    if (commits.empty())
        return false;

    for(int t = 0; t < M; ++t)
        if(!membership_checks(proofs[t]))
            return false;
    std::vector<std::vector<Scalar>> f_;
    f_.resize(M);
    for (int t = 0; t < M; ++t)
    {
        if(!compute_fs(proofs[t], challenges[t], f_[t]) || !abcd_checks(proofs[t], challenges[t], f_[t]))
            return false;
    }

    std::vector<Scalar> y;
    y.resize(M);
    for (int t = 0; t < M; ++t)
        y[t].randomize();

    std::vector<Scalar> f_i_t;
    f_i_t.resize(N);
    GroupElement right;
    Scalar exp;

    std::vector <std::vector<uint64_t>> I_;
    I_.resize(N);
    for (int i = 0; i < N ; ++i)
        I_[i] = LelantusPrimitives::convert_to_nal(i, n, m);

    for (int t = 0; t < M; ++t)
    {
        right += (LelantusPrimitives::double_commit(g_, Scalar(uint64_t(0)), h_[1], proofs[t].zV_, h_[0], proofs[t].zR_)) * y[t];
        Scalar e;
        size_t size = setSizes[t];
        size_t start = N - size;

        Scalar f_i(uint64_t(1));
        std::vector<Scalar>::iterator ptr = f_i_t.begin() + start;
        compute_batch_fis(f_i, m, f_[t], y[t], e, ptr, ptr, ptr + size - 1);

        /*
        * Optimization for getting power for last 'commits' array element is done similarly to the one used in creating
        * a proof. The fact that sum of any row in 'f' array is 'x' (challenge value) is used.
        *
        * Math (in TeX notation):
        *
        * \sum_{i=s+1}^{N-1} \prod_{j=0}^{m-1}f_{j,i_j} =
        *   \sum_{j=0}^{m-1}
        *     \left[
        *       \left( \sum_{i=s_j+1}^{n-1}f_{j,i} \right)
        *       \left( \prod_{k=j}^{m-1}f_{k,s_k} \right)
        *       x^j
        *     \right]
        */

        Scalar pow(uint64_t(1));
        std::vector<Scalar> f_part_product;    // partial product of f array elements for lastIndex
        for (int j = m - 1; j >= 0; j--) {
            f_part_product.push_back(pow);
            pow *= f_[t][j * n + I_[size - 1][j]];
        }

        NthPower xj(challenges[t]);
        for (std::size_t j = 0; j < m; j++) {
            Scalar fi_sum(uint64_t(0));
            for (std::size_t i = I_[size - 1][j] + 1; i < n; i++)
                fi_sum += f_[t][j*n + i];
            pow += fi_sum * xj.pow * f_part_product[m - j - 1];
            xj.go_next();
        }

        f_i_t[N - 1] += pow * y[t];
        e += pow;

        e *= serials[t] * y[t];
        exp += e;
    }

    secp_primitives::MultiExponent mult(commits, f_i_t);
    GroupElement t1 = mult.get_multiple();

    std::vector<std::vector<Scalar>> x_t_k_neg;
    x_t_k_neg.resize(M);
    for (int t = 0; t < M; ++t) {
        x_t_k_neg[t].reserve(m);
        NthPower x_k(challenges[t]);
        for (uint64_t k = 0; k < m; ++k) {
            x_t_k_neg[t].emplace_back(x_k.pow.negate());
            x_k.go_next();
        }
    }
    GroupElement t2;
    for (int t = 0; t < M; ++t) {
        const std::vector <GroupElement>& Gk = proofs[t].Gk_;
        const std::vector <GroupElement>& Qk = proofs[t].Qk;
        GroupElement term;
        for (std::size_t k = 0; k < m; ++k)
        {
            term += ((Gk[k] + Qk[k]) * x_t_k_neg[t][k]);
        }
        term *= y[t];
        t2 += term;
    }
    GroupElement left(t1 + t2);

    right += g_ * exp;
    if (left != right)
        return false;
    return true;
}

bool SigmaExtendedVerifier::membership_checks(const SigmaExtendedProof& proof) const {
    if (!(proof.A_.isMember() &&
         proof.B_.isMember() &&
         proof.C_.isMember() &&
         proof.D_.isMember()) ||
        (proof.A_.isInfinity() ||
         proof.B_.isInfinity() ||
         proof.C_.isInfinity() ||
         proof.D_.isInfinity()))
        return false;

    for (std::size_t i = 0; i < proof.f_.size(); i++)
    {
        if (!proof.f_[i].isMember() || proof.f_[i].isZero())
            return false;
    }
    const std::vector <GroupElement>& Gk = proof.Gk_;
    const std::vector <GroupElement>& Qk = proof.Qk;
    for (std::size_t k = 0; k < m; ++k)
    {
        if (!(Gk[k].isMember() && Qk[k].isMember())
           || Gk[k].isInfinity() || Qk[k].isInfinity())
            return false;
    }
    if(!(proof.ZA_.isMember() &&
         proof.ZC_.isMember() &&
         proof.zV_.isMember() &&
         proof.zR_.isMember()) ||
        (proof.ZA_.isZero() ||
         proof.ZC_.isZero() ||
         proof.zV_.isZero() ||
         proof.zR_.isZero()))
        return false;
    return true;
}

bool SigmaExtendedVerifier::compute_fs(
        const SigmaExtendedProof& proof,
        const Scalar& x,
        std::vector<Scalar>& f_) const {
    for(unsigned int j = 0; j < proof.f_.size(); ++j) {
        if(proof.f_[j] == x)
            return false;
    }

    f_.reserve(n * m);
    for (std::size_t j = 0; j < m; ++j)
    {
        f_.push_back(Scalar(uint64_t(0)));
        Scalar temp;
        int k = n - 1;
        for (int i = 0; i < k; ++i)
        {
            temp += proof.f_[j * k + i];
            f_.emplace_back(proof.f_[j * k + i]);
        }
        f_[j * n] = x - temp;
    }
    return true;
}

bool SigmaExtendedVerifier::abcd_checks(
        const SigmaExtendedProof& proof,
        const Scalar& x,
        const std::vector<Scalar>& f_) const {
    Scalar c;
    c.randomize();

    // Aggregating two checks into one, B^x * A = Comm(..) and C^x * D = Comm(..)
    std::vector<Scalar> f_plus_f_prime;
    f_plus_f_prime.reserve(f_.size());
    for (std::size_t i = 0; i < f_.size(); i++)
        f_plus_f_prime.emplace_back(f_[i] * c + f_[i] * (x - f_[i]));

    GroupElement right;
    LelantusPrimitives::commit(g_, h_, f_plus_f_prime, proof.ZA_ * c + proof.ZC_, right);
    if (((proof.B_ * x + proof.A_) * c + proof.C_ * x + proof.D_) != right)
        return false;
    return true;
}

void SigmaExtendedVerifier::compute_fis(int j, const std::vector<Scalar>& f, std::vector<Scalar>& f_i_) const {
    Scalar f_i(uint64_t(1));
    std::vector<Scalar>::iterator ptr = f_i_.begin();
    compute_fis(f_i, m, f, ptr, f_i_.end());
}

void SigmaExtendedVerifier::compute_fis(
        const Scalar& f_i,
        int j,
        const std::vector<Scalar>& f,
        std::vector<Scalar>::iterator& ptr,
        std::vector<Scalar>::iterator end_ptr) const {
    j--;
    if (j == -1)
    {
        if (ptr < end_ptr)
            *ptr++ += f_i;
        return;
    }

    Scalar t;

    for (int i = 0; i < n; i++)
    {
        t = f[j * n + i];
        t *= f_i;

        compute_fis(t, j, f, ptr, end_ptr);
    }
}

void SigmaExtendedVerifier::compute_batch_fis(
        const Scalar& f_i,
        int j,
        const std::vector<Scalar>& f,
        const Scalar& y,
        Scalar& e,
        std::vector<Scalar>::iterator& ptr,
        std::vector<Scalar>::iterator start_ptr,
        std::vector<Scalar>::iterator end_ptr) const {
    j--;
    if (j == -1)
    {
        if(ptr >= start_ptr && ptr < end_ptr){
            *ptr++ += f_i * y;
            e += f_i;
        }
        return;
    }

    Scalar t;

    for (int i = 0; i < n; i++)
    {
        t = f[j * n + i];
        t *= f_i;

        compute_batch_fis(t, j, f, y, e, ptr, start_ptr, end_ptr);
    }
}

} //namespace lelantus