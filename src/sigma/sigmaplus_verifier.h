#ifndef FIRO_SIGMA_SIGMAPLUS_VERIFIER_H
#define FIRO_SIGMA_SIGMAPLUS_VERIFIER_H

#include "r1_proof_verifier.h"
#include "util.h"

namespace sigma {
template<class Exponent, class GroupElement>
class SigmaPlusVerifier{

public:
    SigmaPlusVerifier(const GroupElement& g,
                      const std::vector<GroupElement>& h_gens,
                      std::size_t n, std::size_t m_);

    bool verify(const std::vector<GroupElement>& commits,
                const SigmaPlusProof<Exponent, GroupElement>& proof,
                bool fPadding) const;

    bool verify(const std::vector<GroupElement>& commits,
                const SigmaPlusProof<Exponent, GroupElement>& proof,
                bool fPadding,
                std::size_t setSize) const;

    bool batch_verify(const std::vector<GroupElement>& commits,
                      const std::vector<Exponent>& serials,
                      const std::vector<bool>& fPadding,
                      const std::vector<size_t>& setSizes,
                      const std::vector<SigmaPlusProof<Exponent, GroupElement>>& proofs) const;

    bool membership_checks(const SigmaPlusProof<Exponent, GroupElement>& proof) const;
    bool compute_fs(const SigmaPlusProof<Exponent, GroupElement>& proof, const Exponent& x, std::vector<Exponent>& f_) const;
    bool abcd_checks(const SigmaPlusProof<Exponent, GroupElement>& proof, const Exponent& x, const std::vector<Exponent>& f_) const;

    void compute_fis(int j, const std::vector<Exponent>& f, std::vector<Exponent>& f_i_) const;
    void compute_fis(const Exponent& f_i, int j, const std::vector<Exponent>& f, typename std::vector<Exponent>::iterator& ptr, typename std::vector<Exponent>::iterator end_ptr) const;
    void compute_batch_fis(
            const Exponent& f_i,
            int j,
            const std::vector<Exponent>& f,
            const Exponent& y,
            Exponent& e,
            typename std::vector<Exponent>::iterator& ptr,
            typename std::vector<Exponent>::iterator start_ptr,
            typename std::vector<Exponent>::iterator end_ptr) const;


private:
    GroupElement g_;
    std::vector<GroupElement> h_;
    std::size_t n;
    std::size_t m;
};

} // namespace sigma

#include "sigmaplus_verifier.hpp"

#endif // FIRO_SIGMA_SIGMAPLUS_VERIFIER_H
