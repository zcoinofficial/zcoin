#ifndef FIRO_LIBLELANTUS_SIGMAEXTENDED_VERIFIER_H
#define FIRO_LIBLELANTUS_SIGMAEXTENDED_VERIFIER_H

#include "lelantus_primitives.h"

namespace lelantus {

class SigmaExtendedVerifier{

public:
    SigmaExtendedVerifier(const GroupElement& g,
                      const std::vector<GroupElement>& h_gens,
                      std::size_t n_, std::size_t m_);

    // Verify a single one-of-many proof
    // In this case, there is an implied input set size
    bool singleverify(const std::vector<GroupElement>& commits,
                     const Scalar& x,
                     const Scalar& serial,
                     const SigmaExtendedProof& proof) const;

    // Verify a single one-of-many proof
    // In this case, there is a specified set size
    bool singleverify(const std::vector<GroupElement>& commits,
                     const Scalar& x,
                     const Scalar& serial,
                     const size_t setSize,
                     const SigmaExtendedProof& proof) const;

    // Verify a batch of one-of-many proofs from the same transaction
    // In this case, there is a single common challenge and implied input set size
    bool batchverify(const std::vector<GroupElement>& commits,
                     const Scalar& x,
                     const std::vector<Scalar>& serials,
                     const std::vector<SigmaExtendedProof>& proofs) const;
    // Verify a general batch of one-of-many proofs
    // In this case, each proof has a separate challenge and specified set size
    bool batchverify(const std::vector<GroupElement>& commits,
                     const std::vector<Scalar>& challenges,
                     const std::vector<Scalar>& serials,
                     const std::vector<size_t>& setSizes,
                     const std::vector<SigmaExtendedProof>& proofs) const;

private:
    // Utility function that actually performs verification
    bool verify(const std::vector<GroupElement>& commits,
                     const std::vector<Scalar>& challenges,
                     const std::vector<Scalar>& serials,
                     const std::vector<size_t>& setSizes,
                     const bool commonChallenge,
                     const bool specifiedSetSizes,
                     const std::vector<SigmaExtendedProof>& proofs) const;
    //auxiliary functions
    bool membership_checks(const SigmaExtendedProof& proof) const;
    bool compute_fs(
            const SigmaExtendedProof& proof,
            const Scalar& x,
            std::vector<Scalar>& f_) const;

    void compute_fis(int j, const std::vector<Scalar>& f, std::vector<Scalar>& f_i_) const;
    void compute_fis(
            const Scalar& f_i,
            int j,
            const std::vector<Scalar>& f,
            std::vector<Scalar>::iterator& ptr,
            std::vector<Scalar>::iterator end_ptr) const;
    void compute_batch_fis(
            const Scalar& f_i,
            int j,
            const std::vector<Scalar>& f,
            const Scalar& y,
            Scalar& e,
            std::vector<Scalar>::iterator& ptr,
            std::vector<Scalar>::iterator start_ptr,
            std::vector<Scalar>::iterator end_ptr) const;

private:
    GroupElement g_;
    std::vector<GroupElement> h_;
    std::size_t n;
    std::size_t m;
};

} // namespace lelantus

#endif //FIRO_LIBLELANTUS_SIGMAEXTENDED_VERIFIER_H
