#ifndef FIRO_LIBLELANTUS_INNER_PRODUCT_PROOF_VERIFIER_H
#define FIRO_LIBLELANTUS_INNER_PRODUCT_PROOF_VERIFIER_H

#include "lelantus_primitives.h"
#include "challenge_generator_impl.h"

namespace lelantus {
    
class InnerProductProofVerifier {

public:
    //g and h are being kept by reference, be sure it will not be modified from outside
    InnerProductProofVerifier(
            const std::vector<GroupElement>& g,
            const std::vector<GroupElement>& h,
            const GroupElement& u,
            const GroupElement& P,
            int version); // if(version >= 2) we should pass CHash256 in verify

    bool verify(const Scalar& x, const InnerProductProof& proof, std::unique_ptr<ChallengeGenerator>& challengeGenerator);
    bool verify_fast(std::size_t n, const Scalar& x, const InnerProductProof& proof, std::unique_ptr<ChallengeGenerator>& challengeGenerator);

private:
    bool verify_util(
            const InnerProductProof& proof,
            typename std::vector<GroupElement>::const_iterator ltr_l,
            typename std::vector<GroupElement>::const_iterator itr_r,
            std::unique_ptr<ChallengeGenerator>& challengeGenerator);

    bool verify_fast_util(std::size_t n, const InnerProductProof& proof, std::unique_ptr<ChallengeGenerator>& challengeGenerator);

private:
    const std::vector<GroupElement>& g_;
    const std::vector<GroupElement>& h_;
    GroupElement u_;
    GroupElement P_;
    int version_;

};

} // namespace lelantus

#endif //FIRO_LIBLELANTUS_INNER_PRODUCT_PROOF_VERIFIER_H
