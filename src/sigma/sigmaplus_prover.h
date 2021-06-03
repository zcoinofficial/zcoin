#ifndef FIRO_SIGMA_SIGMAPLUS_PROVER_H
#define FIRO_SIGMA_SIGMAPLUS_PROVER_H

#include "r1_proof_generator.h"
#include "sigmaplus_proof.h"

#include <cstddef>

namespace sigma {

template <class Exponent, class GroupElement>
class SigmaPlusProver{

public:
    SigmaPlusProver(const GroupElement& g,
                    const std::vector<GroupElement>& h_gens, std::size_t n, std::size_t m);
    void proof(const std::vector<GroupElement>& commits,
               std::size_t l,
               const Exponent& r,
               bool fPadding,
               SigmaPlusProof<Exponent, GroupElement>& proof_out);

private:
    GroupElement g_;
    std::vector<GroupElement> h_;
    std::size_t n_;
    std::size_t m_;
};

} // namespace sigma

#include "sigmaplus_prover.hpp"

#endif // FIRO_SIGMA_SIGMAPLUS_PROVER_H
