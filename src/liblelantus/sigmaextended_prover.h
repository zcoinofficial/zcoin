#ifndef FIRO_LIBLELANTUS_SIGMAEXTENDED_PROVER_H
#define FIRO_LIBLELANTUS_SIGMAEXTENDED_PROVER_H

#include "lelantus_primitives.h"

namespace lelantus {

class SigmaExtendedProver{

public:
    SigmaExtendedProver(const GroupElement& g,
                    const std::vector<GroupElement>& h_gens, std::size_t n, std::size_t m);

    void sigma_commit(
            const std::vector<GroupElement>& commits,
            std::size_t l,
            const Scalar& rA,
            const Scalar& rB,
            const Scalar& rC,
            const Scalar& rD,
            std::vector<Scalar>& a,
            std::vector<Scalar>& Tk,
            std::vector<Scalar>& Pk,
            std::vector<Scalar>& Yk,
            std::vector<Scalar>& sigma,
            SigmaExtendedProof& proof_out);

    void sigma_response(
            const std::vector<Scalar>& sigma,
            const std::vector<Scalar>& a,
            const Scalar& rA,
            const Scalar& rB,
            const Scalar& rC,
            const Scalar& rD,
            const Scalar& v,
            const Scalar& r,
            const std::vector<Scalar>& Tk,
            const std::vector<Scalar>& Pk,
            const Scalar& x,
            SigmaExtendedProof& proof_out);


private:
    GroupElement g_;
    std::vector<GroupElement> h_;
    std::size_t n_;
    std::size_t m_;
};

}//namespace lelantus

#endif //FIRO_LIBLELANTUS_SIGMAEXTENDED_PROVER_H
