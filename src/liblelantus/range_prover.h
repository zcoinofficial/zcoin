#ifndef FIRO_LIBLELANTUS_RANGE_PROVER_H
#define FIRO_LIBLELANTUS_RANGE_PROVER_H

#include "innerproduct_proof_generator.h"

namespace lelantus {
    
class RangeProver {
public:
    RangeProver(
            const GroupElement& g
            , const GroupElement& h1
            , const GroupElement& h2
            , const std::vector<GroupElement>& g_vector
            , const std::vector<GroupElement>& h_vector
            , std::size_t n
            , unsigned int v);

    // commitments are included into transcript if version >= LELANTUS_TX_VERSION_4_5
    void proof(
            const std::vector<Scalar>& v
            , const std::vector<Scalar>& serialNumbers
            , const std::vector<Scalar>& randomness
            , const std::vector<GroupElement>& commitments
            , RangeProof& proof_out);

private:
    GroupElement g;
    GroupElement h1;
    GroupElement h2;
    std::vector<GroupElement> g_;
    std::vector<GroupElement> h_;
    std::size_t n;
    unsigned int version;

};

}//namespace lelantus

#endif //FIRO_LIBLELANTUS_RANGE_PROVER_H
