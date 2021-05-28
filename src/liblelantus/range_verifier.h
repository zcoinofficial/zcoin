#ifndef FIRO_LIBLELANTUS_RANGE_VERIFIER_H
#define FIRO_LIBLELANTUS_RANGE_VERIFIER_H

#include "innerproduct_proof_verifier.h"

namespace lelantus {

class RangeVerifier {
public:
    //g_vector and h_vector are being kept by reference, be sure it will not be modified from outside
    RangeVerifier(
            const GroupElement& g
            , const GroupElement& h1
            , const GroupElement& h2
            , const std::vector<GroupElement>& g_vector
            , const std::vector<GroupElement>& h_vector
            , std::size_t n
            , unsigned int v);

    // commitments are included into transcript if version >= LELANTUS_TX_VERSION_4_5
    bool verify(const std::vector<GroupElement>& V, const std::vector<GroupElement>& commitments, const RangeProof& proof); // single proof
    bool verify(const std::vector<std::vector<GroupElement> >& V, const std::vector<std::vector<GroupElement> >& commitments, const std::vector<RangeProof>& proof); // batch of proofs

private:
    bool membership_checks(const RangeProof& proof);

private:
    GroupElement g;
    GroupElement h1;
    GroupElement h2;
    const std::vector<GroupElement>& g_;
    const std::vector<GroupElement>& h_;
    std::size_t n;
    unsigned int version;
};

}//namespace lelantus

#endif //FIRO_LIBLELANTUS_RANGE_VERIFIER_H
