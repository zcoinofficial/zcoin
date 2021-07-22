#ifndef FIRO_LIBLELANTUS_LELANTUSVERIFIER_H
#define FIRO_LIBLELANTUS_LELANTUSVERIFIER_H

#include "schnorr_verifier.h"
#include "sigmaextended_verifier.h"
#include "range_verifier.h"
#include "lelantus_primitives.h"
#include "coin.h"

namespace lelantus {
class LelantusVerifier {
public:
    LelantusVerifier(const Params* p, unsigned int v);

    bool verify(
            const std::map<uint32_t, std::vector<PublicCoin>>& anonymity_sets,
            const std::vector<std::vector<unsigned char>>& anonymity_set_hashes,
            const std::vector<Scalar>& serialNumbers,
            const std::vector<std::vector<unsigned char>>& ecdsaPubkeys,
            const std::vector<uint32_t>& groupIds,
            const Scalar& Vin,
            uint64_t Vout,
            uint64_t fee,
            const std::vector<PublicCoin>& Cout,
            const LelantusProof& proof,
            const SchnorrProof& qkSchnorrProof);

    bool verify(
            const std::map<uint32_t, std::vector<PublicCoin>>& anonymity_sets,
            const std::vector<std::vector<unsigned char>>& anonymity_set_hashes,
            const std::vector<Scalar>& serialNumbers,
            const std::vector<std::vector<unsigned char>>& ecdsaPubkeys,
            const std::vector<uint32_t>& groupIds,
            const Scalar& Vin,
            uint64_t Vout,
            uint64_t fee,
            const std::vector<PublicCoin>& Cout,
            const LelantusProof& proof,
            const SchnorrProof& qkSchnorrProof,
            Scalar& x,
            bool fSkipVerification = false,
            boost::optional<int64_t> nMaxValueLelantusSpendPerTransaction = boost::none);

private:
    bool verify_sigma(
            const std::vector<std::vector<PublicCoin>>& anonymity_sets,
            const std::vector<std::vector<unsigned char>>& anonymity_set_hashes,
            const std::vector<std::vector<Scalar>>& Sin,
            const std::vector<Scalar>& serialNumbers,
            const std::vector<std::vector<unsigned char>>& ecdsaPubkeys,
            const std::vector<PublicCoin>& Cout,
            const std::vector<SigmaExtendedProof> &sigma_proofs,
            const SchnorrProof& qkSchnorrProof,
            Scalar& x,
            std::unique_ptr<ChallengeGenerator>& challengeGenerator,
            Scalar& zV,
            Scalar& zR,
            bool fSkipVerification = false);
    bool verify_rangeproof(
            const std::vector<PublicCoin>& Cout,
            const RangeProof& bulletproofs);
    bool verify_schnorrproof(
            const Scalar& x,
            const Scalar& zV,
            const Scalar& zR,
            const Scalar& Vin,
            const Scalar& Vout,
            const Scalar fee,
            const std::vector<PublicCoin>& Cout,
            const LelantusProof& proof,
            std::unique_ptr<ChallengeGenerator>& challengeGenerator);

private:
    const Params* params;
    unsigned int version;

};
}// namespace lelantus

#endif //FIRO_LIBLELANTUS_LELANTUSVERIFIER_H
