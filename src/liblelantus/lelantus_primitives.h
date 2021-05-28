#ifndef FIRO_LIBLELANTUS_LELANTUSPRIMITIVES_H
#define FIRO_LIBLELANTUS_LELANTUSPRIMITIVES_H

#include <secp256k1/include/Scalar.h>
#include <secp256k1/include/GroupElement.h>
#include <secp256k1/include/MultiExponent.h>
#include "sigmaextended_proof.h"
#include "lelantus_proof.h"
#include "schnorr_proof.h"
#include "innerproduct_proof.h"
#include "range_proof.h"
#include "challenge_generator.h"
#include "../firo_params.h"

#include "serialize.h"

#include <vector>
#include <algorithm>

namespace lelantus {

struct NthPower {
    Scalar num;
    Scalar pow;

    NthPower(const Scalar& num_) : num(num_), pow(uint64_t(1)) {}
    NthPower(const Scalar& num_, const Scalar& pow_) : num(num_), pow(pow_) {}

    // be careful and verify that you have catch on upper level
    void go_next() {
        pow *= num;
        if (pow == Scalar(uint64_t(1)))
            throw std::invalid_argument("NthPower resulted 1");
    }
};

class LelantusPrimitives {

public:
////common functions
    static std::vector<Scalar> invert(const std::vector<Scalar>& scalars);

    static void generate_challenge(
            const std::vector<GroupElement>& group_elements,
            const std::string& domain_separator,
            Scalar& result_out);

    static GroupElement commit(
            const GroupElement& g,
            const Scalar& m,
            const GroupElement& h,
            const Scalar& r);

    static GroupElement double_commit(
            const GroupElement& g,
            const Scalar& m,
            const GroupElement& hV,
            const Scalar& v,
            const GroupElement& hR,
            const Scalar& r);
////functions for sigma
    static void commit(
            const GroupElement& g,
            const std::vector<GroupElement>& h,
            const std::vector<Scalar>& exp,
            const Scalar& r,
            GroupElement& result_out);

    static void convert_to_sigma(uint64_t num, uint64_t n, uint64_t m, std::vector<Scalar>& out);

    static std::vector<uint64_t> convert_to_nal(uint64_t num, uint64_t n, uint64_t m);

    static void generate_Lelantus_challenge(
            const std::vector<SigmaExtendedProof>& proofs,
            const std::vector<std::vector<unsigned char>>& anonymity_set_hashes,
            const std::vector<Scalar>& serialNumbers,
            const std::vector<std::vector<unsigned char>>& ecdsaPubkeys,
            const std::vector<GroupElement>& Cout,
            unsigned int version,
            std::unique_ptr<ChallengeGenerator>& challengeGenerator,
            Scalar& result_out);

    static void new_factor(const Scalar& x, const Scalar& a, std::vector<Scalar>& coefficients);
//// functions for bulletproofs
    static void commit(
            const GroupElement& h,
            const Scalar& h_exp,
            const std::vector<GroupElement>& g_,
            const std::vector<Scalar>& L,
            const std::vector<GroupElement>& h_,
            const std::vector<Scalar>& R,
            GroupElement& result_out);

    // computes dot product of two Scalar vectors
    static Scalar scalar_dot_product(
            typename std::vector<Scalar>::const_iterator a_start,
            typename std::vector<Scalar>::const_iterator a_end,
            typename std::vector<Scalar>::const_iterator b_start,
            typename std::vector<Scalar>::const_iterator b_end);

    static void g_prime(
            const std::vector<GroupElement>& g_,
            const Scalar& x,
            std::vector<GroupElement>& result);

    static void h_prime(
            const std::vector<GroupElement>& h_,
            const Scalar& x,
            std::vector<GroupElement>& result);

    static GroupElement p_prime(
            const GroupElement& P_,
            const GroupElement& L,
            const GroupElement& R,
            const Scalar& x);

    static Scalar delta(const Scalar& y, const Scalar& z, std::size_t n, std::size_t m);

};

}// namespace lelantus

#endif //FIRO_LIBLELANTUS_LELANTUSPRIMITIVES_H
