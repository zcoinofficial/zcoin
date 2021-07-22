#ifndef FIRO_SIGMA_SIGMA_PRIMITIVES_H
#define FIRO_SIGMA_SIGMA_PRIMITIVES_H

#include "../secp256k1/include/MultiExponent.h"
#include "../secp256k1/include/GroupElement.h"
#include "../secp256k1/include/Scalar.h"

#include <algorithm>
#include <vector>

namespace sigma {

template<class Exponent>
struct NthPower {
    Exponent num;
    Exponent pow;

    NthPower(const Exponent& num_) : num(num_), pow(uint64_t(1)) {}
    NthPower(const Exponent& num_, const Exponent& pow_) : num(num_), pow(pow_) {}

    void go_next() {
        pow *= num;
    }
};

template<class Exponent, class GroupElement>
class SigmaPrimitives {

public:
    static void commit(const GroupElement& g,
            const std::vector<GroupElement>& h,
            const std::vector<Exponent>& exp,
            const Exponent& r,
            GroupElement& result_out);

    static GroupElement commit(const GroupElement& g, const Exponent m, const GroupElement h, const Exponent r);

    static void convert_to_sigma(std::size_t num, std::size_t n, std::size_t m, std::vector<Exponent>& out);

    static std::vector<std::size_t> convert_to_nal(std::size_t num, std::size_t n, std::size_t m);

    static void generate_challenge(const std::vector<GroupElement>& group_elements,
                                   Exponent& result_out);

    /** \brief Adds a factor of (x*x + a) to the given polynomial in coefficients.
     *  \param[in,out] coefficients Coefficients of the polynomial created.
     */
    static void new_factor(const Exponent& x, const Exponent& a, std::vector<Exponent>& coefficients);

    };

} // namespace sigma

#include "sigma_primitives.hpp"

#endif // FIRO_SIGMA_SIGMA_PRIMITIVES_H
