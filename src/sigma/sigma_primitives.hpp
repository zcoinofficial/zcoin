#include "../../crypto/sha256.h"

namespace sigma {

template<class Exponent, class GroupElement>
void SigmaPrimitives<Exponent, GroupElement>::commit(const GroupElement& g,
        const std::vector<GroupElement>& h,
        const std::vector<Exponent>& exp,
        const Exponent& r,
        GroupElement& result_out) {
    secp_primitives::MultiExponent mult(h, exp);
    result_out += g * r + mult.get_multiple();
}

template<class Exponent, class GroupElement>
GroupElement SigmaPrimitives<Exponent, GroupElement>::commit(
        const GroupElement& g,
        const Exponent m,
        const GroupElement h,
        const Exponent r){
    return g * m + h * r;
}

template<class Exponent, class GroupElement>
void SigmaPrimitives<Exponent, GroupElement>::convert_to_sigma(
        std::size_t num,
        std::size_t n,
        std::size_t m,
        std::vector<Exponent>& out) {
    std::size_t rem;
    std::size_t j = 0;

    for (j = 0; j < m; ++j)
    {
        rem = num % n;
        num /= n;
        for (std::size_t i = 0; i < n; ++i) {
            if(i == rem)
                out.push_back(Exponent(uint64_t(1)));
            else
                out.push_back(Exponent(uint64_t(0)));
        }
    }
}

template<class Exponent, class GroupElement>
std::vector<std::size_t> SigmaPrimitives<Exponent, GroupElement>::convert_to_nal(
        std::size_t num,
        std::size_t n,
        std::size_t m) {
    std::vector<std::size_t> result;
    result.reserve(m);
    while (num != 0)
    {
        result.emplace_back(num % n);
        num /= n;
    }
    result.resize(m);
    return result;
}

template<class Exponent, class GroupElement>
void SigmaPrimitives<Exponent, GroupElement>::generate_challenge(
        const std::vector<GroupElement>& group_elements,
        Exponent& result_out) {
    if (group_elements.empty())
        throw std::runtime_error("Group elements empty while generating a challenge.");
    CSHA256 hash;
    std::vector<unsigned char> data(group_elements.size() * group_elements[0].memoryRequired());
    unsigned char* current = data.data();
    for (size_t i = 0; i < group_elements.size(); ++i) {
        current = group_elements[i].serialize(current);
    }
    hash.Write(data.data(), data.size());
    unsigned char result_data[CSHA256::OUTPUT_SIZE];
    hash.Finalize(result_data);
    result_out = result_data;
}

template<class Exponent, class GroupElement>
void SigmaPrimitives<Exponent, GroupElement>::new_factor(
        const Exponent& x,
        const Exponent& a,
        std::vector<Exponent>& coefficients) {
    std::size_t degree = coefficients.size();
    coefficients.push_back(x * coefficients[degree-1]);
    for (std::size_t d = degree-1; d >= 1; --d)
        coefficients[d] = a * coefficients[d] + x * coefficients[d-1];
    coefficients[0] *= a;
}

} // namespace sigma
