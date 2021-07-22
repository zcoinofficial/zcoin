#ifndef FIRO_ELYSIUM_PACKETENCODER_H
#define FIRO_ELYSIUM_PACKETENCODER_H

#include "script.h"

#include "../base58.h"
#include "../pubkey.h"
#include "../random.h"

#include "../primitives/transaction.h"

#include "../script/script.h"
#include "../script/standard.h"

#include <boost/optional.hpp>

#include <algorithm>
#include <array>
#include <iterator>
#include <ostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <inttypes.h>
#include <stddef.h>

namespace elysium {

static_assert(CPubKey::COMPRESSED_PUBLIC_KEY_SIZE >= 4, "Size of compressed public key must be at least 4 bytes");

enum class PacketClass
{
    C
};



/**
 * Prefix of class C packet.
 **/
extern const std::array<unsigned char, 7> magic;

const CBitcoinAddress& GetSystemAddress();
boost::optional<PacketClass> DeterminePacketClass(const CTransaction& tx, int height);

/**
 * Embedds a payload in an OP_RETURN output, prefixed with magic bytes.
 **/
template<typename Payload>
CTxOut EncodeClassC(Payload first, Payload last)
{
    std::vector<unsigned char> data;
    CScript script;

    data.insert(data.end(), magic.begin(), magic.end());
    data.insert(data.end(), first, last);

    script << OP_RETURN << data;

    if (script.size() > nMaxDatacarrierBytes) {
        throw std::invalid_argument("Payload is too large");
    }

    return CTxOut(0, script);
}

} // namespace elysium

namespace std {

using namespace elysium;

string to_string(PacketClass c);

template<typename Char, typename Traits>
basic_ostream<Char, Traits>& operator<<(basic_ostream<Char, Traits>& os, PacketClass v)
{
    return os << to_string(v);
}

} // namespace std

#endif // FIRO_ELYSIUM_PACKETENCODER_H
