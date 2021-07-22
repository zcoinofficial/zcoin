#include "packetencoder.h"

#include "rules.h"
#include "script.h"
#include "utilsbitcoin.h"

#include "../base58.h"
#include "../utilstrencodings.h"

#include "../crypto/sha256.h"

#include "../script/standard.h"

#include <algorithm>
#include <array>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

#include <ctype.h>

namespace elysium {

const std::array<unsigned char, 7> magic = { 0x65, 0x6c, 0x79, 0x73, 0x69, 0x75, 0x6d }; // "elysium"

// Functions.


const CBitcoinAddress& GetSystemAddress()
{
    static const CBitcoinAddress mainAddress("a1kCCGddf5pMXSipLVD9hBG2MGGVNaJ15U");
    static const CBitcoinAddress testAddress("TKPbcG9QVLSfNvrtowQ7GzEEXq4zPjkej6");

    return isNonMainNet() ? testAddress : mainAddress;
}

boost::optional<PacketClass> DeterminePacketClass(const CTransaction& tx, int height)
{
    // Inspect all outputs.
    bool hasOpReturn = false;

    for (auto& output : tx.vout) {
        txnouttype type;

        if (!GetOutputType(output.scriptPubKey, type)) {
            continue;
        }

        if (!IsAllowedOutputType(type, height)) {
            continue;
        }

        if (type == TX_NULL_DATA) {
            // Check if the first push is prefixed with magic bytes.
            std::vector<std::vector<unsigned char>> pushes;

            GetPushedValues(output.scriptPubKey, std::back_inserter(pushes));

            if (!pushes.empty() && pushes[0].size() >= magic.size() && std::equal(magic.begin(), magic.end(), pushes[0].begin())) {
                hasOpReturn = true;
            }
        }
    }

    // Determine packet class based on inspection result.
    if (hasOpReturn) {
        return PacketClass::C;
    }

    return boost::none;
}

} // namespace elysium

namespace std {

using namespace elysium;

string to_string(PacketClass c)
{
    switch (c) {
    case PacketClass::C:
        return "C";
    default:
        throw invalid_argument("Packet class is not valid");
    }
}

} // namespace std
