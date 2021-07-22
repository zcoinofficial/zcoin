// Copyright (c) 2020 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FIRO_ELYSIUM_LELANTUSPRIMITIVES_H
#define FIRO_ELYSIUM_LELANTUSPRIMITIVES_H

#include "../liblelantus/coin.h"
#include "../liblelantus/joinsplit.h"
#include "../uint256.h"

#include <cstdint>

namespace elysium {

typedef uint64_t LelantusAmount;
typedef uint32_t LelantusGroup;
typedef uint64_t LelantusIndex;

// Get from Sigma
uint160 GetSerialId(const secp_primitives::Scalar &serial);

// Id of mint calculated from seed regardless of amount
class MintEntryId : public uint256 {
public:
    MintEntryId();
    MintEntryId(lelantus::PrivateCoin const &coin, uint160 const &seedId);
    MintEntryId(secp_primitives::Scalar const &serial, secp_primitives::Scalar const &randomness, uint160 const &seedId);
    MintEntryId(uint256 const &tag);
};

typedef std::array<uint8_t, 32> ECDSAPrivateKey;

// class to store secret data except amount
class LelantusPrivateKey {
public:
    LelantusPrivateKey(lelantus::Params const *params);
    LelantusPrivateKey(
        lelantus::Params const *params,
        secp_primitives::Scalar const &serial,
        secp_primitives::Scalar const &randomness,
        ECDSAPrivateKey const &ecdsaPrivateKey);

public:
    lelantus::PrivateCoin GetPrivateCoin(LelantusAmount amount) const;

private:
    const lelantus::Params* params;

public:
    secp_primitives::Scalar serial;
    secp_primitives::Scalar randomness;
    ECDSAPrivateKey ecdsaPrivateKey;
};

// class to store all data needed for joinsplit
class SpendableCoin {
public:
    SpendableCoin(LelantusPrivateKey const &_privateKey, LelantusAmount _amount, MintEntryId const &_id);

public:
    LelantusPrivateKey privateKey;
    LelantusAmount amount;
    MintEntryId id;
};

typedef unsigned char EncryptedValue[16];

class JoinSplitMint {
public:
    JoinSplitMint();
    JoinSplitMint(MintEntryId _id, lelantus::PublicCoin const &_publicCoin, EncryptedValue const &_encryptedValue);

public:
    MintEntryId id;
    lelantus::PublicCoin publicCoin;
    EncryptedValue encryptedValue;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(id);
        READWRITE(publicCoin);
        READWRITE(FLATDATA(encryptedValue));
    }
};

lelantus::JoinSplit CreateJoinSplit(
    std::vector<std::pair<lelantus::PrivateCoin, uint32_t>> const &coins,
    std::map<uint32_t, std::vector<lelantus::PublicCoin>> const &anonss,
    std::vector<std::vector<unsigned char>> anonymitySetHashes,
    LelantusAmount amount,
    std::vector<lelantus::PrivateCoin> const &coinOuts,
    std::map<uint32_t, uint256> const &groupBlockHashs,
    uint256 const &metaData);

} // namespace elysium

#endif // FIRO_ELYSIUM_LELANTUSPRIMITIVES_H
