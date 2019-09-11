#include "exodus.h"
#include "sigma.h"

#include "../sigma/sigma_primitives.h"
#include "../main.h"

#include <stdexcept>

#include <assert.h>

namespace exodus {

// SigmaPrivateKey Implementation.

SigmaPrivateKey::SigmaPrivateKey(const sigma::Params *params) : params(params)
{
    assert(params != nullptr);
}

bool SigmaPrivateKey::IsValid() const
{
    return serial.isMember() && randomness.isMember();
}

void SigmaPrivateKey::SetSerial(const secp_primitives::Scalar& v)
{
    serial = v;
}

void SigmaPrivateKey::SetRandomness(const secp_primitives::Scalar& v)
{
    randomness = v;
}

bool SigmaPrivateKey::operator==(const SigmaPrivateKey& other) const
{
    return serial == other.serial && randomness == other.randomness;
}

bool SigmaPrivateKey::operator!=(const SigmaPrivateKey& other) const
{
    return !(*this == other);
}

void SigmaPrivateKey::Set(const secp_primitives::Scalar& serial, const secp_primitives::Scalar& randomness)
{
    SetSerial(serial);
    SetRandomness(randomness);
}

void SigmaPrivateKey::Generate()
{
    do {
        serial.randomize();
        randomness.randomize();
    } while (!IsValid());
}

// SigmaPublicKey Implementation.

SigmaPublicKey::SigmaPublicKey()
{
}

SigmaPublicKey::SigmaPublicKey(const SigmaPrivateKey& pkey)
{
    Generate(pkey);
}

bool SigmaPublicKey::operator==(const SigmaPublicKey& other) const
{
    return commitment == other.commitment;
}

bool SigmaPublicKey::IsValid() const
{
    return commitment.isMember();
}

void SigmaPublicKey::SetCommitment(const secp_primitives::GroupElement& v)
{
    commitment = v;
}

void SigmaPublicKey::Generate(const SigmaPrivateKey& pkey)
{
    if (!pkey.IsValid()) {
        throw std::invalid_argument("The private key is not valid");
    }

    commitment = sigma::SigmaPrimitives<secp_primitives::Scalar, secp_primitives::GroupElement>::commit(
        pkey.GetParams()->get_g(),
        pkey.GetSerial(),
        pkey.GetParams()->get_h0(),
        pkey.GetRandomness()
    );
}

// SigmaProof Implementation.

SigmaProof::SigmaProof() : proof(nullptr)
{
}

void SigmaProof::SetSerial(const secp_primitives::Scalar& v)
{
    serial = v;
}

void SigmaProof::SetProof(const sigma::SigmaPlusProof<secp_primitives::Scalar, secp_primitives::GroupElement>& v)
{
    proof = v;
}

std::pair<SigmaProof, uint16_t> CreateSigmaSpend(
    SigmaPrivateKey const &priv, uint32_t propertyId, uint8_t denomination, uint32_t group)
{
    LOCK(cs_main);

    std::vector<SigmaPublicKey> coins;
    sigmaDb->GetAnonimityGroup(propertyId, denomination, group, std::back_inserter(coins));

    if (coins.size() < 2) {
        throw std::runtime_error("amount of coins in anonimity is not enough to spend");
    }

    SigmaProof p;
    p.Generate(priv, coins.begin(), coins.end());

    // Make sure spend is spendable.
    if (!VerifySigmaSpend(propertyId, denomination, group, coins.size(), p, priv.GetParams())) {
        throw std::runtime_error("failed to create spendable mint");
    }

    return std::make_pair(p, coins.size());
}

bool VerifySigmaSpend(uint32_t propertyId, uint8_t denomination, uint32_t group,
    uint16_t groupSize, SigmaProof &proof, sigma::Params const *params)
{
    LOCK(cs_main);

    std::vector<SigmaPublicKey> coins;
    coins.reserve(groupSize);
    sigmaDb->GetAnonimityGroup(propertyId, denomination, group, groupSize, std::back_inserter(coins));

    return proof.Verify(params, coins.begin(), coins.end());
}

} // namespace exodus