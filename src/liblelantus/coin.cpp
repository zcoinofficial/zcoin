#include "coin.h"
#include "primitives/mint_spend.h"
#include "lelantus_primitives.h"

namespace lelantus {

static std::string zpts("PUBLICKEY_TO_SERIALNUMBER");

//class PublicCoin
PublicCoin::PublicCoin() {
}

PublicCoin::PublicCoin(const GroupElement& coin):
    value(coin) {
}

const GroupElement& PublicCoin::getValue() const {
    return this->value;
}

uint256 PublicCoin::getValueHash() const {
    return primitives::GetPubCoinValueHash(value);
}

bool PublicCoin::operator==(const PublicCoin& other) const {
    return (*this).value == other.value;
}

bool PublicCoin::operator!=(const PublicCoin& other) const {
    return (*this).value != other.value;
}

bool PublicCoin::validate() const {
    return this->value.isMember() && !this->value.isInfinity();
}

size_t PublicCoin::GetSerializeSize() const {
    return value.memoryRequired();
}

//class PrivateCoin
PrivateCoin::PrivateCoin(const Params* p, uint64_t v):
    params(p) {
    this->randomize();
    this->mintCoin(v);
}

PrivateCoin::PrivateCoin(
        const Params* p,
        const Scalar& serial,
        uint64_t v,
        const Scalar& random,
        const std::vector<unsigned char>& seckey,
        int version_) :
        params(p),
        serialNumber(serial),
        randomness(random),
        version(version_) {
    this->setEcdsaSeckey(seckey);
    this->mintCoin(v);
}

const Params* PrivateCoin::getParams() const {
    return this->params;
}

const PublicCoin& PrivateCoin::getPublicCoin() const {
    return this->publicCoin;
}

const Scalar& PrivateCoin::getSerialNumber() const {
    return this->serialNumber;
}

const Scalar& PrivateCoin::getRandomness() const {
    return this->randomness;
}

uint64_t PrivateCoin::getV() const {
    return this->value;
}

Scalar PrivateCoin::getVScalar() const {
    return Scalar(this->value);
}

unsigned int PrivateCoin::getVersion() const {
    return this->version;
}

void PrivateCoin::setPublicCoin(const PublicCoin& p) {
    publicCoin = p;
}

void PrivateCoin::setRandomness(const Scalar& n) {
    randomness = n;
}

const unsigned char* PrivateCoin::getEcdsaSeckey() const {
    return this->ecdsaSeckey;
}

void PrivateCoin::setEcdsaSeckey(const std::vector<unsigned char> &seckey) {
    if (seckey.size() == sizeof(ecdsaSeckey))
        std::copy(seckey.cbegin(), seckey.cend(), &ecdsaSeckey[0]);
    else
        throw std::invalid_argument("EcdsaSeckey size does not match.");
}

void PrivateCoin::setEcdsaSeckey(const uint256& seckey) {
    if (seckey.size() == sizeof(ecdsaSeckey))
        std::copy(seckey.begin(), seckey.end(), &ecdsaSeckey[0]);
    else
        throw std::invalid_argument("EcdsaSeckey size does not match.");
}

void PrivateCoin::setSerialNumber(const Scalar& n) {
    serialNumber = n;
}

void PrivateCoin::setV(uint64_t n) {
    value = n;
}

void PrivateCoin::setVersion(unsigned int nVersion) {
    version = nVersion;
}

void PrivateCoin::randomize() {
    // Create a key pair
    secp256k1_pubkey pubkey;
    do {
        if (RAND_bytes(this->ecdsaSeckey, sizeof(this->ecdsaSeckey)) != 1) {
            throw std::invalid_argument("Unable to generate randomness");
        }
    } while (!secp256k1_ec_pubkey_create(
            OpenSSLContext::get_context(), &pubkey, this->ecdsaSeckey));

    // Hash the public key in the group to obtain a serial number
    serialNumber = serialNumberFromSerializedPublicKey(
            OpenSSLContext::get_context(), &pubkey);

    randomness.randomize();
}

void PrivateCoin::mintCoin(uint64_t v) {
    value = v;
    GroupElement commit = LelantusPrimitives::double_commit(
            params->get_g(), serialNumber, params->get_h1(), getVScalar(), params->get_h0(), randomness);
    publicCoin = PublicCoin(commit);
}

Scalar PrivateCoin::serialNumberFromSerializedPublicKey(
        const secp256k1_context *context,
        secp256k1_pubkey *pubkey) {
    std::vector<unsigned char> pubkey_hash(32, 0);

    static const unsigned char one[32] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };

    // We use secp256k1_ecdh instead of secp256k1_serialize_pubkey to avoid a timing channel.
    if (1 != secp256k1_ecdh(context, pubkey_hash.data(), pubkey, &one[0])) {
        throw std::invalid_argument("Unable to compute public key hash with secp256k1_ecdh.");
    }

    std::vector<unsigned char> pre(zpts.begin(), zpts.end());
    std::copy(pubkey_hash.begin(), pubkey_hash.end(), std::back_inserter(pre));

    unsigned char hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(pre.data(), pre.size()).Finalize(hash);

    // Use 32 bytes of hash as coin serial.
    return Scalar(hash);
}

} //namespace lelantus