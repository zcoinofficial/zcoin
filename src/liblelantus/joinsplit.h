#ifndef FIRO_LIBLELANTUS_JOINSPLIT_H
#define FIRO_LIBLELANTUS_JOINSPLIT_H

#include "coin.h"
#include "lelantus_proof.h"
#include "spend_metadata.h"

namespace lelantus {

class JoinSplit {
public:
    template<typename Stream>
    JoinSplit(const Params* p,  Stream& strm):
            params(p) {
        strm >> *this;
    }

    JoinSplit(const Params* p,
              const std::vector<std::pair<PrivateCoin, uint32_t>>& Cin,
              const std::map<uint32_t, std::vector<PublicCoin>>& anonymity_sets,
              const std::vector<std::vector<unsigned char>>& anonymity_set_hashes,
              const Scalar& Vout,
              const std::vector<PrivateCoin>& Cout,
              uint64_t fee,
              const std::map<uint32_t, uint256>& groupBlockHashes,
              const uint256& txHash,
              unsigned int nVersion);

    bool Verify(const std::map<uint32_t, std::vector<PublicCoin>>& anonymity_sets,
                const std::vector<std::vector<unsigned char>>& anonymity_set_hashes,
                const std::vector<PublicCoin>& Cout,
                uint64_t Vout,
                const uint256& txHash) const;

#ifdef ENABLE_ELYSIUM
    bool VerifyElysium(const std::map<uint32_t, std::vector<PublicCoin>>& anonymity_sets,
                       const std::vector<std::vector<unsigned char>>& anonymity_set_hashes,
                       const std::vector<PublicCoin>& Cout,
                       uint64_t Vout,
                       const uint256& txHash) const;
#endif

    bool Verify(const std::map<uint32_t, std::vector<PublicCoin>>& anonymity_sets,
                const std::vector<std::vector<unsigned char>>& anonymity_set_hashes,
                const std::vector<PublicCoin>& Cout,
                uint64_t Vout,
                const uint256& txHash,
                Scalar& challenge,
                bool fSkipVerification = false,
                boost::optional<int64_t> nMaxValueLelantusSpendPerTransaction = boost::none) const;

    void generatePubKeys(const std::vector<std::pair<PrivateCoin, uint32_t>>& Cin);

    void signMetaData(const std::vector<std::pair<PrivateCoin, uint32_t>>& Cin, const SpendMetaData& m, size_t coutSize);

    uint256 signatureHash(const SpendMetaData& m, size_t coutSize) const;

    void setVersion(unsigned int nVersion) {
        version = nVersion;
    }

    const std::vector<Scalar>& getCoinSerialNumbers();

    const LelantusProof& getLelantusProof();

    uint64_t getFee();

    const std::vector<uint32_t>& getCoinGroupIds();

    const std::vector<std::pair<uint32_t, uint256>>& getIdAndBlockHashes();

    int getVersion() const {
        return version;
    }

    bool getIndex(const PublicCoin& coin, const std::vector<PublicCoin>& anonymity_set, size_t& index);

    bool HasValidSerials() const;

    std::vector<std::vector<unsigned char>> const & GetEcdsaPubkeys() const {
        return ecdsaPubkeys;
    }

    bool isSigmaToLelantus() const;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(lelantusProof);
        READWRITE(coinNum);

        if (ser_action.ForRead())
        {
            groupIds.resize(coinNum);
            ecdsaSignatures.resize(coinNum);
            ecdsaPubkeys.resize(coinNum);
        }

        for(uint8_t i = 0; i < coinNum; i++)
        {
            READWRITE(groupIds[i]);
            size_t sigSize = 64;
            size_t pubKeySize = 33;
            if (ser_action.ForRead())
            {
                ecdsaSignatures[i].resize(sigSize);
                ecdsaPubkeys[i].resize(pubKeySize);
            }

            for (size_t j = 0; j < sigSize; j++)
                READWRITE(ecdsaSignatures[i][j]);
            for (size_t j = 0; j < pubKeySize; j++)
                READWRITE(ecdsaPubkeys[i][j]);
        }

        READWRITE(coinGroupIdAndBlockHash);
        READWRITE(fee);
        READWRITE(version);

        if (version >= LELANTUS_TX_VERSION_4_5)
            READWRITE(qkSchnorrProof);

        if (ser_action.ForRead()) {
            serialNumbers.resize(coinNum);
            for(size_t i = 0; i < coinNum; i++) {
                secp256k1_pubkey pubkey;
                if (!secp256k1_ec_pubkey_parse(OpenSSLContext::get_context(), &pubkey, ecdsaPubkeys[i].data(), 33)) {
                    throw std::invalid_argument("Lelantus joinsplit unserialize failed due to unable to parse ecdsaPubkey.");
                }

                serialNumbers[i] = PrivateCoin::serialNumberFromSerializedPublicKey(OpenSSLContext::get_context(), &pubkey);
            }
        }
    }

private:
    const Params* params;
    unsigned int version = 0;
    LelantusProof lelantusProof;
    SchnorrProof qkSchnorrProof;
    uint8_t coinNum;
    std::vector<Scalar> serialNumbers;
    std::vector<uint32_t> groupIds;
    std::vector<std::vector<unsigned char>> ecdsaSignatures;
    std::vector<std::vector<unsigned char>> ecdsaPubkeys;
    std::vector<std::pair<uint32_t, uint256>> coinGroupIdAndBlockHash;
    uint64_t fee;

};

} //namespace lelantus

#endif //FIRO_LIBLELANTUS_JOINSPLIT_H
