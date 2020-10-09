// Copyright (c) 2020 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "../primitives/zerocoin.h"

#include "lelantusprimitives.h"

namespace elysium {

MintEntryId::MintEntryId()
{
    SetNull();
}

MintEntryId::MintEntryId(lelantus::PrivateCoin const &coin, uint160 const &seedId)
    : MintEntryId(coin.getSerialNumber(), coin.getRandomness())
{
}

MintEntryId::MintEntryId(secp_primitives::Scalar const &serial, secp_primitives::Scalar const &randomness)
{

}

MintEntryId::MintEntryId(uint256 const &tag) : uint256(tag)
{
}

MintTag MintTag::CreateMintTag(
    lelantus::PrivateCoin const &coin,
    uint160 const &seedId,
    LelantusAmount amount)
{
    auto pubcoin = coin.getPublicCoin().getValue() +
        lelantus::Params::get_default()->get_h1() * Scalar(amount).negate();

    auto hashPub = primitives::GetPubCoinValueHash(pubcoin);
    CDataStream ss(SER_GETHASH, CLIENT_VERSION);
    ss << hashPub;
    ss << seedId;

    return Hash(ss.begin(), ss.end());
}

secp_primitives::GroupElement GetReduceCommitment(lelantus::PublicCoin const &pubCoin, LelantusAmount amount)
{
    return pubCoin.getValue() + lelantus::Params::get_default()->get_h1() * Scalar(amount).negate();
}

} // namespace elysium