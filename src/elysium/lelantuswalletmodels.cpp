#include "lelantuswalletmodels.h"

namespace elysium {

// LelantusMintChainState Implementation.

LelantusMintChainState::LelantusMintChainState() noexcept : block(-1), group(0), index(0)
{
}

LelantusMintChainState::LelantusMintChainState(int block, LelantusGroup group, LelantusIndex index) noexcept :
    block(block),
    group(group),
    index(index)
{
}

bool LelantusMintChainState::operator==(const LelantusMintChainState& other) const noexcept
{
    return block == other.block && group == other.group && index == other.index;
}

bool LelantusMintChainState::operator!=(const LelantusMintChainState& other) const noexcept
{
    return !(*this == other);
}

void LelantusMintChainState::Clear() noexcept
{
    block = -1;
    group = 0;
    index = 0;
}

// LelantusMint Implementation.

LelantusMint::LelantusMint() : property(0), amount(0)
{
}

LelantusMint::LelantusMint(PropertyId property, uint64_t amount, CKeyID const &seedId, uint160 const &serialId) :
    property(property), amount(amount), seedId(seedId), serialId(serialId)
{
}

bool LelantusMint::operator==(const LelantusMint& other) const
{
    return property == other.property &&
           amount == other.amount &&
           seedId == other.seedId &&
           serialId == other.serialId &&
           createdTx == other.createdTx &&
           chainState == other.chainState &&
           spendTx == other.spendTx;
}

bool LelantusMint::operator!=(const LelantusMint& other) const
{
    return !(*this == other);
}

// LelantusSpend Implementation.

LelantusSpend::LelantusSpend(
    MintEntryId const & mint,
    LelantusGroup group,
    size_t groupSize) :
    mint(mint),
    group(group),
    groupSize(groupSize)
{
}

} // namespace elysium
