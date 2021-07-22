#ifndef FIRO_ELYSIUM_LELANTUSWALLETMODELS_H
#define FIRO_ELYSIUM_LELANTUSWALLETMODELS_H

#include "property.h"
#include "lelantusprimitives.h"

#include "../pubkey.h"
#include "../serialize.h"
#include "../uint256.h"
#include "../liblelantus/coin.h"

#include <functional>
#include <ostream>

#include <stddef.h>

namespace elysium {

class LelantusMintChainState
{
public:
    int block;
    LelantusGroup group;
    LelantusIndex index;

public:
    LelantusMintChainState() noexcept;
    LelantusMintChainState(int block, LelantusGroup group, LelantusIndex index) noexcept;

    bool operator==(const LelantusMintChainState& other) const noexcept;
    bool operator!=(const LelantusMintChainState& other) const noexcept;

    void Clear() noexcept;

    ADD_SERIALIZE_METHODS;

private:
    template<typename Stream, typename Operation>
    void SerializationOp(Stream& s, Operation ser_action)
    {
        int32_t block = this->block;

        READWRITE(block);
        READWRITE(group);
        READWRITE(index);

        this->block = block;
    }
};

class LelantusMint
{
public:
    PropertyId property;
    LelantusAmount amount;
    CKeyID seedId;
    uint160 serialId;

    uint256 createdTx;
    LelantusMintChainState chainState;
    uint256 spendTx;

public:
    LelantusMint();
    LelantusMint(PropertyId property, LelantusAmount amount, CKeyID const &seedId, uint160 const &serialId);

    bool operator==(const LelantusMint& other) const;
    bool operator!=(const LelantusMint& other) const;

    bool IsOnChain() const
    {
        return chainState.block >= 0;
    }

    bool IsSpent() const
    {
        return !spendTx.IsNull();
    }

    ADD_SERIALIZE_METHODS;

private:
    template<typename Stream, typename Operation>
    void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(property);
        READWRITE(amount);
        READWRITE(seedId);
        READWRITE(serialId);
        READWRITE(createdTx);
        READWRITE(chainState);
        READWRITE(spendTx);
    }
};

class LelantusSpend
{
public:
    MintEntryId mint;
    LelantusGroup group;
    size_t groupSize;
    // SigmaProof proof;

public:
    LelantusSpend(
        MintEntryId const & mint,
        LelantusGroup group,
        size_t groupSize/*,
        const SigmaProof& proof*/);
};

} // namespace elysium

namespace std {

using namespace elysium;

// std::hash specialization.

template<>
struct hash<LelantusMintChainState>
{
    size_t operator()(const LelantusMintChainState& state) const
    {
        return hash<int>()(state.block)
            ^ hash<LelantusGroup>()(state.group)
            ^ hash<LelantusIndex>()(state.index);
    }
};

template<>
struct hash<MintEntryId>
{
    size_t operator()(const MintEntryId &id) const
    {
        return id.GetCheapHash();
    }
};

template<>
struct hash<LelantusMint>
{
    size_t operator()(const LelantusMint& mint) const
    {
        return hash<PropertyId>()(mint.property)
             ^ hash<LelantusAmount>()(mint.amount)
             ^ hash<uint160>()(mint.seedId)
             ^ hash<uint160>()(mint.serialId)
             ^ hash<uint256>()(mint.createdTx)
             ^ hash<LelantusMintChainState>()(mint.chainState)
             ^ hash<uint256>()(mint.spendTx);
    }
};

// basic_ostream supports.

template<class Char, class Traits>
basic_ostream<Char, Traits>& operator<<(basic_ostream<Char, Traits>& os, const LelantusMintChainState& state)
{
    return os << "{block: " << state.block << ", group: " << state.group << ", index: " << state.index << '}';
}

template<class Char, class Traits>
basic_ostream<Char, Traits>& operator<<(basic_ostream<Char, Traits>& os, const LelantusMint& mint)
{
    os << '{';
    os << "property: " << mint.property << ", ";
    os << "denomination: " << mint.amount << ", ";
    os << "seedId: " << mint.seedId.GetHex() << ", ";
    os << "serialId: " << mint.serialId.GetHex() << ", ";
    os << "chainState: " << mint.chainState << ", ";
    os << "spentTx: " << mint.spendTx.GetHex();
    os << '}';

    return os;
}

} // namespace std

#endif // FIRO_ELYSIUM_LELANTUSWALLETMODELS_H
