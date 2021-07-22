#include "wallet.h"
#include "lelantusdb.h"
#include "sigma.h"

#include <functional>
#include <utility>

namespace elysium {

Wallet *wallet;

Wallet::Wallet(const std::string& walletFile) : walletFile(walletFile)
{
    using std::placeholders::_1;
    using std::placeholders::_2;
    using std::placeholders::_3;
    using std::placeholders::_4;
    using std::placeholders::_5;
    using std::placeholders::_6;

    // Subscribe to events.
    LOCK(cs_main);

    {
        auto h = std::bind(&Wallet::OnLelantusMintAdded, this, _1, _2, _3, _4, _5, _6);
        eventConnections.emplace_front(lelantusDb->MintAdded.connect(h));
    }
    {
        auto h = std::bind(&Wallet::OnLelantusMintRemoved, this, _1, _2);
        eventConnections.emplace_front(lelantusDb->MintRemoved.connect(h));
    }
}

Wallet::~Wallet()
{
}

void Wallet::ReloadMasterKey()
{
    lelantusWallet.ReloadMasterKey();
}

LelantusWallet::MintReservation Wallet::CreateLelantusMint(PropertyId property, LelantusAmount amount)
{
    return lelantusWallet.GenerateMint(property, amount);
}

void Wallet::SetLelantusMintUsedTransaction(const MintEntryId& id, const uint256& tx)
{
    lelantusWallet.UpdateMintSpendTx(id, tx);
}

void Wallet::ClearAllChainState()
{
	lelantusWallet.ClearMintsChainState();
}

bool Wallet::SyncWithChain()
{
    return lelantusWallet.SyncWithChain();
}

lelantus::JoinSplit Wallet::CreateLelantusJoinSplit(
    PropertyId property,
    CAmount amountToSpend,
    uint256 const &metadata,
    std::vector<SpendableCoin> &spendables,
    boost::optional<LelantusWallet::MintReservation> &changeMint,
    LelantusAmount &changeValue)
{
    return lelantusWallet.CreateJoinSplit(property, amountToSpend, metadata, spendables, changeMint, changeValue);
}

bool Wallet::HasLelantusMint(const MintEntryId& id)
{
    return lelantusWallet.HasMint(id);
}

bool Wallet::HasLelantusMint(const secp_primitives::Scalar &serial)
{
    return lelantusWallet.HasMint(serial);
}

void Wallet::SetLelantusMintChainState(const MintEntryId &id, const LelantusMintChainState &state)
{
    lelantusWallet.UpdateMintChainstate(id, state);
}

void Wallet::OnLelantusMintAdded(
    PropertyId property,
    MintEntryId id,
    LelantusGroup group,
    LelantusIndex idx,
    boost::optional<LelantusAmount> amount,
    int block)
{
    LogPrintf("%s : Mint added = block : %d, group : %d, idx : %d\n", __func__, block, group, idx);
    auto locked = pwalletMain->IsLocked();
    auto knowAmount = amount.get_ptr() != nullptr;

    // Can set state if wallet is not encrypt or encrypted but amount is known
    auto canSetState = !locked || knowAmount;
    if (!canSetState) {
        LogPrintf("%s : Can not set state\n", __func__);
        return;
    }

    if (HasLelantusMint(id)) {

        // 1. is in wallet then update state
        SetLelantusMintChainState(id, {block, group, idx});
        return;
    }

    if (!locked) {

        // 2. try to recover new mint from pool
        LelantusMintChainState state(block, group, idx);
        if (lelantusWallet.TryRecoverMint(id, state, property, amount.get())) {
            LogPrintf("%s : Found new mint when try to recover\n", __func__);
        }
        return;
    }
}

void Wallet::OnLelantusMintRemoved(
    PropertyId property,
    MintEntryId id)
{
    if (!HasLelantusMint(id)) {
        return;
    }

    SetLelantusMintChainState(id, {});
}

} // namespace elysium
