#ifndef FIRO_ELYSIUM_WALLET_H
#define FIRO_ELYSIUM_WALLET_H

#include "elysium.h"
#include "property.h"
#include "lelantuswallet.h"
#include "sp.h"

#include "../uint256.h"

#include "../wallet/walletdb.h"

#include <boost/optional.hpp>

#include <forward_list>
#include <string>

namespace elysium {

class Wallet
{
public:
    Wallet(const std::string& walletFile);
    virtual ~Wallet();

public:
    void ReloadMasterKey();

public:
    LelantusWallet::MintReservation CreateLelantusMint(PropertyId property, LelantusAmount amount);

    void SetLelantusMintUsedTransaction(const MintEntryId& id, const uint256& tx);

    void ClearAllChainState();

    bool SyncWithChain();

    lelantus::JoinSplit CreateLelantusJoinSplit(
        PropertyId property,
        CAmount amountToSpend,
        uint256 const &metadata,
        std::vector<SpendableCoin> &spendables,
        boost::optional<LelantusWallet::MintReservation> &changeMint,
        LelantusAmount &changeValue);

public:

    template<class OutputIt>
    void ListLelantusMints(OutputIt it)
    {
        lelantusWallet.ListMints(it);
    }

    bool HasLelantusMint(const MintEntryId& id);
    bool HasLelantusMint(const secp_primitives::Scalar &serial);

protected:

	void SetLelantusMintChainState(const MintEntryId &id, const LelantusMintChainState &state);

private:
    void OnLelantusMintAdded(
        PropertyId property,
        MintEntryId id,
        LelantusGroup group,
        LelantusIndex idx,
        boost::optional<LelantusAmount> amount,
        int block);

    void OnLelantusMintRemoved(
        PropertyId property,
        MintEntryId id);

private:
    std::string walletFile;
    std::forward_list<boost::signals2::scoped_connection> eventConnections;
    LelantusWallet lelantusWallet;
};

extern Wallet *wallet;

} // namespace elysium

#endif // FIRO_ELYSIUM_WALLET_H
