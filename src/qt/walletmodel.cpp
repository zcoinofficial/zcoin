// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "walletmodel.h"

#include "addresstablemodel.h"
#include "consensus/validation.h"
#include "guiconstants.h"
#include "guiutil.h"
#include "lelantusmodel.h"
#include "paymentserver.h"
#include "recentrequeststablemodel.h"
#include "transactiontablemodel.h"
#include "pcodemodel.h"

#include "base58.h"
#include "keystore.h"
#include "validation.h"
#include "net.h" // for g_connman
#include "sync.h"
#include "ui_interface.h"
#include "util.h" // for GetBoolArg
#include "wallet/wallet.h"
#include "wallet/walletdb.h" // for BackupWallet
#include "wallet/walletexcept.h"
#include "txmempool.h"
#include "consensus/validation.h"
#include "sigma.h"
#include "sigma/coin.h"
#include "lelantus.h"
#include "bip47/account.h"
#include "bip47/bip47utils.h"
#include "cancelpassworddialog.h"

#include <stdint.h>

#include <QDebug>
#include <QSet>
#include <QTimer>

#include <boost/foreach.hpp>

WalletModel::WalletModel(const PlatformStyle *platformStyle, CWallet *_wallet, OptionsModel *_optionsModel, QObject *parent) :
    QObject(parent), wallet(_wallet), optionsModel(_optionsModel), addressTableModel(0), pcodeAddressTableModel(0),
    lelantusModel(0),
    transactionTableModel(0),
    recentRequestsTableModel(0),
    pcodeModel(0),
    cachedBalance(0), cachedUnconfirmedBalance(0), cachedImmatureBalance(0),
    cachedEncryptionStatus(Unencrypted),
    cachedNumBlocks(0)
{
    fHaveWatchOnly = wallet->HaveWatchOnly();
    fForceCheckBalanceChanged = false;

    addressTableModel = new AddressTableModel(wallet, this);
    pcodeAddressTableModel = new PcodeAddressTableModel(wallet, this);
    lelantusModel = new LelantusModel(platformStyle, wallet, _optionsModel, this);
    transactionTableModel = new TransactionTableModel(platformStyle, wallet, this);
    recentRequestsTableModel = new RecentRequestsTableModel(wallet, this);
    pcodeModel = new PcodeModel(wallet, this);

    // This timer will be fired repeatedly to update the balance
    pollTimer = new QTimer(this);
    connect(pollTimer, SIGNAL(timeout()), this, SLOT(pollBalanceChanged()));
    pollTimer->start(MODEL_UPDATE_DELAY);

    subscribeToCoreSignals();
}

WalletModel::~WalletModel()
{
    unsubscribeFromCoreSignals();
}

CAmount WalletModel::getBalance(const CCoinControl *coinControl, bool fExcludeLocked) const
{
    if (coinControl)
    {
        CAmount nBalance = 0;
        std::vector<COutput> vCoins;
        wallet->AvailableCoins(vCoins, true, coinControl);
        BOOST_FOREACH(const COutput& out, vCoins)
            if(out.fSpendable)
                nBalance += out.tx->tx->vout[out.i].nValue;

        return nBalance;
    }

    return wallet->GetBalance(fExcludeLocked);
}

CAmount WalletModel::getAnonymizableBalance() const
{
    return lelantus::IsLelantusAllowed() ? lelantusModel->getMintableAmount() : 0;
}

CAmount WalletModel::getUnconfirmedBalance() const
{
    return wallet->GetUnconfirmedBalance();
}

CAmount WalletModel::getImmatureBalance() const
{
    return wallet->GetImmatureBalance();
}

bool WalletModel::haveWatchOnly() const
{
    return fHaveWatchOnly;
}

CAmount WalletModel::getWatchBalance() const
{
    return wallet->GetWatchOnlyBalance();
}

CAmount WalletModel::getWatchUnconfirmedBalance() const
{
    return wallet->GetUnconfirmedWatchOnlyBalance();
}

CAmount WalletModel::getWatchImmatureBalance() const
{
    return wallet->GetImmatureWatchOnlyBalance();
}

void WalletModel::updateStatus()
{
    EncryptionStatus newEncryptionStatus = getEncryptionStatus();

    if(cachedEncryptionStatus != newEncryptionStatus)
        Q_EMIT encryptionStatusChanged(newEncryptionStatus);
}

void WalletModel::pollBalanceChanged()
{
    // Get required locks upfront. This avoids the GUI from getting stuck on
    // periodical polls if the core is holding the locks for a longer time -
    // for example, during a wallet rescan.
    TRY_LOCK(cs_main, lockMain);
    if(!lockMain)
        return;
    TRY_LOCK(wallet->cs_wallet, lockWallet);
    if(!lockWallet)
        return;

    if(fForceCheckBalanceChanged || chainActive.Height() != cachedNumBlocks)
    {
        fForceCheckBalanceChanged = false;

        // Balance and number of transactions might have changed
        cachedNumBlocks = chainActive.Height();

        checkBalanceChanged();
        if(transactionTableModel)
            transactionTableModel->updateConfirmations();

        // check sigma
        // support only hd
        if (wallet->zwallet) {
            checkSigmaAmount(false);
        }
    }
}

void WalletModel::updateSigmaCoins(const QString &pubCoin, const QString &isUsed, int status)
{
    if (status == ChangeType::CT_UPDATED) {
        // some coin have been updated to be used
        LOCK2(cs_main, wallet->cs_wallet);
        checkSigmaAmount(true);

    } else if (status == ChangeType::CT_NEW) {
        // new mint
        LOCK2(cs_main, wallet->cs_wallet);
        auto coins = wallet->zwallet->GetTracker().ListMints(true, false, false);

        int block = cachedNumBlocks;
        for (const auto& coin : coins) {
            if (!coin.isUsed) {
                int coinHeight = coin.nHeight;
                if (coinHeight == -1
                    || (coinHeight <= block && coinHeight > block - ZC_MINT_CONFIRMATIONS)) {
                    cachedHavePendingCoin = true;
                }
            }
        }

        if (cachedHavePendingCoin) {
            checkSigmaAmount(true);
        }
    }
}

void WalletModel::checkBalanceChanged()
{
    CAmount newBalance = getBalance();
    CAmount newUnconfirmedBalance = getUnconfirmedBalance();
    CAmount newImmatureBalance = getImmatureBalance();
    CAmount newWatchOnlyBalance = 0;
    CAmount newWatchUnconfBalance = 0;
    CAmount newWatchImmatureBalance = 0;
    CAmount newAnonymizableBalance = getAnonymizableBalance();


    CAmount newPrivateBalance, newUnconfirmedPrivateBalance;
    std::tie(newPrivateBalance, newUnconfirmedPrivateBalance) =
        lelantusModel->getPrivateBalance();

    if (haveWatchOnly())
    {
        newWatchOnlyBalance = getWatchBalance();
        newWatchUnconfBalance = getWatchUnconfirmedBalance();
        newWatchImmatureBalance = getWatchImmatureBalance();
    }

    if(cachedBalance != newBalance
        || cachedUnconfirmedBalance != newUnconfirmedBalance
        || cachedImmatureBalance != newImmatureBalance
        || cachedWatchOnlyBalance != newWatchOnlyBalance
        || cachedWatchUnconfBalance != newWatchUnconfBalance
        || cachedWatchImmatureBalance != newWatchImmatureBalance
        || cachedPrivateBalance != newPrivateBalance
        || cachedUnconfirmedPrivateBalance != newUnconfirmedPrivateBalance
        || cachedAnonymizableBalance != newAnonymizableBalance)
    {
        cachedBalance = newBalance;
        cachedUnconfirmedBalance = newUnconfirmedBalance;
        cachedImmatureBalance = newImmatureBalance;
        cachedWatchOnlyBalance = newWatchOnlyBalance;
        cachedWatchUnconfBalance = newWatchUnconfBalance;
        cachedWatchImmatureBalance = newWatchImmatureBalance;
        cachedPrivateBalance = newPrivateBalance;
        cachedUnconfirmedPrivateBalance = newUnconfirmedPrivateBalance;
        cachedAnonymizableBalance = newAnonymizableBalance;
        Q_EMIT balanceChanged(
            newBalance,
            newUnconfirmedBalance,
            newImmatureBalance,
            newWatchOnlyBalance,
            newWatchUnconfBalance,
            newWatchImmatureBalance,
            newPrivateBalance,
            newUnconfirmedPrivateBalance,
            newAnonymizableBalance);
    }
}

void WalletModel::checkSigmaAmount(bool forced)
{
    auto currentBlock = chainActive.Height();
    if ((cachedHavePendingCoin && currentBlock > lastBlockCheckSigma)
        || currentBlock < lastBlockCheckSigma // reorg
        || forced) {

        auto coins = wallet->zwallet->GetTracker().ListMints(true, false, false);

        std::vector<CMintMeta> spendable, pending;

        std::vector<sigma::PublicCoin> anonimity_set;
        uint256 blockHash;

        cachedHavePendingCoin = false;

        for (const auto& coin : coins) {

            // ignore spent coin
            if (coin.isUsed)
                continue;

            int coinHeight = coin.nHeight;

            if (coinHeight > 0
                && coinHeight + (ZC_MINT_CONFIRMATIONS-1) <= chainActive.Height())  {
                spendable.push_back(coin);
            } else {
                cachedHavePendingCoin = true;
                pending.push_back(coin);
            }
        }

        lastBlockCheckSigma = currentBlock;
        Q_EMIT notifySigmaChanged(spendable, pending);
    }
}

void WalletModel::updateTransaction()
{
    // Balance and number of transactions might have changed
    fForceCheckBalanceChanged = true;
}

void WalletModel::updateAddressBook(const QString &address, const QString &label,
        bool isMine, const QString &purpose, int status)
{
    if(addressTableModel)
        addressTableModel->updateEntry(address, label, isMine, purpose, status);
}

void WalletModel::updateAddressBook(const QString &pubCoin, const QString &isUsed, int status)
{
    if(addressTableModel)
        addressTableModel->updateEntry(pubCoin, isUsed, status);
}

void WalletModel::updateWatchOnlyFlag(bool fHaveWatchonly)
{
    fHaveWatchOnly = fHaveWatchonly;
    Q_EMIT notifyWatchonlyChanged(fHaveWatchonly);
}

bool WalletModel::validateAddress(const QString &address)
{
    CBitcoinAddress addressParsed(address.toStdString());
    return addressParsed.IsValid();
}

WalletModel::SendCoinsReturn WalletModel::prepareTransaction(WalletModelTransaction &transaction, const CCoinControl *coinControl)
{
    CAmount total = 0;
    bool fSubtractFeeFromAmount = false;
    QList<SendCoinsRecipient> recipients = transaction.getRecipients();
    std::vector<CRecipient> vecSend;

    if(recipients.empty())
    {
        return OK;
    }

    QSet<QString> setAddress; // Used to detect duplicates
    int nAddresses = 0;

    // Pre-check input data for validity
    Q_FOREACH(const SendCoinsRecipient &rcp, recipients)
    {
        if (rcp.fSubtractFeeFromAmount)
            fSubtractFeeFromAmount = true;

        if (rcp.paymentRequest.IsInitialized())
        {   // PaymentRequest...
            CAmount subtotal = 0;
            const payments::PaymentDetails& details = rcp.paymentRequest.getDetails();
            for (int i = 0; i < details.outputs_size(); i++)
            {
                const payments::Output& out = details.outputs(i);
                if (out.amount() <= 0) continue;
                subtotal += out.amount();
                const unsigned char* scriptStr = (const unsigned char*)out.script().data();
                CScript scriptPubKey(scriptStr, scriptStr+out.script().size());
                CAmount nAmount = out.amount();
                CRecipient recipient = {scriptPubKey, nAmount, rcp.fSubtractFeeFromAmount};
                vecSend.push_back(recipient);
            }
            if (subtotal <= 0)
            {
                return InvalidAmount;
            }
            total += subtotal;
        }
        else
        {   // User-entered Firo address / amount:
            if(!validateAddress(rcp.address))
            {
                return InvalidAddress;
            }
            if(rcp.amount <= 0)
            {
                return InvalidAmount;
            }
            setAddress.insert(rcp.address);
            ++nAddresses;

            CScript scriptPubKey = GetScriptForDestination(CBitcoinAddress(rcp.address.toStdString()).Get());
            CRecipient recipient = {scriptPubKey, rcp.amount, rcp.fSubtractFeeFromAmount};
            vecSend.push_back(recipient);

            total += rcp.amount;
        }
    }
    if(setAddress.size() != nAddresses)
    {
        return DuplicateAddress;
    }

    CAmount nBalance = getBalance(coinControl);

    if(total > nBalance)
    {
        return AmountExceedsBalance;
    }

    {
        LOCK2(cs_main, wallet->cs_wallet);

        transaction.newPossibleKeyChange(wallet);

        CAmount nFeeRequired = 0;
        int nChangePosRet = -1;
        std::string strFailReason;

        CWalletTx *newTx = transaction.getTransaction();
        CReserveKey *keyChange = transaction.getPossibleKeyChange();
        bool fCreated = wallet->CreateTransaction(vecSend, *newTx, *keyChange, nFeeRequired, nChangePosRet, strFailReason, coinControl);
        transaction.setTransactionFee(nFeeRequired);
        if (fSubtractFeeFromAmount && fCreated)
            transaction.reassignAmounts(nChangePosRet);

        if(!fCreated)
        {
            if(!fSubtractFeeFromAmount && (total + nFeeRequired) > nBalance)
            {
                return SendCoinsReturn(AmountWithFeeExceedsBalance);
            }
            Q_EMIT message(tr("Send Coins"), QString::fromStdString(strFailReason),
                         CClientUIInterface::MSG_ERROR);
            return TransactionCreationFailed;
        }

        // reject absurdly high fee. (This can never happen because the
        // wallet caps the fee at maxTxFee. This merely serves as a
        // belt-and-suspenders check)
        if (nFeeRequired > maxTxFee)
            return AbsurdFee;
    }

    return SendCoinsReturn(OK);
}

WalletModel::SendCoinsReturn WalletModel::prepareJoinSplitTransaction(
    WalletModelTransaction &transaction,
    const CCoinControl *coinControl)
{
    CAmount total = 0;
    bool fSubtractFeeFromAmount = false;
    QList<SendCoinsRecipient> recipients = transaction.getRecipients();
    std::vector<CRecipient> vecSend;

    if(recipients.empty())
    {
        return OK;
    }

    QSet<QString> setAddress; // Used to detect duplicates
    int nAddresses = 0;

    // Pre-check input data for validity
    Q_FOREACH(const SendCoinsRecipient &rcp, recipients)
    {
        if (rcp.fSubtractFeeFromAmount)
            fSubtractFeeFromAmount = true;

        if (rcp.paymentRequest.IsInitialized())
        {
            // PaymentRequest...
            CAmount subtotal = 0;
            const payments::PaymentDetails& details = rcp.paymentRequest.getDetails();
            for (int i = 0; i < details.outputs_size(); i++)
            {
                const payments::Output& out = details.outputs(i);
                if (out.amount() <= 0) continue;
                subtotal += out.amount();
                const unsigned char* scriptStr = (const unsigned char*)out.script().data();
                CScript scriptPubKey(scriptStr, scriptStr+out.script().size());
                CAmount nAmount = out.amount();
                CRecipient recipient = {scriptPubKey, nAmount, rcp.fSubtractFeeFromAmount};
                vecSend.push_back(recipient);
            }
            if (subtotal <= 0)
            {
                return InvalidAmount;
            }
            total += subtotal;
        }
        else
        {
            // User-entered Firo address / amount:
            if(!validateAddress(rcp.address))
            {
                return InvalidAddress;
            }
            if(rcp.amount <= 0)
            {
                return InvalidAmount;
            }
            setAddress.insert(rcp.address);
            ++nAddresses;

            CScript scriptPubKey = GetScriptForDestination(CBitcoinAddress(rcp.address.toStdString()).Get());
            CRecipient recipient = {scriptPubKey, rcp.amount, rcp.fSubtractFeeFromAmount};
            vecSend.push_back(recipient);

            total += rcp.amount;
        }
    }
    if(setAddress.size() != nAddresses)
    {
        return DuplicateAddress;
    }

    CAmount nBalance;
    std::tie(nBalance, std::ignore) = lelantusModel->getPrivateBalance();

    if(total > nBalance)
    {
        return AmountExceedsBalance;
    }

    {
        LOCK2(cs_main, wallet->cs_wallet);

        auto &spendCoins = transaction.getSpendCoins();
        auto &sigmaSpendCoins = transaction.getSigmaSpendCoins();
        auto &mintCoins = transaction.getMintCoins();

        CAmount feeRequired = 0;
        std::string strFailReason;

        CWalletTx *newTx = transaction.getTransaction();
        try {
            *newTx = wallet->CreateLelantusJoinSplitTransaction(vecSend, feeRequired, {}, spendCoins, sigmaSpendCoins, mintCoins, coinControl);
        } catch (InsufficientFunds const&) {
            transaction.setTransactionFee(feeRequired);
            if (!fSubtractFeeFromAmount && (total + feeRequired) > nBalance) {
                return SendCoinsReturn(AmountWithFeeExceedsBalance);
            }
            return SendCoinsReturn(AmountExceedsBalance);
        } catch (std::runtime_error const &e) {
            Q_EMIT message(
                tr("Send Coins"),
                QString::fromStdString(e.what()),
                CClientUIInterface::MSG_ERROR);

            return TransactionCreationFailed;
        } catch (std::invalid_argument const &e) {
            Q_EMIT message(
                    tr("Send Coins"),
                    QString::fromStdString(e.what()),
                    CClientUIInterface::MSG_ERROR);

            return TransactionCreationFailed;
        }

        // reject absurdly high fee. (This can never happen because the
        // wallet caps the fee at maxTxFee. This merely serves as a
        // belt-and-suspenders check)
        if (feeRequired > maxTxFee) {
            return AbsurdFee;
        }

        int changePos = -1;
        if (!mintCoins.empty()) {
            for (changePos = 0; changePos < newTx->tx->vout.size(); changePos++) {
                if (newTx->tx->vout[changePos].scriptPubKey.IsLelantusJMint()) {
                    break;
                }
            }

            changePos = changePos >= newTx->tx->vout.size() ? -1 : changePos;
        }

        transaction.setTransactionFee(feeRequired);
        transaction.reassignAmounts(changePos);
    }

    return SendCoinsReturn(OK);
}

WalletModel::SendCoinsReturn WalletModel::prepareMintTransactions(
    CAmount amount,
    std::vector<WalletModelTransaction> &transactions,
    std::list<CReserveKey> &reserveKeys,
    std::vector<CHDMint> &mints,
    const CCoinControl *coinControl)
{
    if (amount <= 0) {
        return InvalidAmount;
    }

    auto balance = getBalance(coinControl);
    if (amount > balance) {
        return AmountExceedsBalance;
    }

    std::vector<std::pair<CWalletTx, CAmount>> wtxAndFees;
    CAmount allFee = 0;
    int changePos = -1;
    std::string failReason;

    bool success = false;
    try {
        success = wallet->CreateLelantusMintTransactions(
                amount, wtxAndFees, allFee, mints, reserveKeys, changePos, failReason, coinControl);

    } catch (std::runtime_error const &e) {
        return SendCoinsReturn(TransactionCreationFailed, e.what());
    }


    transactions.clear();
    transactions.reserve(wtxAndFees.size());
    for (auto &wtxAndFee : wtxAndFees) {
        auto &wtx = wtxAndFee.first;
        auto fee = wtxAndFee.second;

        QList<SendCoinsRecipient> recipients;

        int changePos = -1;
        for (size_t i = 0; i != wtx.tx->vout.size(); i++) {
            if (wtx.tx->vout[i].scriptPubKey.IsMint()) {
                SendCoinsRecipient r;
                r.amount = wtx.tx->vout[i].nValue;
                recipients.push_back(r);
            } else {
                changePos = i;
            }
        }

        transactions.emplace_back(recipients);
        auto &tx = transactions.back();

        *tx.getTransaction() = wtx;
        tx.setTransactionFee(fee);

        tx.reassignAmounts(changePos);
    }

    if (!success) {
        if (amount + allFee > balance) {
            return SendCoinsReturn(AmountWithFeeExceedsBalance);
        }

        Q_EMIT message(
            tr("Coin Anonymizing"),
            QString::fromStdString(failReason),
            CClientUIInterface::MSG_ERROR);

        return TransactionCommitFailed;
    }

    if (allFee > maxTxFee) {
        return WalletModel::AbsurdFee;
    }

    return SendCoinsReturn(OK);
}

WalletModel::SendCoinsReturn WalletModel::sendCoins(WalletModelTransaction &transaction)
{
    QByteArray transaction_array; /* store serialized transaction */

    {
        LOCK2(cs_main, wallet->cs_wallet);
        CWalletTx *newTx = transaction.getTransaction();

        Q_FOREACH(const SendCoinsRecipient &rcp, transaction.getRecipients())
        {
            if (rcp.paymentRequest.IsInitialized())
            {
                // Make sure any payment requests involved are still valid.
                if (PaymentServer::verifyExpired(rcp.paymentRequest.getDetails())) {
                    return PaymentRequestExpired;
                }

                // Store PaymentRequests in wtx.vOrderForm in wallet.
                std::string key("PaymentRequest");
                std::string value;
                rcp.paymentRequest.SerializeToString(&value);
                newTx->vOrderForm.push_back(make_pair(key, value));
            }
            else if (!rcp.message.isEmpty()) // Message from normal firo:URI (firo:123...?message=example)
                newTx->vOrderForm.push_back(make_pair("Message", rcp.message.toStdString()));
        }

        CReserveKey *keyChange = transaction.getPossibleKeyChange();
        CValidationState state;
        if(!wallet->CommitTransaction(*newTx, *keyChange, g_connman.get(), state))
            return SendCoinsReturn(TransactionCommitFailed, QString::fromStdString(state.GetRejectReason()));

        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << *newTx->tx;
        transaction_array.append(&(ssTx[0]), ssTx.size());
    }

    // Add addresses / update labels that we've sent to to the address book,
    // and emit coinsSent signal for each recipient
    Q_FOREACH(const SendCoinsRecipient &rcp, transaction.getRecipients())
    {
        // Don't touch the address book when we have a payment request
        if (!rcp.paymentRequest.IsInitialized())
        {
            std::string strAddress = rcp.address.toStdString();
            CTxDestination dest = CBitcoinAddress(strAddress).Get();
            std::string strLabel = rcp.label.toStdString();
            {
                LOCK(wallet->cs_wallet);

                std::map<CTxDestination, CAddressBookData>::iterator mi = wallet->mapAddressBook.find(dest);

                // Check if we have a new address or an updated label
                if (mi == wallet->mapAddressBook.end())
                {
                    wallet->SetAddressBook(dest, strLabel, "send");
                }
                else if (mi->second.name != strLabel)
                {
                    wallet->SetAddressBook(dest, strLabel, ""); // "" means don't change purpose
                }
            }
        }
        Q_EMIT coinsSent(wallet, rcp, transaction_array);
    }
    checkBalanceChanged(); // update balance immediately, otherwise there could be a short noticeable delay until pollBalanceChanged hits

    return SendCoinsReturn(OK);
}

WalletModel::SendCoinsReturn WalletModel::sendPrivateCoins(WalletModelTransaction &transaction)
{
    QByteArray transaction_array; /* store serialized transaction */

    {
        LOCK2(cs_main, wallet->cs_wallet);
        CWalletTx *newTx = transaction.getTransaction();

        Q_FOREACH(const SendCoinsRecipient &rcp, transaction.getRecipients())
        {
            if (rcp.paymentRequest.IsInitialized())
            {
                // Make sure any payment requests involved are still valid.
                if (PaymentServer::verifyExpired(rcp.paymentRequest.getDetails())) {
                    return PaymentRequestExpired;
                }

                // Store PaymentRequests in wtx.vOrderForm in wallet.
                std::string key("PaymentRequest");
                std::string value;
                rcp.paymentRequest.SerializeToString(&value);
                newTx->vOrderForm.push_back(make_pair(key, value));
            }
            else if (!rcp.message.isEmpty()) // Message from normal firo:URI (firo:123...?message=example)
                newTx->vOrderForm.push_back(make_pair("Message", rcp.message.toStdString()));
        }

        try {
            if (!wallet->CommitLelantusTransaction(*newTx, transaction.getSpendCoins(), transaction.getSigmaSpendCoins(), transaction.getMintCoins()))
                return SendCoinsReturn(TransactionCommitFailed);
        } catch (std::runtime_error const &e) {
            return SendCoinsReturn(TransactionCommitFailed, e.what());
        }

        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << *newTx->tx;
        transaction_array.append(&(ssTx[0]), ssTx.size());
    }

    // Add addresses / update labels that we've sent to to the address book,
    // and emit coinsSent signal for each recipient
    Q_FOREACH(const SendCoinsRecipient &rcp, transaction.getRecipients())
    {
        // Don't touch the address book when we have a payment request
        if (!rcp.paymentRequest.IsInitialized())
        {
            std::string strAddress = rcp.address.toStdString();
            CTxDestination dest = CBitcoinAddress(strAddress).Get();
            std::string strLabel = rcp.label.toStdString();
            {
                LOCK(wallet->cs_wallet);

                std::map<CTxDestination, CAddressBookData>::iterator mi = wallet->mapAddressBook.find(dest);

                // Check if we have a new address or an updated label
                if (mi == wallet->mapAddressBook.end())
                {
                    wallet->SetAddressBook(dest, strLabel, "send");
                }
                else if (mi->second.name != strLabel)
                {
                    wallet->SetAddressBook(dest, strLabel, ""); // "" means don't change purpose
                }
            }
        }
        Q_EMIT coinsSent(wallet, rcp, transaction_array);
    }
    checkBalanceChanged(); // update balance immediately, otherwise there could be a short noticeable delay until pollBalanceChanged hits

    return SendCoinsReturn(OK);
}

WalletModel::SendCoinsReturn WalletModel::sendAnonymizingCoins(
    std::vector<WalletModelTransaction> &transactions,
    std::list<CReserveKey> &reservekeys,
    std::vector<CHDMint> &mints)
{
    auto reservekey = reservekeys.begin();
    CWalletDB db(wallet->strWalletFile);

    for (size_t i = 0; i != transactions.size(); i++) {

        auto tx = transactions[i].getTransaction();

        CValidationState state;
        if (!wallet->CommitTransaction(*tx, *reservekey++, g_connman.get(), state)) {
            return TransactionCommitFailed;
        }

        auto &mintTmp = mints[i];
        mintTmp.SetTxHash(tx->GetHash());
        {
            wallet->zwallet->GetTracker().AddLelantus(db, mintTmp, true);
        }
    }
    wallet->zwallet->UpdateCountDB(db);
    return SendCoinsReturn(OK);
}

OptionsModel *WalletModel::getOptionsModel()
{
    return optionsModel;
}

AddressTableModel *WalletModel::getAddressTableModel()
{
    return addressTableModel;
}

PcodeAddressTableModel *WalletModel::getPcodeAddressTableModel()
{
    return pcodeAddressTableModel;
}

LelantusModel *WalletModel::getLelantusModel()
{
    return lelantusModel;
}

TransactionTableModel *WalletModel::getTransactionTableModel()
{
    return transactionTableModel;
}

RecentRequestsTableModel *WalletModel::getRecentRequestsTableModel()
{
    return recentRequestsTableModel;
}

PcodeModel *WalletModel::getPcodeModel()
{
    return pcodeModel;
}

WalletModel::EncryptionStatus WalletModel::getEncryptionStatus() const
{
    if(!wallet->IsCrypted())
    {
        return Unencrypted;
    }
    else if(wallet->IsLocked())
    {
        return Locked;
    }
    else
    {
        return Unlocked;
    }
}

bool WalletModel::setWalletEncrypted(bool encrypted, const SecureString &passphrase)
{
    if(encrypted)
    {
        // Encrypt
        return wallet->EncryptWallet(passphrase);
    }
    else
    {
        // Decrypt -- TODO; not supported yet
        return false;
    }
}

bool WalletModel::setWalletLocked(bool locked, const SecureString &passPhrase)
{
    if(locked)
    {
        // Lock
        return wallet->Lock();
    }
    else
    {
        // Unlock
        return wallet->Unlock(passPhrase);
    }
}

bool WalletModel::lockWallet()
{
    return wallet->Lock();
}

void WalletModel::lockWalletDelayed(int seconds)
{
    QTimer::singleShot(seconds * 1000, this, SLOT(lockWallet()));
}

bool WalletModel::changePassphrase(const SecureString &oldPass, const SecureString &newPass)
{
    bool retval;
    {
        LOCK(wallet->cs_wallet);
        wallet->Lock(); // Make sure wallet is locked before attempting pass change
        retval = wallet->ChangeWalletPassphrase(oldPass, newPass);
    }
    return retval;
}

bool WalletModel::backupWallet(const QString &filename)
{
    return wallet->BackupWallet(filename.toLocal8Bit().data());
}

// Handlers for core signals
static void NotifyKeyStoreStatusChanged(WalletModel *walletmodel, CCryptoKeyStore *wallet)
{
    qDebug() << "NotifyKeyStoreStatusChanged";
    QMetaObject::invokeMethod(walletmodel, "updateStatus", Qt::QueuedConnection);
}

static void NotifyAddressBookChanged(WalletModel *walletmodel, CWallet *wallet,
        const CTxDestination &address, const std::string &label, bool isMine,
        const std::string &purpose, ChangeType status)
{
    QString strAddress = QString::fromStdString(CBitcoinAddress(address).ToString());
    QString strLabel = QString::fromStdString(label);
    QString strPurpose = QString::fromStdString(purpose);

    qDebug() << "NotifyAddressBookChanged: " + strAddress + " " + strLabel + " isMine=" + QString::number(isMine) + " purpose=" + strPurpose + " status=" + QString::number(status);
    QMetaObject::invokeMethod(walletmodel, "updateAddressBook", Qt::QueuedConnection,
                              Q_ARG(QString, strAddress),
                              Q_ARG(QString, strLabel),
                              Q_ARG(bool, isMine),
                              Q_ARG(QString, strPurpose),
                              Q_ARG(int, status));
}

static void NotifyZerocoinChanged(WalletModel *walletmodel, CWallet *wallet, const std::string &pubCoin, const std::string &isUsed, ChangeType status)
{
    qDebug() << "NotifyZerocoinChanged:" + QString::fromStdString(pubCoin) + " " + QString::fromStdString(isUsed) + " status=" + QString::number(status);
    QMetaObject::invokeMethod(walletmodel, "updateAddressBook", Qt::QueuedConnection,
                              Q_ARG(QString, QString::fromStdString(pubCoin)),
                              Q_ARG(QString, QString::fromStdString(isUsed)),
                              Q_ARG(int, status));

    // disable sigma
    if (wallet->zwallet) {
        QMetaObject::invokeMethod(walletmodel, "updateSigmaCoins", Qt::QueuedConnection,
                              Q_ARG(QString, QString::fromStdString(pubCoin)),
                              Q_ARG(QString, QString::fromStdString(isUsed)),
                              Q_ARG(int, status));
    }
}

static void NotifyTransactionChanged(WalletModel *walletmodel, CWallet *wallet, const uint256 &hash, ChangeType status)
{
    Q_UNUSED(wallet);
    Q_UNUSED(hash);
    Q_UNUSED(status);
    QMetaObject::invokeMethod(walletmodel, "updateTransaction", Qt::QueuedConnection);
}

static void ShowProgress(WalletModel *walletmodel, const std::string &title, int nProgress)
{
    // emits signal "showProgress"
    QMetaObject::invokeMethod(walletmodel, "showProgress", Qt::QueuedConnection,
                              Q_ARG(QString, QString::fromStdString(title)),
                              Q_ARG(int, nProgress));
}

static void NotifyWatchonlyChanged(WalletModel *walletmodel, bool fHaveWatchonly)
{
    QMetaObject::invokeMethod(walletmodel, "updateWatchOnlyFlag", Qt::QueuedConnection,
                              Q_ARG(bool, fHaveWatchonly));
}

static void NotifyBip47KeysChanged(WalletModel *walletmodel, int receiverAccountNum, CBlockIndex * pBlockIndex)
{
    QMetaObject::invokeMethod(walletmodel, "handleBip47Keys", Qt::QueuedConnection,
                            Q_ARG(int, receiverAccountNum),
                            Q_ARG(void *, pBlockIndex)
                        );
}

void WalletModel::subscribeToCoreSignals()
{
    // Connect signals to wallet
    wallet->NotifyStatusChanged.connect(boost::bind(&NotifyKeyStoreStatusChanged, this, _1));
    wallet->NotifyAddressBookChanged.connect(boost::bind(NotifyAddressBookChanged, this, _1, _2, _3, _4, _5, _6));
    wallet->NotifyTransactionChanged.connect(boost::bind(NotifyTransactionChanged, this, _1, _2, _3));
    wallet->ShowProgress.connect(boost::bind(ShowProgress, this, _1, _2));
    wallet->NotifyWatchonlyChanged.connect(boost::bind(NotifyWatchonlyChanged, this, _1));
    wallet->NotifyZerocoinChanged.connect(boost::bind(NotifyZerocoinChanged, this, _1, _2, _3, _4));
    wallet->NotifyBip47KeysChanged.connect(boost::bind(NotifyBip47KeysChanged, this, _1, _2));

}

void WalletModel::unsubscribeFromCoreSignals()
{
    // Disconnect signals from wallet
    wallet->NotifyStatusChanged.disconnect(boost::bind(&NotifyKeyStoreStatusChanged, this, _1));
    wallet->NotifyAddressBookChanged.disconnect(boost::bind(NotifyAddressBookChanged, this, _1, _2, _3, _4, _5, _6));
    wallet->NotifyTransactionChanged.disconnect(boost::bind(NotifyTransactionChanged, this, _1, _2, _3));
    wallet->ShowProgress.disconnect(boost::bind(ShowProgress, this, _1, _2));
    wallet->NotifyWatchonlyChanged.disconnect(boost::bind(NotifyWatchonlyChanged, this, _1));
    wallet->NotifyZerocoinChanged.disconnect(boost::bind(NotifyZerocoinChanged, this, _1, _2, _3, _4));
    wallet->NotifyBip47KeysChanged.disconnect(boost::bind(NotifyBip47KeysChanged, this, _1, _2));
}

// WalletModel::UnlockContext implementation
WalletModel::UnlockContext WalletModel::requestUnlock(const QString & info)
{
    bool was_locked = getEncryptionStatus() == Locked;
    if(was_locked)
    {
        // Request UI to unlock wallet
        Q_EMIT requireUnlock(info);
    }
    // If wallet is still locked, unlock was failed or cancelled, mark context as invalid
    bool valid = getEncryptionStatus() != Locked;

    return UnlockContext(this, valid, was_locked);
}

WalletModel::UnlockContext::UnlockContext(WalletModel *_wallet, bool _valid, bool _relock):
        wallet(_wallet),
        valid(_valid),
        relock(_relock),
        delay(0)
{
}

WalletModel::UnlockContext::~UnlockContext()
{
    if(valid && relock)
    {
        if(delay == 0)
        {
            wallet->setWalletLocked(true);
        }
        else
        {
            wallet->lockWalletDelayed(delay);
        }
    }
}

void WalletModel::UnlockContext::delayRelock(int seconds)
{
    delay = seconds;
}

void WalletModel::UnlockContext::CopyFrom(const UnlockContext& rhs)
{
    // Transfer context; old object no longer relocks wallet
    wallet = rhs.wallet;
    valid = rhs.valid;
    relock = rhs.relock;
    delay = rhs.delay;
    rhs.relock = false;
}

bool WalletModel::IsSpendable(const CTxDestination& dest) const
{
    return IsMine(*wallet, dest) & ISMINE_SPENDABLE;
}

bool WalletModel::IsSpendable(const CScript& script) const
{
    return IsMine(*wallet, script) & ISMINE_SPENDABLE;
}

bool WalletModel::getPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const
{
    return wallet->GetPubKey(address, vchPubKeyOut);
}

bool WalletModel::havePrivKey(const CKeyID &address) const
{
    return wallet->HaveKey(address);
}

bool WalletModel::getPrivKey(const CKeyID &address, CKey& vchPrivKeyOut) const
{
    return wallet->GetKey(address, vchPrivKeyOut);
}

// returns a list of COutputs from COutPoints
void WalletModel::getOutputs(const std::vector<COutPoint>& vOutpoints, std::vector<COutput>& vOutputs, boost::optional<bool> fMintTabSelected)
{
    LOCK2(cs_main, wallet->cs_wallet);
    BOOST_FOREACH(const COutPoint& outpoint, vOutpoints)
    {
        if (!wallet->mapWallet.count(outpoint.hash)) continue;
        int nDepth = wallet->mapWallet[outpoint.hash].GetDepthInMainChain();
        if (nDepth < 0) continue;
        if (fMintTabSelected != boost::none) {
            if(wallet->mapWallet[outpoint.hash].tx->vout[outpoint.n].scriptPubKey.IsSigmaMint()) {
                if (fMintTabSelected.get()) // only allow mint outputs on the "Spend" tab
                    continue;
            }
            else {
                if (!fMintTabSelected.get())
                    continue; // only allow normal outputs on the "Mint" tab
            }
        }
        COutput out(&wallet->mapWallet[outpoint.hash], outpoint.n, nDepth, true, true);
        vOutputs.push_back(out);
    }
}

bool WalletModel::isSpent(const COutPoint& outpoint) const
{
    LOCK2(cs_main, wallet->cs_wallet);
    return wallet->IsSpent(outpoint.hash, outpoint.n);
}

// AvailableCoins + LockedCoins grouped by wallet address (put change in one group with wallet address)
void WalletModel::listCoins(std::map<QString, std::vector<COutput> >& mapCoins, CoinType nCoinType) const
{
    std::vector<COutput> vCoins;
    CCoinControl coinControl;
    coinControl.nCoinType = nCoinType;
    wallet->AvailableCoins(vCoins, true, &coinControl, false);

    LOCK2(cs_main, wallet->cs_wallet); // ListLockedCoins, mapWallet
    std::vector<COutPoint> vLockedCoins;
    wallet->ListLockedCoins(vLockedCoins);

    // add locked coins
    BOOST_FOREACH(const COutPoint& outpoint, vLockedCoins)
    {
        if (!wallet->mapWallet.count(outpoint.hash)) continue;
        int nDepth = wallet->mapWallet[outpoint.hash].GetDepthInMainChain();
        if (nDepth < 0) continue;
        COutput out(&wallet->mapWallet[outpoint.hash], outpoint.n, nDepth, true, true);

        auto const &vout = out.tx->tx->vout[out.i];
        bool isMint = vout.scriptPubKey.IsMint();

        if(nCoinType == CoinType::ALL_COINS){
            // We are now taking ALL_COINS to mean everything sans mints
            if (isMint) continue;
        } else if(nCoinType == CoinType::ONLY_MINTS){
            // Do not consider anything other than mints
            if (!isMint) continue;
        }

        if (outpoint.n < out.tx->tx->vout.size() && wallet->IsMine(out.tx->tx->vout[outpoint.n]) == ISMINE_SPENDABLE)
            vCoins.push_back(out);
    }

    BOOST_FOREACH(const COutput& out, vCoins)
    {
        COutput cout = out;

        while (wallet->IsChange(cout.tx->GetHash(), cout.tx->tx->vout[cout.i]) && cout.tx->tx->vin.size() > 0 && wallet->IsMine(cout.tx->tx->vin[0], *cout.tx->tx))
        {
            if (!wallet->mapWallet.count(cout.tx->tx->vin[0].prevout.hash)) break;
            cout = COutput(&wallet->mapWallet[cout.tx->tx->vin[0].prevout.hash], cout.tx->tx->vin[0].prevout.n, 0, true, true);
        }

        CTxDestination address;
        auto const &vout = cout.tx->tx->vout[cout.i];
        if (vout.scriptPubKey.IsMint()) {

            mapCoins[QString::fromStdString("(mint)")].push_back(out);
            continue;
        }
        else if(!out.fSpendable || !ExtractDestination(cout.tx->tx->vout[cout.i].scriptPubKey, address)){
            continue;
        }

        mapCoins[QString::fromStdString(CBitcoinAddress(address).ToString())].push_back(out);
    }
}

bool WalletModel::isLockedCoin(uint256 hash, unsigned int n) const
{
    LOCK2(cs_main, wallet->cs_wallet);
    return wallet->IsLockedCoin(hash, n);
}

void WalletModel::lockCoin(COutPoint& output)
{
    LOCK2(cs_main, wallet->cs_wallet);
    wallet->LockCoin(output);
    Q_EMIT updateMintable();
}

void WalletModel::unlockCoin(COutPoint& output)
{
    LOCK2(cs_main, wallet->cs_wallet);
    wallet->UnlockCoin(output);
    Q_EMIT updateMintable();
}

void WalletModel::listLockedCoins(std::vector<COutPoint>& vOutpts)
{
    LOCK2(cs_main, wallet->cs_wallet);
    wallet->ListLockedCoins(vOutpts);
}

void WalletModel::listProTxCoins(std::vector<COutPoint>& vOutpts)
{
    LOCK2(cs_main, wallet->cs_wallet);
    wallet->ListProTxCoins(vOutpts);
}

bool WalletModel::hasMasternode()
{
    LOCK2(cs_main, wallet->cs_wallet);
    return wallet->HasMasternode();
}

void WalletModel::loadReceiveRequests(std::vector<std::string>& vReceiveRequests)
{
    LOCK(wallet->cs_wallet);
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, CAddressBookData)& item, wallet->mapAddressBook)
        BOOST_FOREACH(const PAIRTYPE(std::string, std::string)& item2, item.second.destdata)
            if (item2.first.size() > 2 && item2.first.substr(0,2) == "rr") // receive request
                vReceiveRequests.push_back(item2.second);
}

bool WalletModel::saveReceiveRequest(const std::string &sAddress, const int64_t nId, const std::string &sRequest)
{
    CTxDestination dest = CBitcoinAddress(sAddress).Get();

    std::stringstream ss;
    ss << nId;
    std::string key = "rr" + ss.str(); // "rr" prefix = "receive request" in destdata

    LOCK(wallet->cs_wallet);
    if (sRequest.empty())
        return wallet->EraseDestData(dest, key);
    else
        return wallet->AddDestData(dest, key, sRequest);
}

bool WalletModel::transactionCanBeAbandoned(uint256 hash) const
{
    LOCK2(cs_main, wallet->cs_wallet);
    const CWalletTx *wtx = wallet->GetWalletTx(hash);
    if (!wtx || wtx->isAbandoned() || wtx->GetDepthInMainChain() > 0 || wtx->InMempool() || wtx->InStempool())
        return false;
    return true;
}

bool WalletModel::abandonTransaction(uint256 hash) const
{
    LOCK2(cs_main, wallet->cs_wallet);
    return wallet->AbandonTransaction(hash);
}

bool WalletModel::transactionCanBeRebroadcast(uint256 hash) const
{
    LOCK2(cs_main, wallet->cs_wallet);
    const CWalletTx *wtx = wallet->GetWalletTx(hash);
    if (!wtx || wtx->isAbandoned() || wtx->GetDepthInMainChain() > 0)
        return false;
    return wtx->GetRequestCount() <= 0;
}

bool WalletModel::rebroadcastTransaction(uint256 hash, CValidationState &state)
{
    LOCK2(cs_main, wallet->cs_wallet);
    CWalletTx *wtx = const_cast<CWalletTx*>(wallet->GetWalletTx(hash));

    if (!wtx || wtx->isAbandoned() || wtx->GetDepthInMainChain() > 0)
        return false;
    if (wtx->GetRequestCount() > 0)
        return false;

    CCoinsViewCache &view = *pcoinsTip;
    bool fHaveChain = false;
    for (size_t i=0; i<wtx->tx->vout.size() && !fHaveChain; i++) {
        if (view.HaveCoin(COutPoint(hash, i)))
            fHaveChain = true;
    }

    bool fHaveMempool = mempool.exists(hash);

    if (!fHaveMempool && !fHaveChain) {
        // push to local node and sync with wallets
        bool fMissingInputs;
        if (!AcceptToMemoryPool(mempool, state, wtx->tx, false, &fMissingInputs, NULL, true, false, maxTxFee))
            return false;
    } else if (fHaveChain) {
        return false;
    }

    g_connman->RelayTransaction(*wtx->tx);
    return true;
}

// Sigma
WalletModel::SendCoinsReturn WalletModel::prepareSigmaSpendTransaction(
    WalletModelTransaction &transaction,
    std::vector<CSigmaEntry> &selectedCoins,
    std::vector<CHDMint> &changes,
    bool& fChangeAddedToFee,
    const CCoinControl *coinControl)
{
    QList<SendCoinsRecipient> recipients = transaction.getRecipients();
    std::vector<CRecipient> sendRecipients;

    if (recipients.empty()) {
        return OK;
    }

    QSet<QString> addresses; // Used to detect duplicates

    for (const auto& rcp : recipients) {
        if (!validateAddress(rcp.address)) {
            return InvalidAmount;
        }
        addresses.insert(rcp.address);

        CScript scriptPubKey = GetScriptForDestination(CBitcoinAddress(rcp.address.toStdString()).Get());
        CRecipient recipient = {scriptPubKey, rcp.amount, rcp.fSubtractFeeFromAmount};
        sendRecipients.push_back(recipient);
    }

    if (addresses.size() != recipients.size()) {
        return DuplicateAddress;
    }

    // create transaction
    CAmount fee;

    CWalletTx *newTx = transaction.getTransaction();
    try {
        *newTx = wallet->CreateSigmaSpendTransaction(sendRecipients, fee, selectedCoins, changes, fChangeAddedToFee, coinControl);
    } catch (const InsufficientFunds& err) {
        return AmountExceedsBalance;
    } catch (const std::runtime_error& err) {
        if (_("Can not choose coins within limit.") == err.what())
            return ExceedLimit;
        if (_("Sigma is disabled at this period.") == err.what())
            return SigmaDisabled;
        throw err;
    } catch (const std::invalid_argument& err) {
        return ExceedLimit;
    }

    transaction.setTransactionFee(fee);

    return SendCoinsReturn(OK);
}

WalletModel::SendCoinsReturn WalletModel::sendSigma(WalletModelTransaction &transaction,
    std::vector<CSigmaEntry>& coins, std::vector<CHDMint>& changes)
{
    QByteArray transaction_array; /* store serialized transaction */

    {
        LOCK2(cs_main, wallet->cs_wallet);
        CWalletTx *newTx = transaction.getTransaction();

        for (const auto& rcp : transaction.getRecipients()) {
            if (rcp.paymentRequest.IsInitialized())
            {
                // Make sure any payment requests involved are still valid.
                if (PaymentServer::verifyExpired(rcp.paymentRequest.getDetails())) {
                    return PaymentRequestExpired;
                }

                // Store PaymentRequests in wtx.vOrderForm in wallet.
                std::string key("PaymentRequest");
                std::string value;
                rcp.paymentRequest.SerializeToString(&value);
                newTx->vOrderForm.push_back(std::make_pair(key, value));
            } else if (!rcp.message.isEmpty()) {
                // Message from normal firo:URI (firo:123...?message=example)
                newTx->vOrderForm.push_back(std::make_pair("Message", rcp.message.toStdString()));
            }
        }

        try {
            wallet->CommitSigmaTransaction(*newTx, coins, changes);
        } catch (...) {
            return TransactionCommitFailed;
        }

        CTransactionRef t = newTx->tx;
        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << t;
        transaction_array.append(&(ssTx[0]), ssTx.size());
    }

    // Add addresses / update labels that we've sent to to the address book,
    // and emit coinsSent signal for each recipient
    for (const auto& rcp : transaction.getRecipients()) {
        // Don't touch the address book when we have a payment request
        if (!rcp.paymentRequest.IsInitialized()) {
            std::string address = rcp.address.toStdString();
            CTxDestination dest = CBitcoinAddress(address).Get();
            std::string label = rcp.label.toStdString();
            {
                LOCK(wallet->cs_wallet);

                auto mi = wallet->mapAddressBook.find(dest);

                // Check if we have a new address or an updated label
                if (mi == wallet->mapAddressBook.end()) {
                    wallet->SetAddressBook(dest, label, "send");
                }
                else if (mi->second.name != label) {
                    wallet->SetAddressBook(dest, label, ""); // "" means don't change purpose
                }
            }
        }
        Q_EMIT coinsSent(wallet, rcp, transaction_array);
    }
    checkBalanceChanged();

    return SendCoinsReturn(OK);
}

void WalletModel::sigmaMint(const CAmount& n, const CCoinControl *coinControl)
{
    std::vector<sigma::CoinDenomination> denominations;
    sigma::GetAllDenoms(denominations);

    std::vector<sigma::CoinDenomination> mints;
    if (CWallet::SelectMintCoinsForAmount(n, denominations, mints) != n) {
        throw std::runtime_error("Problem with coin selection.\n");
    }

    std::vector<sigma::PrivateCoin> privCoins;

    const sigma::Params* sigmaParams = sigma::Params::get_default();
    std::transform(mints.begin(), mints.end(), std::back_inserter(privCoins),
        [sigmaParams](const sigma::CoinDenomination& denom) -> sigma::PrivateCoin {
            return sigma::PrivateCoin(sigmaParams, denom);
        });

    std::vector<CHDMint> vDMints;
    auto recipients = CWallet::CreateSigmaMintRecipients(privCoins, vDMints);

    CWalletTx wtx;
    std::string strError = pwalletMain->MintAndStoreSigma(recipients, privCoins, vDMints, wtx, false, coinControl);

    if (strError != "") {
        throw std::range_error(strError);
    }
}

std::vector<CSigmaEntry> WalletModel::GetUnsafeCoins(const CCoinControl* coinControl)
{
    auto allCoins = wallet->GetAvailableCoins(coinControl, true);
    auto spendableCoins = wallet->GetAvailableCoins(coinControl);
    std::vector<CSigmaEntry> unsafeCoins;
    for (auto& coin : allCoins) {
        if (spendableCoins.end() == std::find_if(spendableCoins.begin(), spendableCoins.end(),
            [coin](const CSigmaEntry& spendalbe) {
                return coin.value == spendalbe.value;
            }
        )) {
            unsafeCoins.push_back(coin);
        }
    }
    return unsafeCoins;
}

CAmount WalletModel::GetJMintCredit(const CTxOut& txout) const {
    return wallet->GetCredit(txout, ISMINE_SPENDABLE);
}

bool WalletModel::isWalletEnabled()
{
   return !GetBoolArg("-disablewallet", DEFAULT_DISABLE_WALLET);
}

bool WalletModel::hdEnabled() const
{
    return wallet->IsHDEnabled();
}

int WalletModel::getDefaultConfirmTarget() const
{
    return nTxConfirmTarget;
}

void WalletModel::handleBip47Keys(int receiverAccountNum, void * pBlockIndex_)
{
    //These statics are to display only one password prompt at a time and block consequent prompts
    static std::mutex singlePasswordPromptMutex, queueMutex;
    static std::deque<bip47::CAccountReceiver const *> receiverAccountNumQueue;

    if(!pBlockIndex_)
        return;
    CBlockIndex * pBlockIndex = reinterpret_cast<CBlockIndex *>(pBlockIndex_);

    if (wallet->GetBip47Wallet()) {
        bip47::CAccountReceiver const * acc = wallet->GetBip47Wallet()->getReceivingAccount(uint32_t(receiverAccountNum));
        if (!acc)
            return;

        std::unique_lock<std::mutex> _(singlePasswordPromptMutex, std::try_to_lock);
        if (!_.owns_lock()) {
            std::lock_guard<std::mutex> _(queueMutex);
            receiverAccountNumQueue.push_back(acc);
            return;
        }

        static QString const unlockText = tr("You have received a payment to a RAP address, please unlock your wallet to receive.");
        UnlockContext ctx(requestUnlock(unlockText));
        while(!ctx.isValid()) {
            CancelPasswordDialog msgDialog(
                    tr("RAP address payment"),
                    tr("RAP addresses require you to unlock your wallet every time a payment to it is received."),
                    3
            );
            msgDialog.setInformativeText(tr("If you do not enter your password now, you will need to rescan your wallet to receive your FIRO.<br/><br/>Re-enter your password?"));
            if(msgDialog.exec() == QMessageBox::Cancel)
                return;
            ctx = requestUnlock(unlockText);
        }
        ctx.delayRelock(60);
        bip47::utils::AddReceiverSecretAddresses(*acc, *wallet);
        {
            std::lock_guard<std::mutex> _(queueMutex);
            for(std::deque<bip47::CAccountReceiver const *>::iterator iter = receiverAccountNumQueue.begin(); iter != receiverAccountNumQueue.end(); ++iter)
                bip47::utils::AddReceiverSecretAddresses(**iter, *wallet);
            receiverAccountNumQueue.clear();
        }
        LOCK(cs_main);
        if (!chainActive.Contains(pBlockIndex)) {
            pBlockIndex = const_cast<CBlockIndex*>(chainActive.FindFork(pBlockIndex));
            if (!pBlockIndex) return;
        }
        if (pBlockIndex != chainActive.Tip()) {
            wallet->ScanForWalletTransactions(pBlockIndex, false, false);
        }
    }
}
