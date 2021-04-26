// Copyright (c) 2019-2021 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
// Copyright (c) 2019-2021 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "sendtopcodedialog.h"
#include "ui_sendtopcodedialog.h"

#include "addressbookpage.h"
#include "addresstablemodel.h"
#include "bitcoinunits.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "receiverequestdialog.h"
#include "recentrequeststablemodel.h"
#include "walletmodel.h"
#include "pcodemodel.h"
#include "bip47/paymentchannel.h"
#include "lelantusmodel.h"

#include <QAction>
#include <QCursor>
#include <QItemSelection>
#include <QMessageBox>
#include <QScrollBar>
#include <QTextDocument>

namespace {
void OnTransactionChanged(SendtoPcodeDialog *dialog, CWallet *wallet, uint256 const &hash, ChangeType status)
{
    Q_UNUSED(wallet);
    Q_UNUSED(status);
    if (status == ChangeType::CT_NEW || status == ChangeType::CT_UPDATED) {
        QMetaObject::invokeMethod(dialog, "onTransactionChanged", Qt::QueuedConnection,
            Q_ARG(uint256, hash));
    }
}
}

SendtoPcodeDialog::SendtoPcodeDialog(QWidget *parent, std::string const & pcode) :
    QDialog(parent),
    ui(new Ui::SendtoPcodeDialog),
    model(0),
    result(Result::cancelled)
{
    ui->setupUi(this);
    try {
        paymentCode = std::make_shared<bip47::CPaymentCode>(pcode);
    } catch (std::runtime_error const &) {
        LogBip47("Cannot parse the payment code: " + pcode);
    }
}

SendtoPcodeDialog::~SendtoPcodeDialog()
{
    delete ui;

    if (!model) return;
    model->getWallet()->NotifyTransactionChanged.disconnect(boost::bind(OnTransactionChanged, this, _1, _2, _3));
}

void SendtoPcodeDialog::setModel(WalletModel *_model)
{
    model = _model;

    ui->sendButton->setEnabled(false);
    ui->useButton->setEnabled(false);
    result = Result::cancelled;

    if (!model || !paymentCode)
        return;

    model->getWallet()->NotifyTransactionChanged.connect(boost::bind(OnTransactionChanged, this, _1, _2, _3));

    CAmount lelantusBalance = model->getLelantusModel()->getPrivateBalance().first;

    if (model->getPcodeModel()->getNotificationTxid(*paymentCode, notificationTxHash)) {
        ui->sendButton->setEnabled(false);
        setNotifTxId();
        setUseAddr();
    } else {
        ui->sendButton->setEnabled(true);
        ui->notificationTxIdLabel->setText(tr("None"));

        ui->useButton->setEnabled(false);
        ui->nextAddressLabel->setText(tr("None"));
        result = Result::cancelled;
    }
    ui->notificationTxIdLabel->setTextFormat(Qt::RichText);
    ui->notificationTxIdLabel->setTextInteractionFlags(Qt::TextBrowserInteraction);
    ui->notificationTxIdLabel->setOpenExternalLinks(true);

    std::stringstream balancePretty;
    balancePretty.precision(4);
    balancePretty << std::fixed << 1.0 * lelantusBalance / COIN;
    ui->balanceLabel->setText(balancePretty.str().c_str());

    QColor color(GUIUtil::GUIColors::checkPassed);
    if (lelantusBalance < bip47::NotificationTxValue) {
        color = QColor(GUIUtil::GUIColors::warning);
        ui->sendButton->setEnabled(false);
    }
    ui->balanceLabel->setStyleSheet("QLabel { color: " + color.name() + "; }");
}

std::pair<SendtoPcodeDialog::Result, CBitcoinAddress> SendtoPcodeDialog::getResult() const
{
    if (result == Result::addressSelected) {
        return std::pair<Result, CBitcoinAddress>(result, addressToUse);
    }
    return std::pair<Result, CBitcoinAddress>(Result::cancelled, CBitcoinAddress());
}

std::unique_ptr<WalletModel::UnlockContext> SendtoPcodeDialog::getUnlockContext()
{
    return std::move(unlockContext);
}

void SendtoPcodeDialog::on_sendButton_clicked()
{
    if (!model || !paymentCode)
        return;

    unlockContext = std::unique_ptr<WalletModel::UnlockContext>(new WalletModel::UnlockContext(model->requestUnlock()));
    if (!unlockContext->isValid())
        return;

    try {
        notificationTxHash = model->getPcodeModel()->sendNotificationTx(*paymentCode);
        setNotifTxId();
        ui->sendButton->setEnabled(false);
        setUseAddr();
    }
    catch (std::runtime_error const & e)
    {
        QMessageBox msgBox;
        msgBox.setText(tr(
            "During creation of the notification tx the following error occurred:\n"));
        msgBox.setInformativeText(e.what());
        msgBox.setWindowTitle(tr("RAP error"));
        msgBox.setStandardButtons(QMessageBox::Ok);
        msgBox.setDefaultButton(QMessageBox::Ok);
        msgBox.exec();
    }
}

void SendtoPcodeDialog::on_useButton_clicked()
{
    result = Result::addressSelected;
    close();
}

void SendtoPcodeDialog::on_cancelButton_clicked()
{
    result = Result::cancelled;
    close();
}

void SendtoPcodeDialog::on_helpButton_clicked()
{
    QMessageBox msgBox;
    msgBox.setText(tr(
        "Sending funds to a RAP code requires a notification transaction to be sent by the payer prior to the first payment. \n"
        "Notification transactions use Lelantus facilities to enhance privacy.\n"
        "After the notification transaction is received by the RAP code issuer, funds can be privately sent to the RAP secret addresses.\n"));
    msgBox.setInformativeText(tr(
        "The recommended workflow is as follows:\n"
        "1. Send a notification transaction\n"
        "2. Make sure it is included in a block with a block explorer\n"
        "3. Send funds to the RAP code in one or more transactions"));
    msgBox.setWindowTitle(tr("RAP info"));
    msgBox.setStandardButtons(QMessageBox::Ok);
    msgBox.setDefaultButton(QMessageBox::Ok);
    msgBox.exec();
}

void SendtoPcodeDialog::showEvent( QShowEvent* event ) {
    QDialog::showEvent( event);
    adjustSize();
    ui->balanceSpacer->sizeHint().setHeight(ui->sendButton->size().height());
}

void SendtoPcodeDialog::setNotifTxId()
{
    std::ostringstream ostr;
    ostr << "<a href=\"https://";
    if(Params().GetConsensus().IsTestnet())
        ostr << "test";
    ostr << "explorer.firo.org/tx/" << notificationTxHash.GetHex() << "\">" << notificationTxHash.GetHex() << "</a>";
    ui->notificationTxIdLabel->setText(ostr.str().c_str());

    CWalletTx const * notifTx = model->getWallet()->GetWalletTx(notificationTxHash);
    if (!notifTx) return;
    int notifTxDepth = 0;
    {
        LOCK(cs_main);
        notifTxDepth = notifTx->GetDepthInMainChain();
    }

    if (notifTxDepth > 0)
    {
        ui->useButton->setEnabled(true);
        ui->useButton->setText("Use");
    } else {
        ui->useButton->setEnabled(false);
        ui->useButton->setText("Unconfirmed");
    }
}

void SendtoPcodeDialog::setUseAddr()
{
    {
        LOCK(model->getWallet()->cs_wallet);
        addressToUse = model->getWallet()->GetNextAddress(*paymentCode);
    }
    ui->nextAddressLabel->setText(addressToUse.ToString().c_str());
}

void SendtoPcodeDialog::onTransactionChanged(uint256 txHash)
{
    if (txHash != notificationTxHash) return;
    setNotifTxId();
}