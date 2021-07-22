
#include <thread>

#include "bip47/account.h"
#include "bip47/paymentcode.h"
#include "util.h"
#include "bip47/bip47utils.h"
#include "wallet/wallet.h"
#include "lelantus.h"


namespace bip47 {

CAccountBase::CAccountBase()
: accountNum(0)
, version(1)
{
}

CAccountBase::CAccountBase(CExtKey const & walletKey, uint32_t accountNum)
:accountNum(accountNum)
{
    walletKey.Derive(privkey, (unsigned int)(accountNum) | BIP32_HARDENED_KEY_LIMIT);
    pubkey = privkey.Neuter();
}

MyAddrContT const & CAccountBase::getMyUsedAddresses() const
{
    return generateMyUsedAddresses();
}

MyAddrContT const & CAccountBase::getMyNextAddresses() const
{
    return generateMyNextAddresses();
}

bool CAccountBase::addressUsed(CBitcoinAddress const & address)
{
    return markAddressUsed(address);
}

CPaymentCode const & CAccountBase::getMyPcode() const
{
    if (!myPcode) {
        myPcode.emplace(pubkey.pubkey, pubkey.chaincode);
    }
    return *myPcode;
}

uint32_t CAccountBase::getAccountNum() const
{
    return accountNum;
}

CKey const & CAccountBase::getMyNotificationKey() const
{
    if (!myNotificationKey) {
        myNotificationKey.emplace(utils::Derive(privkey, {0}).key);
    }
    return *myNotificationKey;
}

uint32_t CAccountBase::getVersion() const
{
    return version;
}

/******************************************************************************/

CAccountSender::CAccountSender(CExtKey const & walletKey, uint32_t accountNum, CPaymentCode const & theirPcode)
: CAccountBase(walletKey, accountNum), theirPcode(theirPcode)
{
    updateMyNextAddresses();
}

CPaymentChannel & CAccountSender::getPaymentChannel() const {
    if (!pchannel)
        pchannel.emplace(theirPcode, privkey, CPaymentChannel::Side::sender);
    return *pchannel;
}

std::vector<unsigned char> CAccountSender::getMaskedPayload(COutPoint const & outpoint, CKey const & outpointSecret)
{
    return getPaymentChannel().getMaskedPayload(outpoint, outpointSecret);
}

CPaymentCode const & CAccountSender::getTheirPcode() const
{
    return theirPcode;
}

CBitcoinAddress CAccountSender::generateTheirNextSecretAddress()
{
    return getPaymentChannel().generateTheirNextSecretAddress();
}

CBitcoinAddress CAccountSender::getTheirNextSecretAddress() const
{
    return getPaymentChannel().getTheirNextSecretAddress();
}

size_t CAccountSender::setTheirUsedAddressNumber(size_t number)
{
    return getPaymentChannel().setTheirUsedAddressNumber(number);
}

TheirAddrContT CAccountSender::getTheirUsedAddresses() const
{
    return getPaymentChannel().getTheirUsedSecretAddresses();
}

void CAccountSender::updateMyNextAddresses()
{
    nextAddresses.clear();
    nextAddresses.push_back({getPaymentChannel().getMyPcode().getNotificationAddress(), getMyNotificationKey()});
}

MyAddrContT const & CAccountSender::generateMyUsedAddresses() const
{
    return getPaymentChannel().generateMyUsedAddresses();
}

MyAddrContT const & CAccountSender::generateMyNextAddresses() const
{
    return nextAddresses;
}

bool CAccountSender::markAddressUsed(CBitcoinAddress const & address)
{
    return getPaymentChannel().markAddressUsed(address);
}

void CAccountSender::setNotificationTxId(uint256 const & txId)
{
    notificationTxId = txId;
}
uint256 CAccountSender::getNotificationTxId() const
{
    return notificationTxId;
}

/******************************************************************************/

CAccountReceiver::CAccountReceiver(CExtKey const & walletKey, uint32_t accountNum, std::string const & label)
: CAccountBase(walletKey, accountNum), label(label)
{}

CBitcoinAddress const & CAccountReceiver::getMyNotificationAddress() const
{
    if (!myNotificationAddress) {
        myNotificationAddress.emplace(getMyPcode().getNotificationAddress());
    }
    return *myNotificationAddress;
}

namespace {
    struct CompByPcode {
        CompByPcode(CPaymentCode const & comp): comp(comp){};
        bool operator()(CPaymentChannel const & other) const {return other.getTheirPcode() == comp;};
        CPaymentCode const & comp;
    };
}

bool CAccountReceiver::findTheirPcode(CPaymentCode const & pcode) const
{
    return std::find_if (pchannels.begin(), pchannels.end(), CompByPcode(pcode)) != pchannels.end();
}

std::string const & CAccountReceiver::getLabel() const
{
    return label;
}

void CAccountReceiver::setLabel(std::string const & lbl)
{
    label = lbl;
}

CAccountReceiver::PChannelContT const & CAccountReceiver::getPchannels() const
{
    return pchannels;
}

boost::optional<size_t> CAccountReceiver::setMyUsedAddressNumber(CPaymentCode const & theirPcode, size_t number)
{
    boost::optional<size_t> result;
    for (CPaymentChannel & pchannel: pchannels) {
        if(pchannel.getTheirPcode() == theirPcode)
            result.emplace(pchannel.setMyUsedAddressNumber(number));
    }
    if(result) {
        generateMyNextAddresses();
        generateMyUsedAddresses();
    }
    return result;
}

MyAddrContT const & CAccountReceiver::generateMyUsedAddresses() const
{
    usedAddresses.clear();
    for (CPaymentChannel & pchannel: pchannels) {
        MyAddrContT const & addrs = pchannel.generateMyUsedAddresses();
        usedAddresses.insert(usedAddresses.end(), addrs.begin(), addrs.end());
    }
    return usedAddresses;
}

MyAddrContT const & CAccountReceiver::generateMyNextAddresses() const
{
    nextAddresses.clear();
    nextAddresses.emplace_back(getMyNotificationAddress(), getMyNotificationKey());
    for (CPaymentChannel & pchannel: pchannels) {
        MyAddrContT const & addrs = pchannel.generateMyNextAddresses();
        nextAddresses.insert(nextAddresses.end(), addrs.begin(), addrs.end());
    }
    return nextAddresses;
}

bool CAccountReceiver::markAddressUsed(CBitcoinAddress const & address)
{
    for (PChannelContT::iterator iter = pchannels.begin(); iter != pchannels.end(); ++iter) {
        if (iter->markAddressUsed(address)) {
            generateMyNextAddresses();
            return true;
        }
    }
    return false;
}

void CAccountReceiver::acceptPcode(CPaymentCode const & theirPcode)
{
    if (findTheirPcode(theirPcode))
        return;
    pchannels.emplace_back(theirPcode, privkey, CPaymentChannel::Side::receiver);
}

bool CAccountReceiver::acceptMaskedPayload(std::vector<unsigned char> const & maskedPayload, COutPoint const & outpoint, CPubKey const & outpoinPubkey)
{
    std::unique_ptr<CPaymentCode> pcode;
    CExtKey pcodePrivkey = utils::Derive(privkey, {0});
    try {
        pcode = bip47::utils::PcodeFromMaskedPayload(maskedPayload, outpoint, pcodePrivkey.key, outpoinPubkey);
        if (!pcode)
            return false;
    } catch (std::runtime_error const &) {
        return false;
    }
    acceptPcode(*pcode);
    return true;
}

bool CAccountReceiver::acceptMaskedPayload(std::vector<unsigned char> const & maskedPayload, CTransaction const & tx)
{
    std::unique_ptr<lelantus::JoinSplit> jsplit = lelantus::ParseLelantusJoinSplit(tx);
    if (!jsplit)
        return false;
    std::unique_ptr<CPaymentCode> pcode;
    CExtKey pcodePrivkey = utils::Derive(privkey, {0});
    try {
        CDataStream ds(SER_NETWORK, 0);
        ds << jsplit->getCoinSerialNumbers()[0];
        pcode = bip47::utils::PcodeFromMaskedPayload(maskedPayload, (unsigned char const *)ds.vch.data(), ds.vch.size(), pcodePrivkey.key, jsplit->GetEcdsaPubkeys()[0]);
        if (!pcode)
            return false;
    } catch (std::runtime_error const &) {
        return false;
    }
    acceptPcode(*pcode);
    return true;
}

CPaymentCode const & CAccountReceiver::lastPcode() const
{
    return pchannels.back().getTheirPcode();
}

/******************************************************************************/

CWallet::CWallet(std::vector<unsigned char> const & seedData)
{
    CExtKey seedKey;
    seedKey.SetMaster(seedData.data(), seedData.size());
    privkeySend = utils::Derive(seedKey, {47 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT, 0});
    privkeyReceive = utils::Derive(seedKey, {47 | BIP32_HARDENED_KEY_LIMIT, 0x00 | BIP32_HARDENED_KEY_LIMIT, 1});
}

CWallet::CWallet(uint256 const & seedData)
:CWallet({seedData.begin(), seedData.end()})
{}

CAccountReceiver & CWallet::createReceivingAccount(std::string const & label)
{
    for (std::pair<uint32_t const, CAccountReceiver> const & accReceiver : accReceivers) {
        if (accReceiver.second.getLabel() == label)
            throw std::runtime_error("Account with such label already exists.");
    }
    uint32_t const accNum = (accReceivers.empty() ? 0 : accReceivers.rbegin()->first + 1);
    accReceivers.emplace(accNum, CAccountReceiver(privkeyReceive, accNum, label));
    CAccountReceiver & acc = accReceivers.rbegin()->second;
    LogBip47("Created for receiving: pcode: %s, naddr: %s, accNum: %d\n", acc.getMyPcode().toString(), acc.getMyPcode().getNotificationAddress().ToString(), accNum);
    return acc;
}

CAccountSender & CWallet::provideSendingAccount(CPaymentCode const & theirPcode)
{
    for (std::pair<uint32_t const, CAccountSender> & acc : accSenders) {
        if (acc.second.getTheirPcode() == theirPcode)
            return acc.second;
    }
    uint32_t const accNum = (accSenders.empty() ? 0 : accSenders.rbegin()->first + 1);
    accSenders.emplace(accNum, CAccountSender(privkeySend, accNum, theirPcode));
    CAccountSender & acc = accSenders.rbegin()->second;
    LogBip47("Created for sending to pcode: %s, accNum: %s, myPcode: %s\n", theirPcode.toString().c_str(), accNum, acc.getMyPcode().toString().c_str());
    return acc;
}

CAccountReceiver const * CWallet::getReceivingAccount(uint32_t accountNum) const
{
    std::map<uint32_t, CAccountReceiver>::const_iterator iacc = accReceivers.find(accountNum);
    if (iacc == accReceivers.end())
        return nullptr;
    return &(iacc->second);
}

void CWallet::readReceiver(CAccountReceiver && receiver)
{
    if (accReceivers.find(receiver.getAccountNum()) != accReceivers.end())
        throw std::runtime_error("There is already an account with number " + std::to_string(receiver.getAccountNum()));
    accReceivers.insert(std::pair<uint32_t, CAccountReceiver>(receiver.getAccountNum(), std::move(receiver)));
}

void CWallet::readSender(CAccountSender && sender)
{
    if (accSenders.find(sender.getAccountNum()) != accSenders.end())
        throw std::runtime_error("There is already an account with number " + std::to_string(sender.getAccountNum()));
    accSenders.insert(std::pair<uint32_t, CAccountSender>(sender.getAccountNum(), std::move(sender)));
}

void CWallet::enumerateReceivers(std::function<bool(CAccountReceiver &)> op)
{
    for (std::pair<uint32_t const, CAccountReceiver> & val : accReceivers) {
        if (op && !op(val.second))
            break;
    }
}

void CWallet::enumerateReceivers(std::function<bool(CAccountReceiver const &)> op) const
{
    for (std::pair<uint32_t const, CAccountReceiver> const & val : accReceivers) {
        if (op && !op(val.second))
            break;
    }

}

void CWallet::enumerateSenders(std::function<bool(CAccountSender &)> op)
{
    for (std::pair<uint32_t const, CAccountSender> & val : accSenders) {
        if (op && !op(val.second))
            break;
    }
}

void CWallet::enumerateSenders(std::function<bool(CAccountSender const &)> op) const
{
    for (std::pair<uint32_t const, CAccountSender> const & val : accSenders) {
        if (op && !op(val.second))
            break;
    }
}

}
