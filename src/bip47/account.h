#ifndef ZCOIN_BIP47ACCOUNT_H
#define ZCOIN_BIP47ACCOUNT_H

#include <map>

#include "bip47/defs.h"
#include "bip47/paymentcode.h"
#include "bip47/paymentchannel.h"
#include "key.h"
#include "pubkey.h"

namespace bip47 {

class CWallet;

class CAccountBase
{
public:
    CAccountBase();
    CAccountBase(CExtKey const & walletKey, uint32_t accountNum);
    virtual ~CAccountBase() = default;

    MyAddrContT const & getMyUsedAddresses() const;
    MyAddrContT const & getMyNextAddresses() const;
    bool addressUsed(CBitcoinAddress const & address);

    CPaymentCode const & getMyPcode() const;
    uint32_t getAccountNum() const;

    ADD_DESERIALIZE_CTOR(CAccountBase);
    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    void SerializationOp(Stream& s, Operation ser_action)
    {
        uint32_t accNum = accountNum;
        READWRITE(accNum);
        const_cast<uint32_t &>(accountNum) = accNum;
        READWRITE(version);
        READWRITE(privkey);
        READWRITE(pubkey);
        READWRITE(myPcode);
    }

protected:
    uint32_t const accountNum;
    CExtKey privkey;
    CExtPubKey pubkey;
    CKey const & getMyNotificationKey() const;
    uint32_t getVersion() const;
private:
    boost::optional<CPaymentCode> mutable myPcode;
    boost::optional<CKey> mutable myNotificationKey;
    uint32_t version;

    virtual MyAddrContT const & generateMyUsedAddresses() const = 0;
    virtual MyAddrContT const & generateMyNextAddresses() const = 0;
    virtual bool markAddressUsed(CBitcoinAddress const &) = 0;
};

/******************************************************************************/

/**
 * A sender account is created when the wallet pays to a 'their' payment code.
 * It has just one payment channel which handles payments to their account. 
 */

class CAccountSender : public CAccountBase
{
public:
    CAccountSender() = default;
    CAccountSender(CExtKey const & walletKey, uint32_t accountNum, CPaymentCode const & theirPcode);

    CPaymentChannel & getPaymentChannel() const;
    std::vector<unsigned char> getMaskedPayload(COutPoint const & outpoint, CKey const & outpointSecret);

    CPaymentCode const & getTheirPcode() const;
    CBitcoinAddress generateTheirNextSecretAddress();
    CBitcoinAddress getTheirNextSecretAddress() const;
    size_t setTheirUsedAddressNumber(size_t number);

    TheirAddrContT getTheirUsedAddresses() const;

    void setNotificationTxId(uint256 const & txId);
    uint256 getNotificationTxId() const;

    ADD_DESERIALIZE_CTOR(CAccountSender);
    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    void SerializationOp(Stream& s, Operation ser_action)
    {
        CAccountBase::SerializationOp(s, ser_action);
        READWRITE(theirPcode);
        READWRITE(pchannel);
        if (ser_action.ForRead())
            updateMyNextAddresses();
        READWRITE(notificationTxId);
    }

private:
    CPaymentCode theirPcode;
    boost::optional<CPaymentChannel> mutable pchannel;
    MyAddrContT nextAddresses;
    uint256 notificationTxId;
    std::string label;

    void updateMyNextAddresses();
    virtual MyAddrContT const & generateMyUsedAddresses() const;
    virtual MyAddrContT const & generateMyNextAddresses() const;
    virtual bool markAddressUsed(CBitcoinAddress const &);
};

/******************************************************************************/

/**
 * A receiver account is created every time we publish a payment code.
 * Every time a notification tx is received, a new payment channel for this tx's
 * payment code is created.
 */
class CAccountReceiver : public CAccountBase
{
public:
    CAccountReceiver() = default;
    CAccountReceiver(CExtKey const & walletKey, uint32_t accountNum, std::string const & label);

    CBitcoinAddress const & getMyNotificationAddress() const;

    void acceptPcode(CPaymentCode const & theirPcode);
    bool acceptMaskedPayload(std::vector<unsigned char> const & maskedPayload, COutPoint const & outpoint, CPubKey const & outpoinPubkey);
    bool acceptMaskedPayload(std::vector<unsigned char> const & maskedPayload, CTransaction const & tx);
    CPaymentCode const & lastPcode() const;
    bool findTheirPcode(CPaymentCode const & pcode) const;

    std::string const & getLabel() const;
    void setLabel(std::string const & label);

    using PChannelContT = std::vector<CPaymentChannel>;
    PChannelContT const & getPchannels() const;

    boost::optional<size_t> setMyUsedAddressNumber(CPaymentCode const & theirPcode, size_t number);

    ADD_DESERIALIZE_CTOR(CAccountReceiver);
    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    void SerializationOp(Stream& s, Operation ser_action)
    {
        CAccountBase::SerializationOp(s, ser_action);
        READWRITE(label);
        READWRITE(pchannels);
    }

private:
    PChannelContT mutable pchannels;
    boost::optional<CBitcoinAddress> mutable myNotificationAddress;

    MyAddrContT mutable usedAddresses, nextAddresses;
    std::string label;

    virtual MyAddrContT const & generateMyUsedAddresses() const;
    virtual MyAddrContT const & generateMyNextAddresses() const;
    virtual bool markAddressUsed(CBitcoinAddress const &);
};

/******************************************************************************/

/**
 * Contains and manages bip47 accounts. 
 * Wallet masterkey is derived using the m/47'/136' path.
 */    
    
class CWallet {
public:
    CWallet(std::vector<unsigned char> const & seedData);
    CWallet(uint256 const & seedData);

    CAccountReceiver & createReceivingAccount(std::string const & label);
    CAccountSender & provideSendingAccount(CPaymentCode const & theirPcode);

    CAccountReceiver const * getReceivingAccount(uint32_t accountNum) const;

    void readReceiver(CAccountReceiver && receiver);
    void readSender(CAccountSender && sender);

    /* Op is called for every sender/receiver account. Enumeration stops when calling op returns false */
    void enumerateReceivers(std::function<bool(CAccountReceiver &)> op);
    void enumerateReceivers(std::function<bool(CAccountReceiver const &)> op) const;
    void enumerateSenders(std::function<bool(CAccountSender &)> op);
    void enumerateSenders(std::function<bool(CAccountSender const &)> op) const;
private:
    std::map<uint32_t, CAccountReceiver> accReceivers;
    std::map<uint32_t, CAccountSender> accSenders;
    CExtKey privkeySend, privkeyReceive;
};

}

#endif // ZCOIN_BIP47ACCOUNT_H
