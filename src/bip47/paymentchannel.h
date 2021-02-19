#ifndef ZCOIN_BIP47CHANNEL_H
#define ZCOIN_BIP47CHANNEL_H

#include <string>

#include "serialize.h"
#include "streams.h"
#include "uint256.h"

#include "bip47/defs.h"
#include "bip47/address.h"
#include "bip47/paymentcode.h"

class CWallet;

namespace bip47 {

class CPaymentChannel
{
public:
    enum struct Side : unsigned char {
        sender = 0,
        receiver
    };
public:
    CPaymentChannel(CPaymentCode const & theirPcode, CExtKey const & myChannelKey, Side side);

    CPaymentCode const & getTheirPcode() const;
    CBitcoinAddress generateTheirNextSecretAddress();
    TheirAddrContT generateTheirSecretAddresses(size_t fromAddr, size_t uptoAddr) const;

    CPaymentCode const & getMyPcode() const;
    MyAddrContT generateMySecretAddresses(size_t fromAddr, size_t uptoAddr) const;

    std::vector<unsigned char> getMaskedPayload(unsigned char const * sha512Key, size_t sha512KeySize, CKey const & outpointSecret) const;
    std::vector<unsigned char> getMaskedPayload(COutPoint const & outpoint, CKey const & outpointSecret) const;

    MyAddrContT const & generateMyUsedAddresses();
    MyAddrContT const & generateMyNextAddresses();
    bool markAddressUsed(CBitcoinAddress const &);

    ADD_DESERIALIZE_CTOR(CPaymentChannel);
    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(myChannelKey);
        READWRITE(theirPcode);
        READWRITE(usedAddressCount);
        READWRITE(theirUsedAddressCount);
        unsigned char sd(static_cast<unsigned char>(side));
        READWRITE(sd);
        side = Side(sd);
    }
private:
    CExtKey myChannelKey;
    CPaymentCode theirPcode;
    boost::optional<CPaymentCode> mutable myPcode;

    size_t usedAddressCount, theirUsedAddressCount;
    MyAddrContT usedAddresses;
    MyAddrContT nextAddresses;
    Side side;
};

}

#endif // ZCOIN_BIP47CHANNEL_H
