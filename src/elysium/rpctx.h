#ifndef ELYSIUM_RPCTX
#define ELYSIUM_RPCTX

#include <univalue.h>
#include "rpc/server.h"

UniValue elysium_sendrawtx(const JSONRPCRequest& request);
UniValue elysium_send(const JSONRPCRequest& request);
UniValue elysium_sendall(const JSONRPCRequest& request);
UniValue elysium_sendissuancefixed(const JSONRPCRequest& request);
UniValue elysium_sendissuancemanaged(const JSONRPCRequest& request);
UniValue elysium_sendsto(const JSONRPCRequest& request);
UniValue elysium_sendgrant(const JSONRPCRequest& request);
UniValue elysium_sendrevoke(const JSONRPCRequest& request);
UniValue elysium_sendchangeissuer(const JSONRPCRequest& request);
UniValue elysium_sendactivation(const JSONRPCRequest& request);
UniValue elysium_sendalert(const JSONRPCRequest& request);

#endif // ELYSIUM_RPCTX
