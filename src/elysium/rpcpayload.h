#ifndef ELYSIUM_RPCPAYLOAD_H
#define ELYSIUM_RPCPAYLOAD_H

#include <univalue.h>
#include "rpc/server.h"

UniValue elysium_createpayload_simplesend(const JSONRPCRequest& request);
UniValue elysium_createpayload_sendall(const JSONRPCRequest& request);
UniValue elysium_createpayload_sto(const JSONRPCRequest& request);
UniValue elysium_createpayload_issuancefixed(const JSONRPCRequest& request);
UniValue elysium_createpayload_issuancemanaged(const JSONRPCRequest& request);
UniValue elysium_createpayload_grant(const JSONRPCRequest& request);
UniValue elysium_createpayload_revoke(const JSONRPCRequest& request);
UniValue elysium_createpayload_changeissuer(const JSONRPCRequest& request);

#endif // ELYSIUM_RPCPAYLOAD_H
