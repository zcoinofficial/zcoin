#ifndef ELYSIUM_RPCRAWTX_H
#define ELYSIUM_RPCRAWTX_H

#include <univalue.h>
#include "rpc/server.h"

UniValue elysium_decodetransaction(const JSONRPCRequest& request);
UniValue elysium_createrawtx_opreturn(const JSONRPCRequest& request);
UniValue elysium_createrawtx_input(const JSONRPCRequest& request);
UniValue elysium_createrawtx_reference(const JSONRPCRequest& request);
UniValue elysium_createrawtx_change(const JSONRPCRequest& request);

#endif // ELYSIUM_RPCRAWTX_H
