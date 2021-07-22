#ifndef FIRO_ELYSIUM_TXPROCESSOR_H
#define FIRO_ELYSIUM_TXPROCESSOR_H

#include "property.h"
#include "tx.h"

#include <boost/signals2/signal.hpp>

namespace elysium {

class TxProcessor
{
public:
    int ProcessTx(CMPTransaction& tx);

public:
    boost::signals2::signal<void(const CMPTransaction&)> TransactionProcessed;

private:
    int ProcessLelantusMint(const CMPTransaction& tx);
    int ProcessLelantusJoinSplit(const CMPTransaction& tx);
    int ProcessChangeLelantusStatus(const CMPTransaction& tx);
};

extern TxProcessor *txProcessor;

}

#endif // FIRO_ELYSIUM_TXPROCESSOR_H
