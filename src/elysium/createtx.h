#ifndef ELYSIUM_CREATETX_H
#define ELYSIUM_CREATETX_H

class CCoinsViewCache;
class CMutableTransaction;
class COutPoint;
class CPubKey;
class CScript;
class CTxOut;
class uint256;

#include "script/standard.h"

#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

/**
 * A structure representing previous transaction outputs.
 */
struct PrevTxsEntry
{
    /** Creates a new previous output entry. */
    PrevTxsEntry(const uint256& txid, uint32_t nOut, int64_t nValue, const CScript& scriptPubKey);

    COutPoint outPoint;
    CTxOut txOut;
};

/**
 * Builder to create Elysium transactions.
 *
 * The ElysiumTxBuilder class is an extension of the TxBuilder, with additional
 * methods to build Elysium transactions. Payloads can be embedded with class B
 * (bare-multisig) or class C (op-return) encoding.
 *
 * The output values are based on the dust threshold, but may optionally be
 * higher for reference outputs.
 *
 * Example usage:
 *
 * @code
 *   // add a bare-multisig encoded payload to an existing transaction:
 *   CMutableTransaction modifiedTx = ElysiumTxBuilder(basisTx)
 *           .addMultisig(payload, obfuscationSeed, redeemingPubKey)
 *           .build();
 * @endcode
 */
class ElysiumTxBuilder
{
public:
    /**
     * Creates a new transaction builder.
     */
    ElysiumTxBuilder();

    /**
     * Creates a new transaction builder to extend a transaction.
     *
     * @param transactionIn The transaction used to build upon
     */
    ElysiumTxBuilder(const CMutableTransaction& transactionIn);

    /**
     * Adds an outpoint as input to the transaction.
     *
     * @param outPoint The transaction outpoint to add
     */
    ElysiumTxBuilder& addInput(const COutPoint& outPoint);

    /**
     * Adds a transaction input to the transaction.
     *
     * @param txid The hash of the input transaction
     * @param nOut The index of the transaction output used as input
     */
    ElysiumTxBuilder& addInput(const uint256& txid, uint32_t nOut);

    /**
     * Adds an output to the transaction.
     *
     * @param scriptPubKey The output script
     * @param value        The output value
     */
    ElysiumTxBuilder& addOutput(const CScript& scriptPubKey, int64_t value);

    /**
     * Adds a collection of outputs to the transaction.
     *
     * @param txOutputs The outputs to add
     */
    ElysiumTxBuilder& addOutputs(const std::vector<std::pair<CScript, int64_t> >& txOutputs);

    /**
     * Adds an output for change.
     *
     * Optionally a position can be provided, where the change output should be
     * inserted, starting with 0. If the number of outputs is smaller than the
     * position, then the change output is added to the end.
     *
     * If the change amount would be considered as dust, then no change output
     * is added.
     *
     * @param destination The destination of the change
     * @param view        The coins view, which contains the inputs being spent
     * @param txFee       The desired transaction fees
     * @param position    The position of the change output (default: last position)
     */
    ElysiumTxBuilder& addChange(const CTxDestination& destination, const CCoinsViewCache& view, int64_t txFee, uint32_t position = 999999);

    /**
     * Returns the created transaction.
     *
     * @return The created transaction
     */
    CMutableTransaction build();

    /**
     * Adds a collection of previous outputs as inputs to the transaction.
     *
     * @param outPoint The transaction outpoint to add
     */
    ElysiumTxBuilder& addInputs(const std::vector<PrevTxsEntry>& prevTxs);

    /**
     * Adds an output for the reference address.
     *
     * The output value is set to at least the dust threshold.
     *
     * @param destination The reference address
     * @param value       The optional reference amount
     */
    ElysiumTxBuilder& addReference(const std::string& destination, int64_t value = 0);

    /**
     * Embeds a payload with class C (op-return) encoding.
     *
     * If the data encoding fails, then the transaction is not modified.
     *
     * @param data The payload to embed
     */
    ElysiumTxBuilder& addOpReturn(const std::vector<unsigned char>& data);

    /**
     * Adds an output for change.
     *
     * Optionally a position can be provided, where the change output should be
     * inserted, starting with 0. If the number of outputs is smaller than the
     * position, then the change output is added to the end.
     *
     * If no position is specified, then the change output is added to the first
     * position. This default behavior differs from the TxBuilder class.
     *
     * If the change amount would be considered as dust, then no change output is added.
     *
     * @param destination The destination of the change
     * @param view        The coins view, which contains the inputs being spent
     * @param txFee       The desired transaction fees
     * @param position    The position of the change output (default: first position)
     */
    ElysiumTxBuilder& addChange(const std::string& destination, const CCoinsViewCache& view, int64_t txFee, uint32_t position = 0);

protected:
    CMutableTransaction transaction;
};

/**
 * Adds previous transaction outputs to coins view.
 *
 * @param prevTxs The previous transaction outputs
 * @param view    The coins view to modify
 */
void InputsToView(const std::vector<PrevTxsEntry>& prevTxs, CCoinsViewCache& view);


#endif // ELYSIUM_CREATETX_H
