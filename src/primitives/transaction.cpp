// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"

/** Default for -blockprioritysize, maximum space for zero/low-fee transactions **/
static const unsigned int DEFAULT_BLOCK_PRIORITY_SIZE = 50000; // 50KB
/** Dust Soft Limit, allowed with additional fee per output */
static const int64_t DUST_SOFT_LIMIT = 100000; // 0.001 FIRO
/** The maximum allowed size for a serialized block, in bytes (network rule) */
static const unsigned int MAX_BLOCK_SIZE = 2000000;                      // 2000KB block hard limit
/** Obsolete: maximum size for mined blocks */
static const unsigned int MAX_BLOCK_SIZE_GEN = MAX_BLOCK_SIZE/4;         // 500KB  block soft limit

std::string COutPoint::ToString() const
{
    return strprintf("COutPoint(%s, %u)", hash.ToString(), n);
}

std::string COutPoint::ToStringShort() const
{
    return strprintf("COutPoint(%s, %u)", hash.ToString().substr(0,64), n);
}

CTxIn::CTxIn(COutPoint prevoutIn, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = prevoutIn;
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

CTxIn::CTxIn(uint256 hashPrevTx, uint32_t nOut, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = COutPoint(hashPrevTx, nOut);
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

bool CTxIn::IsZerocoinSpend() const
{
    return (prevout.IsNull() && scriptSig.size() > 0 && (scriptSig[0] == OP_ZEROCOINSPEND) );
}

bool CTxIn::IsSigmaSpend() const
{
    return (prevout.IsSigmaMintGroup() && scriptSig.size() > 0 && (scriptSig[0] == OP_SIGMASPEND) );
}

bool CTxIn::IsLelantusJoinSplit() const
{
    return (prevout.IsNull() && scriptSig.size() > 0 && (scriptSig[0] == OP_LELANTUSJOINSPLIT || scriptSig[0] == OP_LELANTUSJOINSPLITPAYLOAD) );
}

bool CTxIn::IsZerocoinRemint() const
{
    return (prevout.IsNull() && scriptSig.size() > 0 && (scriptSig[0] == OP_ZEROCOINTOSIGMAREMINT));
}

std::string CTxIn::ToString() const
{
    std::string str;
    str += "CTxIn(";
    str += prevout.ToString();
    if (prevout.IsNull())
        str += strprintf(", coinbase %s", HexStr(scriptSig).substr(0, 24));
    else
        str += strprintf(", scriptSig=%s", HexStr(scriptSig).substr(0, 24));
    if (nSequence != SEQUENCE_FINAL)
        str += strprintf(", nSequence=%u", nSequence);
    str += ")";
    return str;
}

CTxOut::CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn)
{
    nValue = nValueIn;
    scriptPubKey = scriptPubKeyIn;
}

std::string CTxOut::ToString() const
{
    return strprintf("CTxOut(nValue=%d.%08d, scriptPubKey=%s)", nValue / COIN, nValue % COIN, HexStr(scriptPubKey).substr(0, 30));
}

CMutableTransaction::CMutableTransaction() : nVersion(CTransaction::CURRENT_VERSION), nType(TRANSACTION_NORMAL), nLockTime(0) {}
CMutableTransaction::CMutableTransaction(const CTransaction& tx) : nVersion(tx.nVersion), nType(tx.nType), vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime), vExtraPayload(tx.vExtraPayload) {}

uint256 CMutableTransaction::GetHash() const
{
    return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
}

std::string CMutableTransaction::ToString() const
{
    std::string str;
    str += strprintf("CMutableTransaction(hash=%s, ver=%d, vin.size=%u, vout.size=%u, nLockTime=%u)\n",
                     GetHash().ToString().substr(0,10),
                     nVersion,
                     vin.size(),
                     vout.size(),
                     nLockTime);
    for (unsigned int i = 0; i < vin.size(); i++)
        str += "    " + vin[i].ToString() + "\n";
    for (unsigned int i = 0; i < vout.size(); i++)
        str += "    " + vout[i].ToString() + "\n";
    return str;
}

uint256 CTransaction::ComputeHash() const
{
    return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
}


uint256 CTransaction::GetWitnessHash() const
{
    if (!HasWitness()) {
        return GetHash();
    }
    return SerializeHash(*this, SER_GETHASH, 0);
}

/* For backward compatibility, the hash is initialized to 0. TODO: remove the need for this default constructor entirely. */
CTransaction::CTransaction() : nVersion(CTransaction::CURRENT_VERSION), nType(TRANSACTION_NORMAL), vin(), vout(), nLockTime(0), hash() {}
CTransaction::CTransaction(const CMutableTransaction &tx) : nVersion(tx.nVersion), nType(tx.nType), vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime), vExtraPayload(tx.vExtraPayload), hash(ComputeHash()) {}
CTransaction::CTransaction(CMutableTransaction &&tx) : nVersion(tx.nVersion), nType(tx.nType), vin(std::move(tx.vin)), vout(std::move(tx.vout)), nLockTime(tx.nLockTime), vExtraPayload(std::move(tx.vExtraPayload)), hash(ComputeHash()) {}
CAmount CTransaction::GetValueOut() const
{
    CAmount nValueOut = 0;
    for (std::vector<CTxOut>::const_iterator it(vout.begin()); it != vout.end(); ++it)
    {
        nValueOut += it->nValue;
        if (!MoneyRange(it->nValue) || !MoneyRange(nValueOut))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return nValueOut;
}

double CTransaction::ComputePriority(double dPriorityInputs, unsigned int nTxSize) const
{
    nTxSize = CalculateModifiedSize(nTxSize);
    if (nTxSize == 0) return 0.0;

    return dPriorityInputs / nTxSize;
}

bool CTransaction::IsZerocoinSpend() const
{
    for (const CTxIn &txin: vin) {
        if (txin.IsZerocoinSpend())
            return true;
    }
    return false;
}

bool CTransaction::IsSigmaSpend() const
{
    for (const CTxIn &txin: vin) {
        if (txin.IsSigmaSpend())
            return true;
    }
    return false;
}

bool CTransaction::IsLelantusJoinSplit() const
{
    if (nVersion >= 3 && nType == TRANSACTION_LELANTUS)
        return true;

    for (const CTxIn &txin: vin) {
        if (txin.IsLelantusJoinSplit())
            return true;
    }
    return false;
}

bool CTransaction::IsZerocoinMint() const
{
    for (const CTxOut &txout: vout) {
        if (txout.scriptPubKey.IsZerocoinMint())
            return true;
    }
    return false;
}

bool CTransaction::IsSigmaMint() const
{
    if (IsZerocoinRemint())
        return false;
        
    for (const CTxOut &txout: vout) {
        if (txout.scriptPubKey.IsSigmaMint())
            return true;
    }
    return false;
}

bool CTransaction::IsLelantusMint() const
{
    for (const CTxOut &txout: vout) {
        if (txout.scriptPubKey.IsLelantusMint() || txout.scriptPubKey.IsLelantusJMint())
            return true;
    }
    return false;
}

bool CTransaction::IsZerocoinTransaction() const
{
    return IsZerocoinSpend() || IsZerocoinMint();
}

bool CTransaction::IsZerocoinV3SigmaTransaction() const
{
    return IsSigmaSpend() || IsSigmaMint() || IsZerocoinRemint();
}

bool CTransaction::IsLelantusTransaction() const
{
    return IsLelantusMint() || IsLelantusJoinSplit();
}

bool CTransaction::IsZerocoinRemint() const
{
    for (const CTxIn &txin: vin) {
        if (txin.IsZerocoinRemint())
            return true;
    }
    return false;
}

bool CTransaction::HasNoRegularInputs() const {
    return IsZerocoinSpend() || IsSigmaSpend() || IsZerocoinRemint() || IsLelantusJoinSplit();
}

unsigned int CTransaction::CalculateModifiedSize(unsigned int nTxSize) const
{
    // In order to avoid disincentivizing cleaning up the UTXO set we don't count
    // the constant overhead for each txin and up to 110 bytes of scriptSig (which
    // is enough to cover a compressed pubkey p2sh redemption) for priority.
    // Providing any more cleanup incentive than making additional inputs free would
    // risk encouraging people to create junk outputs to redeem later.
    if (nTxSize == 0)
        nTxSize = (GetTransactionWeight(*this) + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR;
    for (std::vector<CTxIn>::const_iterator it(vin.begin()); it != vin.end(); ++it)
    {
        unsigned int offset = 41U + std::min(110U, (unsigned int)it->scriptSig.size());
        if (nTxSize > offset)
            nTxSize -= offset;
    }
    return nTxSize;
}

unsigned int CTransaction::GetTotalSize() const
{
    return ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION);
}

std::string CTransaction::ToString() const
{
    std::string str;
    str += strprintf("CTransaction(hash=%s, ver=%d, type=%d, vin.size=%u, vout.size=%u, nLockTime=%u, vExtraPayload.size=%d)\n",
        GetHash().ToString().substr(0,10),
        nVersion,
        nType,
        vin.size(),
        vout.size(),
        nLockTime,
        vExtraPayload.size());
    for (unsigned int i = 0; i < vin.size(); i++)
        str += "    " + vin[i].ToString() + "\n";
    for (unsigned int i = 0; i < vin.size(); i++)
        str += "    " + vin[i].scriptWitness.ToString() + "\n";
    for (unsigned int i = 0; i < vout.size(); i++)
        str += "    " + vout[i].ToString() + "\n";
    return str;
}

int64_t GetTransactionWeight(const CTransaction& tx)
{
    return ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (WITNESS_SCALE_FACTOR -1) + ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
}
