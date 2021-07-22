// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "transactionrecord.h"

#include <QApplication>

#include "base58.h"
#include "consensus/consensus.h"
#include "lelantus.h"
#include "validation.h"
#include "timedata.h"
#include "wallet/wallet.h"
#include "bip47/bip47utils.h"

#include <stdint.h>

#include <boost/foreach.hpp>

/* Return positive answer if transaction should be shown in list.
 */
bool TransactionRecord::showTransaction(const CWalletTx &wtx)
{
    if (wtx.IsCoinBase())
    {
        // Ensures we show generated coins / mined transactions at depth 1
        if (!wtx.IsInMainChain())
        {
            return false;
        }
    }
    return true;
}

/*
 * Decompose CWallet transaction to model transaction records.
 */
QList<TransactionRecord> TransactionRecord::decomposeTransaction(const CWallet *wallet, const CWalletTx &wtx)
{
    QList<TransactionRecord> parts;
    int64_t nTime = wtx.GetTxTime();
    CAmount nCredit = wtx.GetCredit(ISMINE_ALL);
    CAmount nDebit = wtx.GetDebit(ISMINE_ALL);
    CAmount nNet = nCredit - nDebit;
    uint256 hash = wtx.GetHash();
    std::map<std::string, std::string> mapValue = wtx.mapValue;

    bool isAllSigmaSpendFromMe = false;
    for (const auto& vin : wtx.tx->vin) {
        isAllSigmaSpendFromMe = (wallet->IsMine(vin, *wtx.tx) & ISMINE_SPENDABLE) && vin.IsSigmaSpend();
        if (!isAllSigmaSpendFromMe)
            break;
    }

    bool isAllJoinSplitFromMe = false;
    for (const auto& vin : wtx.tx->vin) {
        isAllJoinSplitFromMe = (wallet->IsMine(vin, *wtx.tx) & ISMINE_SPENDABLE) && vin.IsLelantusJoinSplit();
        if (!isAllJoinSplitFromMe)
            break;
    }

    if (wtx.tx->IsZerocoinSpend() || isAllSigmaSpendFromMe || isAllJoinSplitFromMe) {
        CAmount nTxFee = nDebit - wtx.tx->GetValueOut();
        if (isAllJoinSplitFromMe && wtx.tx->vin.size() > 0) {
            nTxFee = lelantus::ParseLelantusJoinSplit(*wtx.tx)->getFee();
        }

        bool first = true;

        bool isAllToMe = true;
        std::string addresses = "";
        bool involvesWatchAddress = false;
        bool firstAddress = true;

        for (const CTxOut& txout : wtx.tx->vout) {
            isminetype mine = wallet->IsMine(txout);
            if (!mine) {
                isAllToMe = false;
                break;
            } else if (!txout.scriptPubKey.IsSigmaMint() && !txout.scriptPubKey.IsLelantusJMint()) {
                CTxDestination address;
                ExtractDestination(txout.scriptPubKey, address);
                if (firstAddress) {
                    addresses.append(CBitcoinAddress(address).ToString());
                    firstAddress = false;
                } else
                    addresses.append(", " + CBitcoinAddress(address).ToString());
            }
            if(mine & ISMINE_WATCH_ONLY)
                involvesWatchAddress = true;
        }

        if (isAllToMe) {
            TransactionRecord sub(hash, nTime);
            sub.involvesWatchAddress = involvesWatchAddress;
            sub.type = TransactionRecord::SpendToSelf;
            sub.address = addresses;
            sub.idx = parts.size();
            sub.debit = -nTxFee;
            parts.append(sub);
        } else {
            for (const CTxOut& txout : wtx.tx->vout) {
                if (wtx.IsChange(txout)) {
                    continue;
                }
                isminetype mine = wallet->IsMine(txout);

                TransactionRecord sub(hash, nTime);
                CTxDestination address;
                sub.idx = parts.size();
                if (mine) {
                    sub.involvesWatchAddress = mine & ISMINE_WATCH_ONLY;
                    if (ExtractDestination(txout.scriptPubKey, address) && IsMine(*wallet, address)) {
                        sub.type = TransactionRecord::SpendToSelf;
                        sub.address = CBitcoinAddress(address).ToString();
                        sub.credit = txout.nValue;
                    }
                } else {
                    if (!bip47::utils::GetMaskedPcode(txout).empty())
                        continue;
                    ExtractDestination(txout.scriptPubKey, address);
                    sub.type = TransactionRecord::SpendToAddress;
                    sub.address = CBitcoinAddress(address).ToString();
                    sub.debit = -txout.nValue;
                    if (first) {
                        sub.debit -= nTxFee;
                        first = false;
                    }
                }
                boost::optional<bip47::CPaymentCodeDescription> pcode = wallet->FindPcode(address);
                if(pcode)
                {
                    sub.type = TransactionRecord::SendToPcode;
                    sub.pcode = std::get<1>(*pcode).toString();
                }
                parts.append(sub);
            }
        }
    }
    else if (wtx.tx->IsZerocoinRemint()) {
        TransactionRecord sub(hash, nTime);
        sub.type = TransactionRecord::SpendToSelf;
        CAmount txAmount = 0;
        for (const CTxOut &txout: wtx.tx->vout)
            txAmount += txout.nValue;
        sub.idx = parts.size();
        sub.debit = -txAmount;
        sub.credit = txAmount;
        sub.address = QCoreApplication::translate("firo-core", "Zerocoin->Sigma remint").toStdString();
        parts.append(sub);
    }
    else if (nNet > 0 || wtx.IsCoinBase())
    {
        //
        // Credit
        //

        for(unsigned int i = 0; i < wtx.tx->vout.size(); i++)
        {
            const CTxOut& txout = wtx.tx->vout[i];
            isminetype mine = wallet->IsMine(txout);
            if (mine)
            {
                TransactionRecord sub(hash, nTime);
                CTxDestination address;
                sub.idx = i; // vout index
                sub.credit = txout.nValue;
                sub.involvesWatchAddress = mine & ISMINE_WATCH_ONLY;

                if(ExtractDestination(txout.scriptPubKey, address) && IsMine(*wallet, address))
                {
                    // Received by Bitcoin Address
                    sub.type = TransactionRecord::RecvWithAddress;
                    sub.address = CBitcoinAddress(address).ToString();
                }
                else
                {
                    // Received by IP connection (deprecated features), or a multisignature or other non-simple transaction
                    sub.type = TransactionRecord::RecvFromOther;
                    sub.address = mapValue["from"];
                }
                if (wtx.IsCoinBase())
                {
                    // Generated
                    sub.type = TransactionRecord::Generated;
                }
                boost::optional<bip47::CPaymentCodeDescription> pcode = wallet->FindPcode(address);
                if(pcode)
                {
                    sub.type = TransactionRecord::RecvWithPcode;
                    sub.pcode = std::get<1>(*pcode).toString();
                }
                parts.append(sub);
            }
        }
    }
    else
    {
        bool involvesWatchAddress = false;
        isminetype fAllFromMe = ISMINE_SPENDABLE;
        BOOST_FOREACH(const CTxIn& txin, wtx.tx->vin)
        {
            isminetype mine = wallet->IsMine(txin, *wtx.tx);
            if(mine & ISMINE_WATCH_ONLY) involvesWatchAddress = true;
            if(fAllFromMe > mine) fAllFromMe = mine;
        }

        isminetype fAllToMe = ISMINE_SPENDABLE;
        BOOST_FOREACH(const CTxOut& txout, wtx.tx->vout)
        {
            isminetype mine = wallet->IsMine(txout);
            if(mine & ISMINE_WATCH_ONLY) involvesWatchAddress = true;
            if(fAllToMe > mine) fAllToMe = mine;
        }

        if(wtx.tx->IsSigmaMint() && !wtx.tx->IsSigmaSpend())
            fAllToMe = ISMINE_SPENDABLE;

        if (fAllFromMe && fAllToMe)
        {
            CAmount nChange = wtx.GetChange();
            if (wtx.tx->IsSigmaMint() || wtx.tx->IsZerocoinMint() || wtx.tx->IsLelantusMint())
            {
                // Mint to self
                parts.append(TransactionRecord(hash, nTime, TransactionRecord::Anonymize, "",
                    -(nDebit - nChange), 0));
            } else {
                // Payment to self
                parts.append(TransactionRecord(hash, nTime, TransactionRecord::SendToSelf, "",
                    -(nDebit - nChange), nCredit - nChange));
                parts.last().involvesWatchAddress = involvesWatchAddress;   // maybe pass to TransactionRecord as constructor argument
            }
        }
        else if (fAllFromMe)
        {
            //
            // Debit
            //
            CAmount nTxFee = nDebit - wtx.tx->GetValueOut();

            for (unsigned int nOut = 0; nOut < wtx.tx->vout.size(); nOut++)
            {
                const CTxOut& txout = wtx.tx->vout[nOut];
                TransactionRecord sub(hash, nTime);
                sub.idx = nOut;
                sub.involvesWatchAddress = involvesWatchAddress;

                if(wallet->IsMine(txout))
                {
                    // Ignore parts sent to self, as this is usually the change
                    // from a transaction sent back to our own address.
                    continue;
                }

                CTxDestination address;
                if(ExtractDestination(txout.scriptPubKey, address))
                {
                    // Sent to Bitcoin Address
                    sub.type = TransactionRecord::SendToAddress;
                    sub.address = CBitcoinAddress(address).ToString();
                    boost::optional<bip47::CPaymentCodeDescription> pcode = wallet->FindPcode(address);
                    if(pcode)
                    {
                        sub.type = TransactionRecord::SendToPcode;
                        sub.pcode = std::get<1>(*pcode).toString();
                    }
                }
                else if(wtx.tx->IsZerocoinMint() || wtx.tx->IsSigmaMint() || wtx.tx->IsLelantusMint())
                {
                    sub.type = TransactionRecord::Anonymize;
                }
                else
                {
                    // Sent to IP, or other non-address transaction like OP_EVAL
                    sub.type = TransactionRecord::SendToOther;
                    sub.address = mapValue["to"];
                }

                CAmount nValue = txout.nValue;
                /* Add fee to first output */
                if (nTxFee > 0)
                {
                    nValue += nTxFee;
                    nTxFee = 0;
                }
                sub.debit = -nValue;

                parts.append(sub);
            }
        }
        else
        {
            //
            // Mixed debit transaction, can't break down payees
            //
            parts.append(TransactionRecord(hash, nTime, TransactionRecord::Other, "", nNet, 0));
            parts.last().involvesWatchAddress = involvesWatchAddress;
        }
    }

    return parts;
}

void TransactionRecord::updateStatus(const CWalletTx &wtx)
{
    AssertLockHeld(cs_main);
    // Determine transaction status

    // Find the block the tx is in
    CBlockIndex* pindex = NULL;
    BlockMap::iterator mi = mapBlockIndex.find(wtx.hashBlock);
    if (mi != mapBlockIndex.end())
        pindex = (*mi).second;

    // Sort order, unrecorded transactions sort to the top
    status.sortKey = strprintf("%010d-%01d-%010u-%03d",
        (pindex ? pindex->nHeight : std::numeric_limits<int>::max()),
        (wtx.IsCoinBase() ? 1 : 0),
        wtx.nTimeReceived,
        idx);
    status.countsForBalance = wtx.IsTrusted() && !(wtx.GetBlocksToMaturity() > 0);
    status.depth = wtx.GetDepthInMainChain();
    status.cur_num_blocks = chainActive.Height();

    if (!CheckFinalTx(wtx))
    {
        if (wtx.tx->nLockTime < LOCKTIME_THRESHOLD)
        {
            status.status = TransactionStatus::OpenUntilBlock;
            status.open_for = wtx.tx->nLockTime - chainActive.Height();
        }
        else
        {
            status.status = TransactionStatus::OpenUntilDate;
            status.open_for = wtx.tx->nLockTime;
        }
    }
    // For generated transactions, determine maturity
    else if(type == TransactionRecord::Generated)
    {
        if (wtx.GetBlocksToMaturity() > 0)
        {
            status.status = TransactionStatus::Immature;

            if (wtx.IsInMainChain())
            {
                status.matures_in = wtx.GetBlocksToMaturity();

                // Check if the block was requested by anyone
                if (GetAdjustedTime() - wtx.nTimeReceived > 2 * 60 && wtx.GetRequestCount() == 0)
                    status.status = TransactionStatus::MaturesWarning;
            }
            else
            {
                status.status = TransactionStatus::NotAccepted;
            }
        }
        else
        {
            status.status = TransactionStatus::Confirmed;
        }
    }
    else
    {
        if (status.depth < 0)
        {
            status.status = TransactionStatus::Conflicted;
        }
        else if (GetAdjustedTime() - wtx.nTimeReceived > 2 * 60 && wtx.GetRequestCount() == 0)
        {
            status.status = TransactionStatus::Offline;
        }
        else if (status.depth == 0)
        {
            status.status = TransactionStatus::Unconfirmed;
            if (wtx.isAbandoned())
                status.status = TransactionStatus::Abandoned;
        }
        else if (status.depth < RecommendedNumConfirmations)
        {
            status.status = TransactionStatus::Confirming;
        }
        else
        {
            status.status = TransactionStatus::Confirmed;
        }
    }

}

bool TransactionRecord::statusUpdateNeeded()
{
    AssertLockHeld(cs_main);
    return status.cur_num_blocks != chainActive.Height();
}

QString TransactionRecord::getTxID() const
{
    return QString::fromStdString(hash.ToString());
}

int TransactionRecord::getOutputIndex() const
{
    return idx;
}
