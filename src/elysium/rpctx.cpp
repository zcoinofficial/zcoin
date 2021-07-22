#include "rpctx.h"

#include "createpayload.h"
#include "errors.h"
#include "elysium.h"
#include "pending.h"
#include "rpcrequirements.h"
#include "rpcvalues.h"
#include "rules.h"
#include "sp.h"
#include "tx.h"
#include "lelantusutils.h"
#include "utilsbitcoin.h"
#include "wallet.h"

#include "../init.h"
#include "../validation.h"
#include "../lelantus.h"
#include "../rpc/server.h"
#include "../sync.h"
#include "../wallet/wallet.h"
#include "../wallet/walletexcept.h"

#include <univalue.h>

#include <boost/function_output_iterator.hpp>
#include <boost/optional.hpp>

#include <stdexcept>
#include <string>

#include <inttypes.h>

using std::runtime_error;
using namespace elysium;


UniValue elysium_sendrawtx(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 5)
        throw runtime_error(
            "elysium_sendrawtx \"fromaddress\" \"rawtransaction\" ( \"referenceaddress\" \"redeemaddress\" \"referenceamount\" )\n"
            "\nBroadcasts a raw Elysium Layer transaction.\n"
            "\nArguments:\n"
            "1. fromaddress          (string, required) the address to send from\n"
            "2. rawtransaction       (string, required) the hex-encoded raw transaction\n"
            "3. referenceaddress     (string, optional) a reference address (none by default)\n"
            "4. redeemaddress        (string, optional) an address that can spent the transaction dust (sender by default)\n"
            "5. referenceamount      (string, optional) a firo amount that is sent to the receiver (minimal by default)\n"
            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"
            "\nExamples:\n"
            + HelpExampleCli("elysium_sendrawtx", "\"1MCHESTptvd2LnNp7wmr2sGTpRomteAkq8\" \"000000000000000100000000017d7840\" \"1EqTta1Rt8ixAA32DuC29oukbsSWU62qAV\"")
            + HelpExampleRpc("elysium_sendrawtx", "\"1MCHESTptvd2LnNp7wmr2sGTpRomteAkq8\", \"000000000000000100000000017d7840\", \"1EqTta1Rt8ixAA32DuC29oukbsSWU62qAV\"")
        );

    std::string fromAddress = ParseAddress(request.params[0]);
    std::vector<unsigned char> data = ParseHexV(request.params[1], "raw transaction");
    std::string toAddress = (request.params.size() > 2) ? ParseAddressOrEmpty(request.params[2]): "";
    std::string redeemAddress = (request.params.size() > 3) ? ParseAddressOrEmpty(request.params[3]): "";
    int64_t referenceAmount = (request.params.size() > 4) ? ParseAmount(request.params[4], true): 0;

    //some sanity checking of the data supplied?
    uint256 newTX;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, toAddress, redeemAddress, referenceAmount, data, newTX, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            return newTX.GetHex();
        }
    }
}


UniValue elysium_send(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 4 || request.params.size() > 6)
        throw runtime_error(
            "elysium_send \"fromaddress\" \"toaddress\" propertyid \"amount\" ( \"redeemaddress\" \"referenceamount\" )\n"

            "\nCreate and broadcast a simple send transaction.\n"

            "\nArguments:\n"
            "1. fromaddress          (string, required) the address to send from\n"
            "2. toaddress            (string, required) the address of the receiver\n"
            "3. propertyid           (number, required) the identifier of the tokens to send\n"
            "4. amount               (string, required) the amount to send\n"
            "5. redeemaddress        (string, optional) an address that can spend the transaction dust (sender by default)\n"
            "6. referenceamount      (string, optional) a firo amount that is sent to the receiver (minimal by default)\n"

            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"

            "\nExamples:\n"
            + HelpExampleCli("elysium_send", "\"3M9qvHKtgARhqcMtM5cRT9VaiDJ5PSfQGY\" \"37FaKponF7zqoMLUjEiko25pDiuVH5YLEa\" 1 \"100.0\"")
            + HelpExampleRpc("elysium_send", "\"3M9qvHKtgARhqcMtM5cRT9VaiDJ5PSfQGY\", \"37FaKponF7zqoMLUjEiko25pDiuVH5YLEa\", 1, \"100.0\"")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    std::string toAddress = ParseAddress(request.params[1]);
    uint32_t propertyId = ParsePropertyId(request.params[2]);
    int64_t amount = ParseAmount(request.params[3], isPropertyDivisible(propertyId));
    std::string redeemAddress = (request.params.size() > 4 && !ParseText(request.params[4]).empty()) ? ParseAddress(request.params[4]): "";
    int64_t referenceAmount = (request.params.size() > 5) ? ParseAmount(request.params[5], true): 0;

    // perform checks
    RequireExistingProperty(propertyId);
    RequireBalance(fromAddress, propertyId, amount);
    RequireSaneReferenceAmount(referenceAmount);

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_SimpleSend(propertyId, amount);

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, toAddress, redeemAddress, referenceAmount, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            PendingAdd(txid, fromAddress, ELYSIUM_TYPE_SIMPLE_SEND, propertyId, amount);
            return txid.GetHex();
        }
    }
}


UniValue elysium_sendall(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 3 || request.params.size() > 5)
        throw runtime_error(
            "elysium_sendall \"fromaddress\" \"toaddress\" ecosystem ( \"redeemaddress\" \"referenceamount\" )\n"

            "\nTransfers all available tokens in the given ecosystem to the recipient.\n"

            "\nArguments:\n"
            "1. fromaddress          (string, required) the address to send from\n"
            "2. toaddress            (string, required) the address of the receiver\n"
            "3. ecosystem            (number, required) the ecosystem of the tokens to send (1 for main ecosystem, 2 for test ecosystem)\n"
            "4. redeemaddress        (string, optional) an address that can spend the transaction dust (sender by default)\n"
            "5. referenceamount      (string, optional) a firo amount that is sent to the receiver (minimal by default)\n"

            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"

            "\nExamples:\n"
            + HelpExampleCli("elysium_sendall", "\"3M9qvHKtgARhqcMtM5cRT9VaiDJ5PSfQGY\" \"37FaKponF7zqoMLUjEiko25pDiuVH5YLEa\" 2")
            + HelpExampleRpc("elysium_sendall", "\"3M9qvHKtgARhqcMtM5cRT9VaiDJ5PSfQGY\", \"37FaKponF7zqoMLUjEiko25pDiuVH5YLEa\" 2")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    std::string toAddress = ParseAddress(request.params[1]);
    uint8_t ecosystem = ParseEcosystem(request.params[2]);
    std::string redeemAddress = (request.params.size() > 3 && !ParseText(request.params[3]).empty()) ? ParseAddress(request.params[3]): "";
    int64_t referenceAmount = (request.params.size() > 4) ? ParseAmount(request.params[4], true): 0;

    // perform checks
    RequireSaneReferenceAmount(referenceAmount);

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_SendAll(ecosystem);

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, toAddress, redeemAddress, referenceAmount, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            // TODO: pending
            return txid.GetHex();
        }
    }
}

UniValue elysium_sendissuancefixed(const JSONRPCRequest& request)
{
	
    if (request.fHelp || request.params.size() < 10 || request.params.size() > 11)
        throw runtime_error(
            "elysium_sendissuancefixed \"fromaddress\" ecosystem type previousid \"category\" \"subcategory\" \"name\" \"url\" \"data\" \"amount\" ( lelantus )\n"

            "\nCreate new tokens with fixed supply.\n"

            "\nArguments:\n"
            "1. fromaddress          (string, required) the address to send from\n"
            "2. ecosystem            (string, required) the ecosystem to create the tokens in (1 for main ecosystem, 2 for test ecosystem)\n"
            "3. type                 (number, required) the type of the tokens to create: (1 for indivisible tokens, 2 for divisible tokens)\n"
            "4. previousid           (number, required) an identifier of a predecessor token (use 0 for new tokens)\n"
            "5. category             (string, required) a category for the new tokens (can be \"\")\n"
            "6. subcategory          (string, required) a subcategory for the new tokens  (can be \"\")\n"
            "7. name                 (string, required) the name of the new tokens to create\n"
            "8. url                  (string, required) an URL for further information about the new tokens (can be \"\")\n"
            "9. data                 (string, required) a description for the new tokens (can be \"\")\n"
            "10. amount              (string, required) the number of tokens to create\n"
            "11. lelantus            (number, optional, default=0) flag to control lelantus feature for the new tokens: (0 for soft disabled, 1 for soft enabled, 2 for hard disabled, 3 for hard enabled)\n"

            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"

            "\nExamples:\n"
            + HelpExampleCli("elysium_sendissuancefixed", "\"aGoK6MF87K2SgT7cnJFhSWt7u2cAS5m18p\" 2 1 0 \"Companies\" \"Firo Mining\" \"Quantum Miner\" \"\" \"\" \"1000000\"")
            + HelpExampleRpc("elysium_sendissuancefixed", "\"aGoK6MF87K2SgT7cnJFhSWt7u2cAS5m18p\", 2, 1, 0, \"Companies\", \"Firo Mining\", \"Quantum Miner\", \"\", \"\", \"1000000\"")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    uint8_t ecosystem = ParseEcosystem(request.params[1]);
    uint16_t type = ParsePropertyType(request.params[2]);
    uint32_t previousId = ParsePreviousPropertyId(request.params[3]);
    std::string category = ParseText(request.params[4]);
    std::string subcategory = ParseText(request.params[5]);
    std::string name = ParseText(request.params[6]);
    std::string url = ParseText(request.params[7]);
    std::string data = ParseText(request.params[8]);
    int64_t amount = ParseAmount(request.params[9], type);
    boost::optional<LelantusStatus> lelantus;

    if (request.params.size() > 10) {
        lelantus = static_cast<LelantusStatus>(request.params[10].get_int());
    }

    // perform checks
    RequirePropertyName(name);

    if (lelantus) {
        RequireLelantusStatus(lelantus.get());
    }

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_IssuanceFixed(
        ecosystem,
        type,
        previousId,
        category,
        subcategory,
        name,
        url,
        data,
        amount,
        lelantus
    );

    // request the wallet build the transaction (and if needed commit it)
    auto& consensus = ConsensusParams();
    uint256 txid;
    std::string rawHex;
    std::string receiver;
    CAmount fee = 0;

    if (IsRequireCreationFee(ecosystem)) {
        receiver = consensus.PROPERTY_CREATION_FEE_RECEIVER.ToString();
        fee = consensus.PROPERTY_CREATION_FEE;
    }

    int result = WalletTxBuilder(fromAddress, receiver, "", fee, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            return txid.GetHex();
        }
    }
}


UniValue elysium_sendissuancemanaged(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 9 || request.params.size() > 10)
        throw runtime_error(
            "elysium_sendissuancemanaged \"fromaddress\" ecosystem type previousid \"category\" \"subcategory\" \"name\" \"url\" \"data\" ( lelantus )\n"

            "\nCreate new tokens with manageable supply.\n"

            "\nArguments:\n"
            "1. fromaddress          (string, required) the address to send from\n"
            "2. ecosystem            (string, required) the ecosystem to create the tokens in (1 for main ecosystem, 2 for test ecosystem)\n"
            "3. type                 (number, required) the type of the tokens to create: (1 for indivisible tokens, 2 for divisible tokens)\n"
            "4. previousid           (number, required) an identifier of a predecessor token (use 0 for new tokens)\n"
            "5. category             (string, required) a category for the new tokens (can be \"\")\n"
            "6. subcategory          (string, required) a subcategory for the new tokens  (can be \"\")\n"
            "7. name                 (string, required) the name of the new tokens to create\n"
            "8. url                  (string, required) an URL for further information about the new tokens (can be \"\")\n"
            "9. data                 (string, required) a description for the new tokens (can be \"\")\n"
            "10. lelantus            (number, optional, default=0) flag to control lelantus feature for the new tokens: (0 for soft disabled, 1 for soft enabled, 2 for hard disabled, 3 for hard enabled)\n"

            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"

            "\nExamples:\n"
            + HelpExampleCli("elysium_sendissuancemanaged", "\"aGoK6MF87K2SgT7cnJFhSWt7u2cAS5m18p\" 2 1 0 \"Companies\" \"Firo Mining\" \"Quantum Miner\" \"\" \"\"")
            + HelpExampleRpc("elysium_sendissuancemanaged", "\"aGoK6MF87K2SgT7cnJFhSWt7u2cAS5m18p\", 2, 1, 0, \"Companies\", \"Firo Mining\", \"Quantum Miner\", \"\", \"\"")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    uint8_t ecosystem = ParseEcosystem(request.params[1]);
    uint16_t type = ParsePropertyType(request.params[2]);
    uint32_t previousId = ParsePreviousPropertyId(request.params[3]);
    std::string category = ParseText(request.params[4]);
    std::string subcategory = ParseText(request.params[5]);
    std::string name = ParseText(request.params[6]);
    std::string url = ParseText(request.params[7]);
    std::string data = ParseText(request.params[8]);
    boost::optional<LelantusStatus> lelantus;

    if (request.params.size() > 9) {
        lelantus = static_cast<LelantusStatus>(request.params[9].get_int());
    }

    // perform checks
    RequirePropertyName(name);


    if (lelantus) {
        RequireLelantusStatus(lelantus.get());
    }

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_IssuanceManaged(
        ecosystem,
        type,
        previousId,
        category,
        subcategory,
        name,
        url,
        data,
        lelantus
    );

    // request the wallet build the transaction (and if needed commit it)
    auto& consensus = ConsensusParams();
    uint256 txid;
    std::string rawHex;
    std::string receiver;
    CAmount fee = 0;

    if (IsRequireCreationFee(ecosystem)) {
        receiver = consensus.PROPERTY_CREATION_FEE_RECEIVER.ToString();
        fee = consensus.PROPERTY_CREATION_FEE;
    }

    int result = WalletTxBuilder(fromAddress, receiver, "", fee, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            return txid.GetHex();
        }
    }
}

UniValue elysium_sendsto(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 3 || request.params.size() > 5)
        throw runtime_error(
            "elysium_sendsto \"fromaddress\" propertyid \"amount\" ( \"redeemaddress\" distributionproperty )\n"

            "\nCreate and broadcast a send-to-owners transaction.\n"

            "\nArguments:\n"
            "1. fromaddress            (string, required) the address to send from\n"
            "2. propertyid             (number, required) the identifier of the tokens to distribute\n"
            "3. amount                 (string, required) the amount to distribute\n"
            "4. redeemaddress          (string, optional) an address that can spend the transaction dust (sender by default)\n"
            "5. distributionproperty   (number, optional) the identifier of the property holders to distribute to\n"

            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"

            "\nExamples:\n"
            + HelpExampleCli("elysium_sendsto", "\"32Z3tJccZuqQZ4PhJR2hxHC3tjgjA8cbqz\" \"37FaKponF7zqoMLUjEiko25pDiuVH5YLEa\" 3 \"5000\"")
            + HelpExampleRpc("elysium_sendsto", "\"32Z3tJccZuqQZ4PhJR2hxHC3tjgjA8cbqz\", \"37FaKponF7zqoMLUjEiko25pDiuVH5YLEa\", 3, \"5000\"")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    uint32_t propertyId = ParsePropertyId(request.params[1]);
    int64_t amount = ParseAmount(request.params[2], isPropertyDivisible(propertyId));
    std::string redeemAddress = (request.params.size() > 3 && !ParseText(request.params[3]).empty()) ? ParseAddress(request.params[3]): "";
    uint32_t distributionPropertyId = (request.params.size() > 4) ? ParsePropertyId(request.params[4]) : propertyId;

    // perform checks
    RequireBalance(fromAddress, propertyId, amount);

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_SendToOwners(propertyId, amount, distributionPropertyId);

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, "", redeemAddress, 0, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            PendingAdd(txid, fromAddress, ELYSIUM_TYPE_SEND_TO_OWNERS, propertyId, amount);
            return txid.GetHex();
        }
    }
}


UniValue elysium_sendgrant(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 4 || request.params.size() > 5)
        throw runtime_error(
            "elysium_sendgrant \"fromaddress\" \"toaddress\" propertyid \"amount\" ( \"memo\" )\n"

            "\nIssue or grant new units of managed tokens.\n"

            "\nArguments:\n"
            "1. fromaddress          (string, required) the address to send from\n"
            "2. toaddress            (string, required) the receiver of the tokens (sender by default, can be \"\")\n"
            "3. propertyid           (number, required) the identifier of the tokens to grant\n"
            "4. amount               (string, required) the amount of tokens to create\n"
            "5. memo                 (string, optional) a text note attached to this transaction (none by default)\n"

            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"

            "\nExamples:\n"
            + HelpExampleCli("elysium_sendgrant", "\"3HsJvhr9qzgRe3ss97b1QHs38rmaLExLcH\" \"\" 51 \"7000\"")
            + HelpExampleRpc("elysium_sendgrant", "\"3HsJvhr9qzgRe3ss97b1QHs38rmaLExLcH\", \"\", 51, \"7000\"")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    std::string toAddress = !ParseText(request.params[1]).empty() ? ParseAddress(request.params[1]): "";
    uint32_t propertyId = ParsePropertyId(request.params[2]);
    int64_t amount = ParseAmount(request.params[3], isPropertyDivisible(propertyId));
    std::string memo = (request.params.size() > 4) ? ParseText(request.params[4]): "";

    // perform checks
    RequireExistingProperty(propertyId);
    RequireManagedProperty(propertyId);
    RequireTokenIssuer(fromAddress, propertyId);

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_Grant(propertyId, amount, memo);

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, toAddress, "", 0, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            return txid.GetHex();
        }
    }
}


UniValue elysium_sendrevoke(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 3 || request.params.size() > 4)
        throw runtime_error(
            "elysium_sendrevoke \"fromaddress\" propertyid \"amount\" ( \"memo\" )\n"

            "\nRevoke units of managed tokens.\n"

            "\nArguments:\n"
            "1. fromaddress          (string, required) the address to revoke the tokens from\n"
            "2. propertyid           (number, required) the identifier of the tokens to revoke\n"
            "3. amount               (string, required) the amount of tokens to revoke\n"
            "4. memo                 (string, optional) a text note attached to this transaction (none by default)\n"

            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"

            "\nExamples:\n"
            + HelpExampleCli("elysium_sendrevoke", "\"3HsJvhr9qzgRe3ss97b1QHs38rmaLExLcH\" \"\" 51 \"100\"")
            + HelpExampleRpc("elysium_sendrevoke", "\"3HsJvhr9qzgRe3ss97b1QHs38rmaLExLcH\", \"\", 51, \"100\"")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    uint32_t propertyId = ParsePropertyId(request.params[1]);
    int64_t amount = ParseAmount(request.params[2], isPropertyDivisible(propertyId));
    std::string memo = (request.params.size() > 3) ? ParseText(request.params[3]): "";

    // perform checks
    RequireExistingProperty(propertyId);
    RequireManagedProperty(propertyId);
    RequireTokenIssuer(fromAddress, propertyId);
    RequireBalance(fromAddress, propertyId, amount);

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_Revoke(propertyId, amount, memo);

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, "", "", 0, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            return txid.GetHex();
        }
    }
}

UniValue elysium_sendchangeissuer(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 3)
        throw runtime_error(
            "elysium_sendchangeissuer \"fromaddress\" \"toaddress\" propertyid\n"

            "\nChange the issuer on record of the given tokens.\n"

            "\nArguments:\n"
            "1. fromaddress          (string, required) the address associated with the tokens\n"
            "2. toaddress            (string, required) the address to transfer administrative control to\n"
            "3. propertyid           (number, required) the identifier of the tokens\n"

            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"

            "\nExamples:\n"
            + HelpExampleCli("elysium_sendchangeissuer", "\"1ARjWDkZ7kT9fwjPrjcQyvbXDkEySzKHwu\" \"3HTHRxu3aSDV4deakjC7VmsiUp7c6dfbvs\" 3")
            + HelpExampleRpc("elysium_sendchangeissuer", "\"1ARjWDkZ7kT9fwjPrjcQyvbXDkEySzKHwu\", \"3HTHRxu3aSDV4deakjC7VmsiUp7c6dfbvs\", 3")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    std::string toAddress = ParseAddress(request.params[1]);
    uint32_t propertyId = ParsePropertyId(request.params[2]);

    // perform checks
    RequireExistingProperty(propertyId);
    RequireTokenIssuer(fromAddress, propertyId);

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_ChangeIssuer(propertyId);

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, toAddress, "", 0, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            return txid.GetHex();
        }
    }
}


UniValue elysium_sendenablefreezing(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw runtime_error(
            "elysium_sendenablefreezing \"fromaddress\" propertyid\n"

            "\nEnables address freezing for a centrally managed property.\n"

            "\nArguments:\n"
            "1. fromaddress          (string,  required) the issuer of the tokens\n"
            "2. propertyid           (number,  required) the identifier of the tokens\n"

            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"

            "\nExamples:\n"
            + HelpExampleCli("elysium_sendenablefreezing", "\"3HTHRxu3aSDV4deakjC7VmsiUp7c6dfbvs\" 3")
            + HelpExampleRpc("elysium_sendenablefreezing", "\"3HTHRxu3aSDV4deakjC7VmsiUp7c6dfbvs\", 3")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    uint32_t propertyId = ParsePropertyId(request.params[1]);

    // perform checks
    RequireExistingProperty(propertyId);
    RequireManagedProperty(propertyId);
    RequireTokenIssuer(fromAddress, propertyId);

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_EnableFreezing(propertyId);

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, "", "", 0, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            return txid.GetHex();
        }
    }
}


UniValue elysium_senddisablefreezing(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw runtime_error(
            "elysium_senddisablefreezing \"fromaddress\" propertyid\n"

            "\nDisables address freezing for a centrally managed property.\n"
            "\nIMPORTANT NOTE:  Disabling freezing for a property will UNFREEZE all frozen addresses for that property!"

            "\nArguments:\n"
            "1. fromaddress          (string,  required) the issuer of the tokens\n"
            "2. propertyid           (number,  required) the identifier of the tokens\n"

            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"

            "\nExamples:\n"
            + HelpExampleCli("elysium_senddisablefreezing", "\"3HTHRxu3aSDV4deakjC7VmsiUp7c6dfbvs\" 3")
            + HelpExampleRpc("elysium_senddisablefreezing", "\"3HTHRxu3aSDV4deakjC7VmsiUp7c6dfbvs\", 3")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    uint32_t propertyId = ParsePropertyId(request.params[1]);

    // perform checks
    RequireExistingProperty(propertyId);
    RequireManagedProperty(propertyId);
    RequireTokenIssuer(fromAddress, propertyId);

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_DisableFreezing(propertyId);

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, "", "", 0, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            return txid.GetHex();
        }
    }
}


UniValue elysium_sendfreeze(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 4)
        throw runtime_error(
            "elysium_sendfreeze \"fromaddress\" \"toaddress\" propertyid amount \n"
            "\nFreeze an address for a centrally managed token.\n"
            "\nNote: Only the issuer may freeze tokens, and only if the token is of the managed type with the freezing option enabled.\n"
            "\nArguments:\n"
            "1. fromaddress          (string, required) the address to send from (must be the issuer of the property)\n"
            "2. toaddress            (string, required) the address to freeze tokens for\n"
            "3. propertyid           (number, required) the property to freeze tokens for (must be managed type and have freezing option enabled)\n"
            "4. amount               (number, required) the amount of tokens to freeze (note: this is unused - once frozen an address cannot send any transactions for the property)\n"
            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"
            "\nExamples:\n"
            + HelpExampleCli("elysium_sendfreeze", "\"1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P\" \"3HTHRxu3aSDV4deakjC7VmsiUp7c6dfbvs\" 1 0")
            + HelpExampleRpc("elysium_sendfreeze", "\"1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P\", \"3HTHRxu3aSDV4deakjC7VmsiUp7c6dfbvs\", 1, 0")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    std::string refAddress = ParseAddress(request.params[1]);
    uint32_t propertyId = ParsePropertyId(request.params[2]);
    int64_t amount = ParseAmount(request.params[3], isPropertyDivisible(propertyId));

    // perform checks
    RequireExistingProperty(propertyId);
    RequireManagedProperty(propertyId);
    RequireTokenIssuer(fromAddress, propertyId);

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_FreezeTokens(propertyId, amount, refAddress);

    // request the wallet build the transaction (and if needed commit it)
    // Note: no ref address is sent to WalletTxBuilder as the ref address is contained within the payload
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, "", "", 0, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            return txid.GetHex();
        }
    }
}


UniValue elysium_sendunfreeze(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 4)
        throw runtime_error(
            "elysium_sendunfreeze \"fromaddress\" \"toaddress\" propertyid amount \n"
            "\nUnfreezes an address for a centrally managed token.\n"
            "\nNote: Only the issuer may unfreeze tokens.\n"
            "\nArguments:\n"
            "1. fromaddress          (string, required) the address to send from (must be the issuer of the property)\n"
            "2. toaddress            (string, required) the address to unfreeze tokens for\n"
            "3. propertyid           (number, required) the property to unfreeze tokens for (must be managed type and have freezing option enabled)\n"
            "4. amount               (number, required) the amount of tokens to unfreeze (note: this is unused - once frozen an address cannot send any transactions for the property)\n"
            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"
            "\nExamples:\n"
            + HelpExampleCli("elysium_sendunfreeze", "\"1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P\" \"3HTHRxu3aSDV4deakjC7VmsiUp7c6dfbvs\" 1 0")
            + HelpExampleRpc("elysium_sendunfreeze", "\"1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P\", \"3HTHRxu3aSDV4deakjC7VmsiUp7c6dfbvs\", 1, 0")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    std::string refAddress = ParseAddress(request.params[1]);
    uint32_t propertyId = ParsePropertyId(request.params[2]);
    int64_t amount = ParseAmount(request.params[3], isPropertyDivisible(propertyId));

    // perform checks
    RequireExistingProperty(propertyId);
    RequireManagedProperty(propertyId);
    RequireTokenIssuer(fromAddress, propertyId);

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_UnfreezeTokens(propertyId, amount, refAddress);

    // request the wallet build the transaction (and if needed commit it)
    // Note: no ref address is sent to WalletTxBuilder as the ref address is contained within the payload
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, "", "", 0, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            return txid.GetHex();
        }
    }
}


UniValue elysium_sendactivation(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 4)
        throw runtime_error(
            "elysium_sendactivation \"fromaddress\" featureid block minclientversion\n"
            "\nActivate a protocol feature.\n"
            "\nNote: Elysium Core ignores activations from unauthorized sources.\n"
            "\nArguments:\n"
            "1. fromaddress          (string, required) the address to send from\n"
            "2. featureid            (number, required) the identifier of the feature to activate\n"
            "3. block                (number, required) the activation block\n"
            "4. minclientversion     (number, required) the minimum supported client version\n"
            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"
            "\nExamples:\n"
            + HelpExampleCli("elysium_sendactivation", "\"1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P\" 1 370000 999")
            + HelpExampleRpc("elysium_sendactivation", "\"1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P\", 1, 370000, 999")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    uint16_t featureId = request.params[1].get_int();
    uint32_t activationBlock = request.params[2].get_int();
    uint32_t minClientVersion = request.params[3].get_int();

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_ActivateFeature(featureId, activationBlock, minClientVersion);

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, "", "", 0, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            return txid.GetHex();
        }
    }
}


UniValue elysium_senddeactivation(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw runtime_error(
            "elysium_senddeactivation \"fromaddress\" featureid\n"
            "\nDeactivate a protocol feature.  For Emergency Use Only.\n"
            "\nNote: Elysium Core ignores deactivations from unauthorized sources.\n"
            "\nArguments:\n"
            "1. fromaddress          (string, required) the address to send from\n"
            "2. featureid            (number, required) the identifier of the feature to activate\n"
            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"
            "\nExamples:\n"
            + HelpExampleCli("elysium_senddeactivation", "\"1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P\" 1")
            + HelpExampleRpc("elysium_senddeactivation", "\"1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P\", 1")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    uint16_t featureId = request.params[1].get_int64();

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_DeactivateFeature(featureId);

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, "", "", 0, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            return txid.GetHex();
        }
    }
}


UniValue elysium_sendalert(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 4)
        throw runtime_error(
            "elysium_sendalert \"fromaddress\" alerttype expiryvalue typecheck versioncheck \"message\"\n"
            "\nCreates and broadcasts an Elysium Core alert.\n"
            "\nNote: Elysium Core ignores alerts from unauthorized sources.\n"
            "\nArguments:\n"
            "1. fromaddress          (string, required) the address to send from\n"
            "2. alerttype            (number, required) the alert type\n"
            "3. expiryvalue          (number, required) the value when the alert expires (depends on alert type)\n"
            "4. message              (string, required) the user-faced alert message\n"
            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"
            "\nExamples:\n"
            + HelpExampleCli("elysium_sendalert", "")
            + HelpExampleRpc("elysium_sendalert", "")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    int64_t tempAlertType = request.params[1].get_int64();
    if (tempAlertType < 1 || 65535 < tempAlertType) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Alert type is out of range");
    }
    uint16_t alertType = static_cast<uint16_t>(tempAlertType);
    int64_t tempExpiryValue = request.params[2].get_int64();
    if (tempExpiryValue < 1 || 4294967295LL < tempExpiryValue) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Expiry value is out of range");
    }
    uint32_t expiryValue = static_cast<uint32_t>(tempExpiryValue);
    std::string alertMessage = ParseText(request.params[3]);

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_ElysiumAlert(alertType, expiryValue, alertMessage);

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, "", "", 0, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            return txid.GetHex();
        }
    }
}

UniValue elysium_sendlelantusmint(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 3 || request.params.size() > 4) {
        throw std::runtime_error(
            "elysium_sendlelantusmint \"fromaddress\" propertyid amount\n"
            "\nCreate mints.\n"
            "\nArguments:\n"
            "1. fromaddress                  (string, required) the address to send from\n"
            "2. propertyid                   (number, required) the property to create mints\n"
            "3. amount                       (number, required) amount to mint\n"
            "\nResult:\n"
            "\"hash\"                          (string) the hex-encoded transaction hash\n"
            "\nExamples:\n"
            + HelpExampleCli("elysium_sendmint", "\"3M9qvHKtgARhqcMtM5cRT9VaiDJ5PSfQGY\" 1 100")
            + HelpExampleRpc("elysium_sendmint", "\"3M9qvHKtgARhqcMtM5cRT9VaiDJ5PSfQGY\", 1, 100")
        );
    }

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    uint32_t propertyId = ParsePropertyId(request.params[1]);

    // perform checks
    RequireExistingProperty(propertyId);
    RequireLelantus(propertyId);

    int64_t amount = ParseAmount(request.params[2], isPropertyDivisible(propertyId));

    RequireBalance(fromAddress, propertyId, amount);

    auto mint = wallet->CreateLelantusMint(propertyId, amount);
    auto coin = mint.coin;

    CDataStream  serializedSchnorrProof(SER_NETWORK, PROTOCOL_VERSION);
    lelantus::GenerateMintSchnorrProof(coin, serializedSchnorrProof);

    uint256 txid;
    std::string rawHex;

    auto payload = CreatePayload_CreateLelantusMint(propertyId, coin.getPublicCoin(), mint.id, amount, {serializedSchnorrProof.begin(), serializedSchnorrProof.end()});
    auto result = WalletTxBuilder(fromAddress, "", "", 0, payload, txid, rawHex, autoCommit);

    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    }

    // success then commit
    mint.Commit();

    if (!autoCommit) {
        return rawHex;
    } else {
        PendingAdd(txid, fromAddress, ELYSIUM_TYPE_LELANTUS_MINT, propertyId, amount);
        return txid.GetHex();
    }
}

UniValue elysium_sendlelantusspend(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 3 || request.params.size() > 4) {
        throw std::runtime_error(
            "elysium_sendlelantusspend \"toaddress\" propertyid amount ( \"referenceamount\" )\n"
            "\nCreate spend.\n"
            "\nArguments:\n"
            "1. toaddress                    (string, required) the address to spend to\n"
            "2. propertyid                   (number, required) the property to spend\n"
            "3. amount                       (number, required) the amount to spend\n"
            "4. referenceamount              (string, optional) a firo amount that is sent to the receiver (minimal by default)\n"
            "\nResult:\n"
            "\"hash\"                          (string) the hex-encoded transaction hash\n"
            "\nExamples:\n"
            + HelpExampleCli("elysium_sendlelantusspend", "\"3M9qvHKtgARhqcMtM5cRT9VaiDJ5PSfQGY\" 1 1")
            + HelpExampleRpc("elysium_sendlelantusspend", "\"3M9qvHKtgARhqcMtM5cRT9VaiDJ5PSfQGY\", 1, 1")
        );
    }

    // obtain parameters & info
    auto toAddress = ParseAddress(request.params[0]);
    auto propertyId = ParsePropertyId(request.params[1]);
    auto amount = ParseAmount(request.params[2], isPropertyDivisible(propertyId));
    auto referenceAmount = (request.params.size() > 3) ? ParseAmount(request.params[3], true): 0;

    // perform checks
    RequireExistingProperty(propertyId);
    RequireSaneReferenceAmount(referenceAmount);
    RequireLelantus(propertyId);

    // create spend
    std::vector<unsigned char> payload;

    // calculate reference amount
    CBitcoinAddress address(toAddress);
    if (referenceAmount <= 0) {
        CScript scriptPubKey = GetScriptForDestination(CBitcoinAddress(address).Get());
        referenceAmount = GetDustThreshold(scriptPubKey);
    }

    auto metaData = PrepareSpendMetadata(address, referenceAmount);

    std::vector<SpendableCoin> spendables;
    boost::optional<LelantusWallet::MintReservation> reservation;
    LelantusAmount changeValue = 0;

    try {
        auto joinSplit = wallet->CreateLelantusJoinSplit(propertyId, amount, metaData, spendables, reservation, changeValue);

        boost::optional<JoinSplitMint> joinSplitMint;
        if (reservation.get_ptr() != nullptr) {
            auto pub = reservation->coin.getPublicCoin();
            EncryptedValue enc;
            EncryptMintAmount(changeValue, pub.getValue(), enc);

            joinSplitMint = JoinSplitMint(
                reservation->id,
                pub,
                enc
            );
        }

        payload = CreatePayload_CreateLelantusJoinSplit(
            propertyId, amount, joinSplit, joinSplitMint);

    } catch (InsufficientFunds& e) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, e.what());
    } catch (WalletError &e) {
        throw JSONRPCError(RPC_WALLET_ERROR, e.what());
    }

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(
        "",
        toAddress,
        "",
        referenceAmount,
        payload,
        txid,
        rawHex,
        autoCommit,
        InputMode::LELANTUS
    );

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        // mark the coin as used
        for (auto const &s : spendables) {
            wallet->SetLelantusMintUsedTransaction(s.id, txid);
        }

        if (reservation.get_ptr() != nullptr) {
            reservation->Commit();
        }

        if (!autoCommit) {
            return rawHex;
        } else {
            PendingAdd(
                txid,
                "Lelantus Joinsplit",
				ELYSIUM_TYPE_LELANTUS_JOINSPLIT,
                propertyId,
                amount,
                false,
                toAddress);
            return txid.GetHex();
        }
    }
}


UniValue elysium_sendchangelelantusstatus(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 3)
        throw runtime_error(
            "elysium_sendchangelelantusstatus \"fromaddress\" propertyid status\n"

            "\nChange lelantus status on record of the given tokens.\n"

            "\nArguments:\n"
            "1. fromaddress          (string, required) the address associated with the tokens\n"
            "2. propertyid           (number, required) the identifier of the tokens\n"
            "2. status               (number, required) the status that need to change to (0 for soft disabled, 1 for soft enabled, 2 for hard disabled, 3 for hard enabled)\n"

            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"

            "\nExamples:\n"
            + HelpExampleCli("elysium_sendchangelelantusstatus", "\"1ARjWDkZ7kT9fwjPrjcQyvbXDkEySzKHwu\" \"3HTHRxu3aSDV4deakjC7VmsiUp7c6dfbvs\" 3")
            + HelpExampleRpc("elysium_sendchangelelantusstatus", "\"1ARjWDkZ7kT9fwjPrjcQyvbXDkEySzKHwu\", \"3HTHRxu3aSDV4deakjC7VmsiUp7c6dfbvs\", 3")
        );

    // obtain parameters & info
    auto fromAddress = ParseAddress(request.params[0]);
    auto propertyId = ParsePropertyId(request.params[1]);
    auto status = static_cast<LelantusStatus>(request.params[2].get_int());

    // perform checks
    RequireExistingProperty(propertyId);
    RequireTokenIssuer(fromAddress, propertyId);

    if (!IsFeatureActivated(FEATURE_LELANTUS, GetHeight())) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Lelantus feature is not activated yet");
    }

    if (!elysium::IsLelantusStatusUpdatable(propertyId)) {
        throw JSONRPCError(RPC_INVALID_REQUEST, "The property is not allowed to update lelantus status");
    }

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_ChangeLelantusStatus(propertyId, status);

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, "", "", 0, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            return txid.GetHex();
        }
    }
}


static const CRPCCommand commands[] =
{ //  category                             name                            actor (function)               okSafeMode
  //  ------------------------------------ ------------------------------- ------------------------------ ----------
    { "elysium (transaction creation)",  "elysium_sendrawtx",                 &elysium_sendrawtx,                  false },
    { "elysium (transaction creation)",  "elysium_send",                      &elysium_send,                       false },
    { "elysium (transaction creation)",  "elysium_sendissuancefixed",         &elysium_sendissuancefixed,          false },
    { "elysium (transaction creation)",  "elysium_sendissuancemanaged",       &elysium_sendissuancemanaged,        false },
    { "elysium (transaction creation)",  "elysium_sendsto",                   &elysium_sendsto,                    false },
    { "elysium (transaction creation)",  "elysium_sendgrant",                 &elysium_sendgrant,                  false },
    { "elysium (transaction creation)",  "elysium_sendrevoke",                &elysium_sendrevoke,                 false },
    { "elysium (transaction creation)",  "elysium_sendchangeissuer",          &elysium_sendchangeissuer,           false },
    { "hidden",                          "elysium_sendall",                   &elysium_sendall,                    false },
    { "hidden",                          "elysium_sendenablefreezing",        &elysium_sendenablefreezing,         false },
    { "hidden",                          "elysium_senddisablefreezing",       &elysium_senddisablefreezing,        false },
    { "hidden",                          "elysium_sendfreeze",                &elysium_sendfreeze,                 false },
    { "hidden",                          "elysium_sendunfreeze",              &elysium_sendunfreeze,               false },
    { "hidden",                          "elysium_senddeactivation",          &elysium_senddeactivation,           true  },
    { "hidden",                          "elysium_sendactivation",            &elysium_sendactivation,             false },
    { "hidden",                          "elysium_sendalert",                 &elysium_sendalert,                  true  },
    { "elysium (transaction creation)",  "elysium_sendlelantusmint",          &elysium_sendlelantusmint,           false },
    { "elysium (transaction creation)",  "elysium_sendlelantusspend",         &elysium_sendlelantusspend,          false },
    { "elysium (transaction creation)",  "elysium_sendchangelelantusstatus",  &elysium_sendchangelelantusstatus,   false },

    /* depreciated: */
    { "hidden",                          "sendrawtx_MP",                      &elysium_sendrawtx,                  false },
    { "hidden",                          "send_MP",                           &elysium_send,                       false },
    { "hidden",                          "sendtoowners_MP",                   &elysium_sendsto,                    false },
};

void RegisterElysiumTransactionCreationRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
