#ifndef FIRO_ELYSIUM_ELYSIUM_H
#define FIRO_ELYSIUM_ELYSIUM_H

class CBlockIndex;
class CCoinsView;
class CCoinsViewCache;
class CTransaction;

#include "log.h"
#include "persistence.h"
#include "tally.h"

#include "../base58.h"
#include "../sync.h"
#include "../uint256.h"
#include "../util.h"

#include <univalue.h>

#include <boost/filesystem/path.hpp>

#include <leveldb/status.h>

#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include <inttypes.h>

using std::string;

int const MAX_STATE_HISTORY = 50;

constexpr size_t ELYSIUM_MAX_SIMPLE_MINTS = std::numeric_limits<uint8_t>::max();

// increment this value to force a refresh of the state (similar to --startclean)
#define DB_VERSION 6

// maximum size of string fields
#define SP_STRING_FIELD_LEN 256

// Elysium Transaction (Packet) Version
#define MP_TX_PKT_V0  0
#define MP_TX_PKT_V1  1
#define MP_TX_PKT_V2  2

#define MIN_PAYLOAD_SIZE     5

#define ELYSIUM_PROPERTY_TYPE_INDIVISIBLE             1
#define ELYSIUM_PROPERTY_TYPE_DIVISIBLE               2
#define ELYSIUM_PROPERTY_TYPE_INDIVISIBLE_REPLACING   65
#define ELYSIUM_PROPERTY_TYPE_DIVISIBLE_REPLACING     66
#define ELYSIUM_PROPERTY_TYPE_INDIVISIBLE_APPENDING   129
#define ELYSIUM_PROPERTY_TYPE_DIVISIBLE_APPENDING     130

enum FILETYPES {
  FILETYPE_BALANCES = 0,
  FILETYPE_GLOBALS,
  NUM_FILETYPES
};

#define PKT_RETURNED_OBJECT    (1000)

#define PKT_ERROR             ( -9000)
// Smart Properties
#define PKT_ERROR_SP          (-40000)
// Send To Owners
#define PKT_ERROR_STO         (-50000)
#define PKT_ERROR_SEND        (-60000)
#define PKT_ERROR_TOKENS      (-82000)
#define PKT_ERROR_SEND_ALL    (-83000)
#define PKT_ERROR_LELANTUS    (-85000)

#define ELYSIUM_PROPERTY_FIRO   0
#define ELYSIUM_PROPERTY_ELYSIUM   1
#define ELYSIUM_PROPERTY_TELYSIUM  2

// forward declarations
std::string FormatDivisibleMP(int64_t amount, bool fSign = false);
std::string FormatDivisibleShortMP(int64_t amount);
std::string FormatMP(uint32_t propertyId, int64_t amount, bool fSign = false);
std::string FormatShortMP(uint32_t propertyId, int64_t amount);
std::string FormatByType(int64_t amount, uint16_t propertyType);

//! Used to indicate, whether to automatically commit created transactions
extern bool autoCommit;

/** LevelDB based storage for storing Elysium transaction data.  This will become the new master database, holding serialized Elysium transactions.
 *  Note, intention is to consolidate and clean up data storage
 */
class CElysiumTransactionDB : public CDBBase
{
public:
    CElysiumTransactionDB(const boost::filesystem::path& path, bool fWipe)
    {
        leveldb::Status status = Open(path, fWipe);
        PrintToLog("Loading master transactions database: %s\n", status.ToString());
    }

    virtual ~CElysiumTransactionDB()
    {
        if (elysium_debug_persistence) PrintToLog("CElysiumTransactionDB closed\n");
    }

    /* These functions would be expanded upon to store a serialized version of the transaction and associated state data
     *
     * void RecordTransaction(const uint256& txid, uint32_t posInBlock, various, other, data);
     * int FetchTransactionPosition(const uint256& txid);
     * bool FetchTransactionValidity(const uint256& txid);
     *
     * and so on...
     */
    void RecordTransaction(const uint256& txid, uint32_t posInBlock, int processingResult);
    std::vector<std::string> FetchTransactionDetails(const uint256& txid);
    uint32_t FetchTransactionPosition(const uint256& txid);
    std::string FetchInvalidReason(const uint256& txid);
};

/** LevelDB based storage for STO recipients.
 */
class CMPSTOList : public CDBBase
{
public:
    CMPSTOList(const boost::filesystem::path& path, bool fWipe)
    {
        leveldb::Status status = Open(path, fWipe);
        PrintToLog("Loading send-to-owners database: %s\n", status.ToString());
    }

    virtual ~CMPSTOList()
    {
        if (elysium_debug_persistence) PrintToLog("CMPSTOList closed\n");
    }

    void getRecipients(const uint256 txid, string filterAddress, UniValue *recipientArray, uint64_t *total, uint64_t *numRecipients);
    std::string getMySTOReceipts(string filterAddress);
    int deleteAboveBlock(int blockNum);
    void printStats();
    void printAll();
    bool exists(string address);
    void recordSTOReceive(std::string, const uint256&, int, unsigned int, uint64_t);
};

/** LevelDB based storage for transactions, with txid as key and validity bit, and other data as value.
 */
class CMPTxList : public CDBBase
{
public:
    CMPTxList(const boost::filesystem::path& path, bool fWipe)
    {
        leveldb::Status status = Open(path, fWipe);
        PrintToLog("Loading tx meta-info database: %s\n", status.ToString());
    }

    virtual ~CMPTxList()
    {
        if (elysium_debug_persistence) PrintToLog("CMPTxList closed\n");
    }

    void recordTX(const uint256 &txid, bool fValid, int nBlock, unsigned int type, uint64_t nValue);
	/** Records a "send all" sub record. */
    void recordSendAllSubRecord(const uint256& txid, int subRecordNumber, uint32_t propertyId, int64_t nvalue);

    string getKeyValue(string key);
    /** Returns the number of sub records. */
    int getNumberOfSubRecords(const uint256& txid);
    bool getPurchaseDetails(const uint256 txid, int purchaseNumber, string *buyer, string *seller, uint64_t *vout, uint64_t *propertyId, uint64_t *nValue);
    /** Retrieves details about a "send all" record. */
    bool getSendAllDetails(const uint256& txid, int subSend, uint32_t& propertyId, int64_t& amount);
    int getMPTransactionCountTotal();
    int getMPTransactionCountBlock(int block);

    int getDBVersion();
    int setDBVersion();

    bool exists(const uint256 &txid);
    bool getTX(const uint256 &txid, string &value);

    std::set<int> GetSeedBlocks(int startHeight, int endHeight);
    void LoadAlerts(int blockHeight);
    void LoadActivations(int blockHeight);
    bool LoadFreezeState(int blockHeight);
    bool CheckForFreezeTxs(int blockHeight);

    void printStats();
    void printAll();

    bool isMPinBlockRange(int, int, bool);
};

//! Available balances of wallet properties
extern std::map<uint32_t, int64_t> global_balance_money;
//! Reserved balances of wallet propertiess
extern std::map<uint32_t, int64_t> global_balance_reserved;
//! Vector containing a list of properties relative to the wallet
extern std::set<uint32_t> global_wallet_property_list;

int64_t getMPbalance(const std::string& address, uint32_t propertyId, TallyType ttype);
int64_t getUserAvailableMPbalance(const std::string& address, uint32_t propertyId);
int64_t getUserFrozenMPbalance(const std::string& address, uint32_t propertyId);

bool isElysiumEnabled();

/** Global handler to initialize Elysium Core. */
int elysium_init();

/** Global handler to shut down Elysium Core. */
int elysium_shutdown();

/** Global handler to total wallet balances. */
void CheckWalletUpdate(bool forceUpdate = false);

/** Used to notify that the number of tokens for a property has changed. */
void NotifyTotalTokensChanged(uint32_t propertyId, int block);

int elysium_handler_disc_begin(int nBlockNow, CBlockIndex const * pBlockIndex);
int elysium_handler_disc_end(int nBlockNow, CBlockIndex const * pBlockIndex);
int elysium_handler_block_begin(int nBlockNow, CBlockIndex const * pBlockIndex);
int elysium_handler_block_end(int nBlockNow, CBlockIndex const * pBlockIndex, unsigned int);
bool elysium_handler_tx(const CTransaction& tx, int nBlock, unsigned int idx, const CBlockIndex* pBlockIndex);
int elysium_save_state( CBlockIndex const *pBlockIndex );

namespace elysium
{
extern std::unordered_map<std::string, CMPTally> mp_tally_map;
extern CMPTxList *p_txlistdb;
extern CMPSTOList *s_stolistdb;
extern CElysiumTransactionDB *p_ElysiumTXDB;

// TODO: move, rename
extern CCoinsView viewDummy;
extern CCoinsViewCache view;
//! Guards coins view cache

std::string strMPProperty(uint32_t propertyId);

bool isMPinBlockRange(int starting_block, int ending_block, bool bDeleteFound);

std::string FormatIndivisibleMP(int64_t n);

enum class InputMode {
    NORMAL,
    LELANTUS
};

int WalletTxBuilder(const std::string& senderAddress, const std::string& receiverAddress, const std::string& redemptionAddress,
                 int64_t referenceAmount, const std::vector<unsigned char>& data, uint256& txid, std::string& rawHex, bool commit,
                 InputMode inputMode = InputMode::NORMAL);

bool isTestEcosystemProperty(uint32_t propertyId);
bool isMainEcosystemProperty(uint32_t propertyId);
uint32_t GetNextPropertyId(bool maineco); // maybe move into sp

CMPTally* getTally(const std::string& address);

int64_t getTotalTokens(uint32_t propertyId, int64_t* n_owners_total = NULL);

std::string strTransactionType(uint16_t txType);

/** Determines, whether it is valid to use a Class C transaction for a given payload size. */
bool UseEncodingClassC(size_t nDataSize);

bool getValidMPTX(const uint256 &txid, int *block = NULL, unsigned int *type = NULL, uint64_t *nAmended = NULL);

bool update_tally_map(const std::string& who, uint32_t propertyId, int64_t amount, TallyType ttype);

std::string getTokenLabel(uint32_t propertyId);

/**
    NOTE: The following functions are only permitted for properties
          managed by a central issuer that have enabled freezing.
 **/
/** Adds an address and property to the frozenMap **/
void freezeAddress(const std::string& address, uint32_t propertyId);
/** Removes an address and property from the frozenMap **/
void unfreezeAddress(const std::string& address, uint32_t propertyId);
/** Checks whether an address and property are frozen **/
bool isAddressFrozen(const std::string& address, uint32_t propertyId);
/** Adds a property to the freezingEnabledMap **/
void enableFreezing(uint32_t propertyId, int liveBlock);
/** Removes a property from the freezingEnabledMap **/
void disableFreezing(uint32_t propertyId);
/** Checks whether a property has freezing enabled **/
bool isFreezingEnabled(uint32_t propertyId, int block);
/** Clears the freeze state in the event of a reorg **/
void ClearFreezeState();
/** Prints the freeze state **/
void PrintFreezeState();

}

#endif // FIRO_ELYSIUM_ELYSIUM_H
