/*
** 2001 September 15
**
** The author disclaims copyright to this source code.  In place of
** a legal notice, here is a blessing:
**
**    May you do good and not evil.
**    May you find forgiveness for yourself and forgive others.
**    May you share freely, never taking more than you give.
**
*************************************************************************
** This header file defines the interface that the sqlite B-Tree file
** subsystem.  See comments in the source code for a detailed description
** of what each interface routine does.
*/
#ifndef SQLITE_BTREE_H
#define SQLITE_BTREE_H

#ifdef __cplusplus
extern "C" {
#endif

/* TODO: This definition is just included so other modules compile. It
** needs to be revisited.
*/
#define SQLITE_N_BTREE_META 16

/*
** If defined as non-zero, auto-vacuum is enabled by default. Otherwise
** it must be turned on for each database using "PRAGMA auto_vacuum = 1".
*/
#ifndef SQLITE_DEFAULT_AUTOVACUUM
  #define SQLITE_DEFAULT_AUTOVACUUM 0
#endif

#define BTREE_AUTOVACUUM_NONE 0        /* Do not do auto-vacuum */
#define BTREE_AUTOVACUUM_FULL 1        /* Do full auto-vacuum */
#define BTREE_AUTOVACUUM_INCR 2        /* Incremental vacuum */

/*
** Forward declarations of structure
*/
typedef struct Btree Btree;
typedef struct BtCursor BtCursor;
typedef struct BtShared BtShared;
typedef struct BtreePayload BtreePayload;


int csqliteBtreeOpen(
  csqlite_vfs *pVfs,       /* VFS to use with this b-tree */
  const char *zFilename,   /* Name of database file to open */
  csqlite *db,             /* Associated database connection */
  Btree **ppBtree,         /* Return open Btree* here */
  int flags,               /* Flags */
  int vfsFlags             /* Flags passed through to VFS open */
);

/* The flags parameter to csqliteBtreeOpen can be the bitwise or of the
** following values.
**
** NOTE:  These values must match the corresponding PAGER_ values in
** pager.h.
*/
#define BTREE_OMIT_JOURNAL  1  /* Do not create or use a rollback journal */
#define BTREE_MEMORY        2  /* This is an in-memory DB */
#define BTREE_SINGLE        4  /* The file contains at most 1 b-tree */
#define BTREE_UNORDERED     8  /* Use of a hash implementation is OK */

int csqliteBtreeClose(Btree*);
int csqliteBtreeSetCacheSize(Btree*,int);
int csqliteBtreeSetSpillSize(Btree*,int);
#if SQLITE_MAX_MMAP_SIZE>0
  int csqliteBtreeSetMmapLimit(Btree*,csqlite_int64);
#endif
int csqliteBtreeSetPagerFlags(Btree*,unsigned);
int csqliteBtreeSetPageSize(Btree *p, int nPagesize, int nReserve, int eFix);
int csqliteBtreeGetPageSize(Btree*);
int csqliteBtreeMaxPageCount(Btree*,int);
u32 csqliteBtreeLastPage(Btree*);
int csqliteBtreeSecureDelete(Btree*,int);
int csqliteBtreeGetOptimalReserve(Btree*);
int csqliteBtreeGetReserveNoMutex(Btree *p);
int csqliteBtreeSetAutoVacuum(Btree *, int);
int csqliteBtreeGetAutoVacuum(Btree *);
int csqliteBtreeBeginTrans(Btree*,int,int*);
int csqliteBtreeCommitPhaseOne(Btree*, const char *zMaster);
int csqliteBtreeCommitPhaseTwo(Btree*, int);
int csqliteBtreeCommit(Btree*);
int csqliteBtreeRollback(Btree*,int,int);
int csqliteBtreeBeginStmt(Btree*,int);
int csqliteBtreeCreateTable(Btree*, int*, int flags);
int csqliteBtreeIsInTrans(Btree*);
int csqliteBtreeIsInReadTrans(Btree*);
int csqliteBtreeIsInBackup(Btree*);
void *csqliteBtreeSchema(Btree *, int, void(*)(void *));
int csqliteBtreeSchemaLocked(Btree *pBtree);
#ifndef SQLITE_OMIT_SHARED_CACHE
int csqliteBtreeLockTable(Btree *pBtree, int iTab, u8 isWriteLock);
#endif
int csqliteBtreeSavepoint(Btree *, int, int);

const char *csqliteBtreeGetFilename(Btree *);
const char *csqliteBtreeGetJournalname(Btree *);
int csqliteBtreeCopyFile(Btree *, Btree *);

int csqliteBtreeIncrVacuum(Btree *);

/* The flags parameter to csqliteBtreeCreateTable can be the bitwise OR
** of the flags shown below.
**
** Every SQLite table must have either BTREE_INTKEY or BTREE_BLOBKEY set.
** With BTREE_INTKEY, the table key is a 64-bit integer and arbitrary data
** is stored in the leaves.  (BTREE_INTKEY is used for SQL tables.)  With
** BTREE_BLOBKEY, the key is an arbitrary BLOB and no content is stored
** anywhere - the key is the content.  (BTREE_BLOBKEY is used for SQL
** indices.)
*/
#define BTREE_INTKEY     1    /* Table has only 64-bit signed integer keys */
#define BTREE_BLOBKEY    2    /* Table has keys only - no data */

int csqliteBtreeDropTable(Btree*, int, int*);
int csqliteBtreeClearTable(Btree*, int, int*);
int csqliteBtreeClearTableOfCursor(BtCursor*);
int csqliteBtreeTripAllCursors(Btree*, int, int);

void csqliteBtreeGetMeta(Btree *pBtree, int idx, u32 *pValue);
int csqliteBtreeUpdateMeta(Btree*, int idx, u32 value);

int csqliteBtreeNewDb(Btree *p);

/*
** The second parameter to csqliteBtreeGetMeta or csqliteBtreeUpdateMeta
** should be one of the following values. The integer values are assigned 
** to constants so that the offset of the corresponding field in an
** SQLite database header may be found using the following formula:
**
**   offset = 36 + (idx * 4)
**
** For example, the free-page-count field is located at byte offset 36 of
** the database file header. The incr-vacuum-flag field is located at
** byte offset 64 (== 36+4*7).
**
** The BTREE_DATA_VERSION value is not really a value stored in the header.
** It is a read-only number computed by the pager.  But we merge it with
** the header value access routines since its access pattern is the same.
** Call it a "virtual meta value".
*/
#define BTREE_FREE_PAGE_COUNT     0
#define BTREE_SCHEMA_VERSION      1
#define BTREE_FILE_FORMAT         2
#define BTREE_DEFAULT_CACHE_SIZE  3
#define BTREE_LARGEST_ROOT_PAGE   4
#define BTREE_TEXT_ENCODING       5
#define BTREE_USER_VERSION        6
#define BTREE_INCR_VACUUM         7
#define BTREE_APPLICATION_ID      8
#define BTREE_DATA_VERSION        15  /* A virtual meta-value */

/*
** Kinds of hints that can be passed into the csqliteBtreeCursorHint()
** interface.
**
** BTREE_HINT_RANGE  (arguments: Expr*, Mem*)
**
**     The first argument is an Expr* (which is guaranteed to be constant for
**     the lifetime of the cursor) that defines constraints on which rows
**     might be fetched with this cursor.  The Expr* tree may contain
**     TK_REGISTER nodes that refer to values stored in the array of registers
**     passed as the second parameter.  In other words, if Expr.op==TK_REGISTER
**     then the value of the node is the value in Mem[pExpr.iTable].  Any
**     TK_COLUMN node in the expression tree refers to the Expr.iColumn-th
**     column of the b-tree of the cursor.  The Expr tree will not contain
**     any function calls nor subqueries nor references to b-trees other than
**     the cursor being hinted.
**
**     The design of the _RANGE hint is aid b-tree implementations that try
**     to prefetch content from remote machines - to provide those
**     implementations with limits on what needs to be prefetched and thereby
**     reduce network bandwidth.
**
** Note that BTREE_HINT_FLAGS with BTREE_BULKLOAD is the only hint used by
** standard SQLite.  The other hints are provided for extentions that use
** the SQLite parser and code generator but substitute their own storage
** engine.
*/
#define BTREE_HINT_RANGE 0       /* Range constraints on queries */

/*
** Values that may be OR'd together to form the argument to the
** BTREE_HINT_FLAGS hint for csqliteBtreeCursorHint():
**
** The BTREE_BULKLOAD flag is set on index cursors when the index is going
** to be filled with content that is already in sorted order.
**
** The BTREE_SEEK_EQ flag is set on cursors that will get OP_SeekGE or
** OP_SeekLE opcodes for a range search, but where the range of entries
** selected will all have the same key.  In other words, the cursor will
** be used only for equality key searches.
**
*/
#define BTREE_BULKLOAD 0x00000001  /* Used to full index in sorted order */
#define BTREE_SEEK_EQ  0x00000002  /* EQ seeks only - no range seeks */

/* 
** Flags passed as the third argument to csqliteBtreeCursor().
**
** For read-only cursors the wrFlag argument is always zero. For read-write
** cursors it may be set to either (BTREE_WRCSR|BTREE_FORDELETE) or just
** (BTREE_WRCSR). If the BTREE_FORDELETE bit is set, then the cursor will
** only be used by SQLite for the following:
**
**   * to seek to and then delete specific entries, and/or
**
**   * to read values that will be used to create keys that other
**     BTREE_FORDELETE cursors will seek to and delete.
**
** The BTREE_FORDELETE flag is an optimization hint.  It is not used by
** by this, the native b-tree engine of SQLite, but it is available to
** alternative storage engines that might be substituted in place of this
** b-tree system.  For alternative storage engines in which a delete of
** the main table row automatically deletes corresponding index rows,
** the FORDELETE flag hint allows those alternative storage engines to
** skip a lot of work.  Namely:  FORDELETE cursors may treat all SEEK
** and DELETE operations as no-ops, and any READ operation against a
** FORDELETE cursor may return a null row: 0x01 0x00.
*/
#define BTREE_WRCSR     0x00000004     /* read-write cursor */
#define BTREE_FORDELETE 0x00000008     /* Cursor is for seek/delete only */

int csqliteBtreeCursor(
  Btree*,                              /* BTree containing table to open */
  int iTable,                          /* Index of root page */
  int wrFlag,                          /* 1 for writing.  0 for read-only */
  struct KeyInfo*,                     /* First argument to compare function */
  BtCursor *pCursor                    /* Space to write cursor structure */
);
BtCursor *csqliteBtreeFakeValidCursor(void);
int csqliteBtreeCursorSize(void);
void csqliteBtreeCursorZero(BtCursor*);
void csqliteBtreeCursorHintFlags(BtCursor*, unsigned);
#ifdef SQLITE_ENABLE_CURSOR_HINTS
void csqliteBtreeCursorHint(BtCursor*, int, ...);
#endif

int csqliteBtreeCloseCursor(BtCursor*);
int csqliteBtreeMovetoUnpacked(
  BtCursor*,
  UnpackedRecord *pUnKey,
  i64 intKey,
  int bias,
  int *pRes
);
int csqliteBtreeCursorHasMoved(BtCursor*);
int csqliteBtreeCursorRestore(BtCursor*, int*);
int csqliteBtreeDelete(BtCursor*, u8 flags);

/* Allowed flags for csqliteBtreeDelete() and csqliteBtreeInsert() */
#define BTREE_SAVEPOSITION 0x02  /* Leave cursor pointing at NEXT or PREV */
#define BTREE_AUXDELETE    0x04  /* not the primary delete operation */
#define BTREE_APPEND       0x08  /* Insert is likely an append */

/* An instance of the BtreePayload object describes the content of a single
** entry in either an index or table btree.
**
** Index btrees (used for indexes and also WITHOUT ROWID tables) contain
** an arbitrary key and no data.  These btrees have pKey,nKey set to the
** key and the pData,nData,nZero fields are uninitialized.  The aMem,nMem
** fields give an array of Mem objects that are a decomposition of the key.
** The nMem field might be zero, indicating that no decomposition is available.
**
** Table btrees (used for rowid tables) contain an integer rowid used as
** the key and passed in the nKey field.  The pKey field is zero.  
** pData,nData hold the content of the new entry.  nZero extra zero bytes
** are appended to the end of the content when constructing the entry.
** The aMem,nMem fields are uninitialized for table btrees.
**
** Field usage summary:
**
**               Table BTrees                   Index Btrees
**
**   pKey        always NULL                    encoded key
**   nKey        the ROWID                      length of pKey
**   pData       data                           not used
**   aMem        not used                       decomposed key value
**   nMem        not used                       entries in aMem
**   nData       length of pData                not used
**   nZero       extra zeros after pData        not used
**
** This object is used to pass information into csqliteBtreeInsert().  The
** same information used to be passed as five separate parameters.  But placing
** the information into this object helps to keep the interface more 
** organized and understandable, and it also helps the resulting code to
** run a little faster by using fewer registers for parameter passing.
*/
struct BtreePayload {
  const void *pKey;       /* Key content for indexes.  NULL for tables */
  csqlite_int64 nKey;     /* Size of pKey for indexes.  PRIMARY KEY for tabs */
  const void *pData;      /* Data for tables. */
  csqlite_value *aMem;    /* First of nMem value in the unpacked pKey */
  u16 nMem;               /* Number of aMem[] value.  Might be zero */
  int nData;              /* Size of pData.  0 if none. */
  int nZero;              /* Extra zero data appended after pData,nData */
};

int csqliteBtreeInsert(BtCursor*, const BtreePayload *pPayload,
                       int flags, int seekResult);
int csqliteBtreeFirst(BtCursor*, int *pRes);
#ifndef SQLITE_OMIT_WINDOWFUNC
void csqliteBtreeSkipNext(BtCursor*);
#endif
int csqliteBtreeLast(BtCursor*, int *pRes);
int csqliteBtreeNext(BtCursor*, int flags);
int csqliteBtreeEof(BtCursor*);
int csqliteBtreePrevious(BtCursor*, int flags);
i64 csqliteBtreeIntegerKey(BtCursor*);
#ifdef SQLITE_ENABLE_OFFSET_SQL_FUNC
i64 csqliteBtreeOffset(BtCursor*);
#endif
int csqliteBtreePayload(BtCursor*, u32 offset, u32 amt, void*);
const void *csqliteBtreePayloadFetch(BtCursor*, u32 *pAmt);
u32 csqliteBtreePayloadSize(BtCursor*);

char *csqliteBtreeIntegrityCheck(Btree*, int *aRoot, int nRoot, int, int*);
struct Pager *csqliteBtreePager(Btree*);
i64 csqliteBtreeRowCountEst(BtCursor*);

#ifndef SQLITE_OMIT_INCRBLOB
int csqliteBtreePayloadChecked(BtCursor*, u32 offset, u32 amt, void*);
int csqliteBtreePutData(BtCursor*, u32 offset, u32 amt, void*);
void csqliteBtreeIncrblobCursor(BtCursor *);
#endif
void csqliteBtreeClearCursor(BtCursor *);
int csqliteBtreeSetVersion(Btree *pBt, int iVersion);
int csqliteBtreeCursorHasHint(BtCursor*, unsigned int mask);
int csqliteBtreeIsReadonly(Btree *pBt);
int csqliteHeaderSizeBtree(void);

#ifndef NDEBUG
int csqliteBtreeCursorIsValid(BtCursor*);
#endif
int csqliteBtreeCursorIsValidNN(BtCursor*);

#ifndef SQLITE_OMIT_BTREECOUNT
int csqliteBtreeCount(BtCursor *, i64 *);
#endif

#ifdef SQLITE_TEST
int csqliteBtreeCursorInfo(BtCursor*, int*, int);
void csqliteBtreeCursorList(Btree*);
#endif

#ifndef SQLITE_OMIT_WAL
  int csqliteBtreeCheckpoint(Btree*, int, int *, int *);
#endif

/*
** If we are not using shared cache, then there is no need to
** use mutexes to access the BtShared structures.  So make the
** Enter and Leave procedures no-ops.
*/
#ifndef SQLITE_OMIT_SHARED_CACHE
  void csqliteBtreeEnter(Btree*);
  void csqliteBtreeEnterAll(csqlite*);
  int csqliteBtreeSharable(Btree*);
  void csqliteBtreeEnterCursor(BtCursor*);
  int csqliteBtreeConnectionCount(Btree*);
#else
# define csqliteBtreeEnter(X) 
# define csqliteBtreeEnterAll(X)
# define csqliteBtreeSharable(X) 0
# define csqliteBtreeEnterCursor(X)
# define csqliteBtreeConnectionCount(X) 1
#endif

#if !defined(SQLITE_OMIT_SHARED_CACHE) && SQLITE_THREADSAFE
  void csqliteBtreeLeave(Btree*);
  void csqliteBtreeLeaveCursor(BtCursor*);
  void csqliteBtreeLeaveAll(csqlite*);
#ifndef NDEBUG
  /* These routines are used inside assert() statements only. */
  int csqliteBtreeHoldsMutex(Btree*);
  int csqliteBtreeHoldsAllMutexes(csqlite*);
  int csqliteSchemaMutexHeld(csqlite*,int,Schema*);
#endif
#else

# define csqliteBtreeLeave(X)
# define csqliteBtreeLeaveCursor(X)
# define csqliteBtreeLeaveAll(X)

# define csqliteBtreeHoldsMutex(X) 1
# define csqliteBtreeHoldsAllMutexes(X) 1
# define csqliteSchemaMutexHeld(X,Y,Z) 1
#endif

// from vdbe.h

typedef int (*RecordCompare)(int,const void*,UnpackedRecord*);
  
#ifdef __cplusplus
}  /* end of the 'extern "C"' block */
#endif


#endif /* SQLITE_BTREE_H */
