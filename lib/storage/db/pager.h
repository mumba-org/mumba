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
** This header file defines the interface that the sqlite page cache
** subsystem.  The page cache subsystem reads and writes a file a page
** at a time and provides a journal for rollback.
*/

#ifndef SQLITE_PAGER_H
#define SQLITE_PAGER_H

#ifdef __cplusplus
extern "C" {
#endif

/*
** Default maximum size for persistent journal files. A negative 
** value means no limit. This value may be overridden using the 
** csqlitePagerJournalSizeLimit() API. See also "PRAGMA journal_size_limit".
*/
#ifndef SQLITE_DEFAULT_JOURNAL_SIZE_LIMIT
  #define SQLITE_DEFAULT_JOURNAL_SIZE_LIMIT -1
#endif

/*
** The type used to represent a page number.  The first page in a file
** is called page 1.  0 is used to represent "not a page".
*/
typedef u32 Pgno;

/*
** Each open file is managed by a separate instance of the "Pager" structure.
*/
typedef struct Pager Pager;

/*
** Handle type for pages.
*/
typedef struct PgHdr DbPage;

/*
** Page number PAGER_MJ_PGNO is never used in an SQLite database (it is
** reserved for working around a windows/posix incompatibility). It is
** used in the journal to signify that the remainder of the journal file 
** is devoted to storing a master journal name - there are no more pages to
** roll back. See comments for function writeMasterJournal() in pager.c 
** for details.
*/
#define PAGER_MJ_PGNO(x) ((Pgno)((PENDING_BYTE/((x)->pageSize))+1))

/*
** Allowed values for the flags parameter to csqlitePagerOpen().
**
** NOTE: These values must match the corresponding BTREE_ values in btree.h.
*/
#define PAGER_OMIT_JOURNAL  0x0001    /* Do not use a rollback journal */
#define PAGER_MEMORY        0x0002    /* In-memory database */

/*
** Valid values for the second argument to csqlitePagerLockingMode().
*/
#define PAGER_LOCKINGMODE_QUERY      -1
#define PAGER_LOCKINGMODE_NORMAL      0
#define PAGER_LOCKINGMODE_EXCLUSIVE   1

/*
** Numeric constants that encode the journalmode.
**
** The numeric values encoded here (other than PAGER_JOURNALMODE_QUERY)
** are exposed in the API via the "PRAGMA journal_mode" command and
** therefore cannot be changed without a compatibility break.
*/
#define PAGER_JOURNALMODE_QUERY     (-1)  /* Query the value of journalmode */
#define PAGER_JOURNALMODE_DELETE      0   /* Commit by deleting journal file */
#define PAGER_JOURNALMODE_PERSIST     1   /* Commit by zeroing journal header */
#define PAGER_JOURNALMODE_OFF         2   /* Journal omitted.  */
#define PAGER_JOURNALMODE_TRUNCATE    3   /* Commit by truncating journal */
#define PAGER_JOURNALMODE_MEMORY      4   /* In-memory journal file */
#define PAGER_JOURNALMODE_WAL         5   /* Use write-ahead logging */

/*
** Flags that make up the mask passed to csqlitePagerGet().
*/
#define PAGER_GET_NOCONTENT     0x01  /* Do not load data from disk */
#define PAGER_GET_READONLY      0x02  /* Read-only page is acceptable */

/*
** Flags for csqlitePagerSetFlags()
**
** Value constraints (enforced via assert()):
**    PAGER_FULLFSYNC      == SQLITE_FullFSync
**    PAGER_CKPT_FULLFSYNC == SQLITE_CkptFullFSync
**    PAGER_CACHE_SPILL    == SQLITE_CacheSpill
*/
#define PAGER_SYNCHRONOUS_OFF       0x01  /* PRAGMA synchronous=OFF */
#define PAGER_SYNCHRONOUS_NORMAL    0x02  /* PRAGMA synchronous=NORMAL */
#define PAGER_SYNCHRONOUS_FULL      0x03  /* PRAGMA synchronous=FULL */
#define PAGER_SYNCHRONOUS_EXTRA     0x04  /* PRAGMA synchronous=EXTRA */
#define PAGER_SYNCHRONOUS_MASK      0x07  /* Mask for four values above */
#define PAGER_FULLFSYNC             0x08  /* PRAGMA fullfsync=ON */
#define PAGER_CKPT_FULLFSYNC        0x10  /* PRAGMA checkpoint_fullfsync=ON */
#define PAGER_CACHESPILL            0x20  /* PRAGMA cache_spill=ON */
#define PAGER_FLAGS_MASK            0x38  /* All above except SYNCHRONOUS */

/*
** The remainder of this file contains the declarations of the functions
** that make up the Pager sub-system API. See source code comments for 
** a detailed description of each routine.
*/

/* Open and close a Pager connection. */ 
int csqlitePagerOpen(
  csqlite_vfs*,
  Pager **ppPager,
  const char*,
  int,
  int,
  int,
  void(*)(DbPage*)
);
int csqlitePagerClose(Pager *pPager, csqlite*);
int csqlitePagerReadFileheader(Pager*, int, unsigned char*);

/* Functions used to configure a Pager object. */
void csqlitePagerSetBusyHandler(Pager*, int(*)(void *), void *);
int csqlitePagerSetPagesize(Pager*, u32*, int);
#ifdef SQLITE_HAS_CODEC
void csqlitePagerAlignReserve(Pager*,Pager*);
#endif
int csqlitePagerMaxPageCount(Pager*, int);
void csqlitePagerSetCachesize(Pager*, int);
int csqlitePagerSetSpillsize(Pager*, int);
void csqlitePagerSetMmapLimit(Pager *, csqlite_int64);
void csqlitePagerShrink(Pager*);
void csqlitePagerSetFlags(Pager*,unsigned);
int csqlitePagerLockingMode(Pager *, int);
int csqlitePagerSetJournalMode(Pager *, int);
int csqlitePagerGetJournalMode(Pager*);
int csqlitePagerOkToChangeJournalMode(Pager*);
i64 csqlitePagerJournalSizeLimit(Pager *, i64);
csqlite_backup **csqlitePagerBackupPtr(Pager*);
int csqlitePagerFlush(Pager*);

/* Functions used to obtain and release page references. */ 
int csqlitePagerGet(Pager *pPager, Pgno pgno, DbPage **ppPage, int clrFlag);
DbPage *csqlitePagerLookup(Pager *pPager, Pgno pgno);
void csqlitePagerRef(DbPage*);
void csqlitePagerUnref(DbPage*);
void csqlitePagerUnrefNotNull(DbPage*);
void csqlitePagerUnrefPageOne(DbPage*);

/* Operations on page references. */
int csqlitePagerWrite(DbPage*);
void csqlitePagerDontWrite(DbPage*);
int csqlitePagerMovepage(Pager*,DbPage*,Pgno,int);
int csqlitePagerPageRefcount(DbPage*);
void *csqlitePagerGetData(DbPage *); 
void *csqlitePagerGetExtra(DbPage *); 

/* Functions used to manage pager transactions and savepoints. */
void csqlitePagerPagecount(Pager*, int*);
int csqlitePagerBegin(Pager*, int exFlag, int);
int csqlitePagerCommitPhaseOne(Pager*,const char *zMaster, int);
int csqlitePagerExclusiveLock(Pager*);
int csqlitePagerSync(Pager *pPager, const char *zMaster);
int csqlitePagerCommitPhaseTwo(Pager*);
int csqlitePagerRollback(Pager*);
int csqlitePagerOpenSavepoint(Pager *pPager, int n);
int csqlitePagerSavepoint(Pager *pPager, int op, int iSavepoint);
int csqlitePagerSharedLock(Pager *pPager);

#ifndef SQLITE_OMIT_WAL
  int csqlitePagerCheckpoint(Pager *pPager, csqlite*, int, int*, int*);
  int csqlitePagerWalSupported(Pager *pPager);
  int csqlitePagerWalCallback(Pager *pPager);
  int csqlitePagerOpenWal(Pager *pPager, int *pisOpen);
  int csqlitePagerCloseWal(Pager *pPager, csqlite*);
# ifdef SQLITE_DIRECT_OVERFLOW_READ
  int csqlitePagerUseWal(Pager *pPager, Pgno);
# endif
# ifdef SQLITE_ENABLE_SNAPSHOT
  int csqlitePagerSnapshotGet(Pager *pPager, csqlite_snapshot **ppSnapshot);
  int csqlitePagerSnapshotOpen(Pager *pPager, csqlite_snapshot *pSnapshot);
  int csqlitePagerSnapshotRecover(Pager *pPager);
  int csqlitePagerSnapshotCheck(Pager *pPager, csqlite_snapshot *pSnapshot);
  void csqlitePagerSnapshotUnlock(Pager *pPager);
# endif
#else
# define csqlitePagerUseWal(x,y) 0
#endif

#ifdef SQLITE_ENABLE_ZIPVFS
  int csqlitePagerWalFramesize(Pager *pPager);
#endif

/* Functions used to query pager state and configuration. */
u8 csqlitePagerIsreadonly(Pager*);
u32 csqlitePagerDataVersion(Pager*);
#ifdef SQLITE_DEBUG
  int csqlitePagerRefcount(Pager*);
#endif
int csqlitePagerMemUsed(Pager*);
const char *csqlitePagerFilename(Pager*, int);
csqlite_vfs *csqlitePagerVfs(Pager*);
csqlite_file *csqlitePagerFile(Pager*);
csqlite_file *csqlitePagerJrnlFile(Pager*);
const char *csqlitePagerJournalname(Pager*);
void *csqlitePagerTempSpace(Pager*);
int csqlitePagerIsMemdb(Pager*);
void csqlitePagerCacheStat(Pager *, int, int, int *);
void csqlitePagerClearCache(Pager*);
int csqliteSectorSize(csqlite_file *);
#ifdef SQLITE_ENABLE_SETLK_TIMEOUT
void csqlitePagerResetLockTimeout(Pager *pPager);
#else
# define csqlitePagerResetLockTimeout(X)
#endif

/* Functions used to truncate the database file. */
void csqlitePagerTruncateImage(Pager*,Pgno);

void csqlitePagerRekey(DbPage*, Pgno, u16);

#if defined(SQLITE_HAS_CODEC) && !defined(SQLITE_OMIT_WAL)
void *csqlitePagerCodec(DbPage *);
#endif

/* Functions to support testing and debugging. */
#if !defined(NDEBUG) || defined(SQLITE_TEST)
  Pgno csqlitePagerPagenumber(DbPage*);
  int csqlitePagerIswriteable(DbPage*);
#endif
#ifdef SQLITE_TEST
  int *csqlitePagerStats(Pager*);
  void csqlitePagerRefdump(Pager*);
  void disable_simulated_io_errors(void);
  void enable_simulated_io_errors(void);
#else
# define disable_simulated_io_errors()
# define enable_simulated_io_errors()
#endif

#ifdef __cplusplus
}  /* end of the 'extern "C"' block */
#endif


#endif /* SQLITE_PAGER_H */
