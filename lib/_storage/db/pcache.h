/*
** 2008 August 05
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
** subsystem. 
*/

#ifndef _PCACHE_H_

#ifdef __cplusplus
extern "C" {
#endif


typedef struct PgHdr PgHdr;
typedef struct PCache PCache;

/*
** Every page in the cache is controlled by an instance of the following
** structure.
*/
struct PgHdr {
  csqlite_pcache_page *pPage;    /* Pcache object page handle */
  void *pData;                   /* Page data */
  void *pExtra;                  /* Extra content */
  PCache *pCache;                /* PRIVATE: Cache that owns this page */
  PgHdr *pDirty;                 /* Transient list of dirty sorted by pgno */
  Pager *pPager;                 /* The pager this page is part of */
  Pgno pgno;                     /* Page number for this page */
#ifdef SQLITE_CHECK_PAGES
  u32 pageHash;                  /* Hash of page content */
#endif
  u16 flags;                     /* PGHDR flags defined below */

  /**********************************************************************
  ** Elements above, except pCache, are public.  All that follow are 
  ** private to pcache.c and should not be accessed by other modules.
  ** pCache is grouped with the public elements for efficiency.
  */
  i16 nRef;                      /* Number of users of this page */
  PgHdr *pDirtyNext;             /* Next element in list of dirty pages */
  PgHdr *pDirtyPrev;             /* Previous element in list of dirty pages */
                          /* NB: pDirtyNext and pDirtyPrev are undefined if the
                          ** PgHdr object is not dirty */
};

/* Bit values for PgHdr.flags */
#define PGHDR_CLEAN           0x001  /* Page not on the PCache.pDirty list */
#define PGHDR_DIRTY           0x002  /* Page is on the PCache.pDirty list */
#define PGHDR_WRITEABLE       0x004  /* Journaled and ready to modify */
#define PGHDR_NEED_SYNC       0x008  /* Fsync the rollback journal before
                                     ** writing this page to the database */
#define PGHDR_DONT_WRITE      0x010  /* Do not write content to disk */
#define PGHDR_MMAP            0x020  /* This is an mmap page object */

#define PGHDR_WAL_APPEND      0x040  /* Appended to wal file */

/* Initialize and shutdown the page cache subsystem */
int csqlitePcacheInitialize(void);
void csqlitePcacheShutdown(void);

/* Page cache buffer management:
** These routines implement SQLITE_CONFIG_PAGECACHE.
*/
void csqlitePCacheBufferSetup(void *, int sz, int n);

/* Create a new pager cache.
** Under memory stress, invoke xStress to try to make pages clean.
** Only clean and unpinned pages can be reclaimed.
*/
int csqlitePcacheOpen(
  int szPage,                    /* Size of every page */
  int szExtra,                   /* Extra space associated with each page */
  int bPurgeable,                /* True if pages are on backing store */
  int (*xStress)(void*, PgHdr*), /* Call to try to make pages clean */
  void *pStress,                 /* Argument to xStress */
  PCache *pToInit                /* Preallocated space for the PCache */
);

/* Modify the page-size after the cache has been created. */
int csqlitePcacheSetPageSize(PCache *, int);

/* Return the size in bytes of a PCache object.  Used to preallocate
** storage space.
*/
int csqlitePcacheSize(void);

/* One release per successful fetch.  Page is pinned until released.
** Reference counted. 
*/
csqlite_pcache_page *csqlitePcacheFetch(PCache*, Pgno, int createFlag);
int csqlitePcacheFetchStress(PCache*, Pgno, csqlite_pcache_page**);
PgHdr *csqlitePcacheFetchFinish(PCache*, Pgno, csqlite_pcache_page *pPage);
void csqlitePcacheRelease(PgHdr*);

void csqlitePcacheDrop(PgHdr*);         /* Remove page from cache */
void csqlitePcacheMakeDirty(PgHdr*);    /* Make sure page is marked dirty */
void csqlitePcacheMakeClean(PgHdr*);    /* Mark a single page as clean */
void csqlitePcacheCleanAll(PCache*);    /* Mark all dirty list pages as clean */
void csqlitePcacheClearWritable(PCache*);

/* Change a page number.  Used by incr-vacuum. */
void csqlitePcacheMove(PgHdr*, Pgno);

/* Remove all pages with pgno>x.  Reset the cache if x==0 */
void csqlitePcacheTruncate(PCache*, Pgno x);

/* Get a list of all dirty pages in the cache, sorted by page number */
PgHdr *csqlitePcacheDirtyList(PCache*);

/* Reset and close the cache object */
void csqlitePcacheClose(PCache*);

/* Clear flags from pages of the page cache */
void csqlitePcacheClearSyncFlags(PCache *);

/* Discard the contents of the cache */
void csqlitePcacheClear(PCache*);

/* Return the total number of outstanding page references */
int csqlitePcacheRefCount(PCache*);

/* Increment the reference count of an existing page */
void csqlitePcacheRef(PgHdr*);

int csqlitePcachePageRefcount(PgHdr*);

/* Return the total number of pages stored in the cache */
int csqlitePcachePagecount(PCache*);

#if defined(SQLITE_CHECK_PAGES) || defined(SQLITE_DEBUG)
/* Iterate through all dirty pages currently stored in the cache. This
** interface is only available if SQLITE_CHECK_PAGES is defined when the 
** library is built.
*/
void csqlitePcacheIterateDirty(PCache *pCache, void (*xIter)(PgHdr *));
#endif

#if defined(SQLITE_DEBUG)
/* Check invariants on a PgHdr object */
int csqlitePcachePageSanity(PgHdr*);
#endif

/* Set and get the suggested cache-size for the specified pager-cache.
**
** If no global maximum is configured, then the system attempts to limit
** the total number of pages cached by purgeable pager-caches to the sum
** of the suggested cache-sizes.
*/
void csqlitePcacheSetCachesize(PCache *, int);
#ifdef SQLITE_TEST
int csqlitePcacheGetCachesize(PCache *);
#endif

/* Set or get the suggested spill-size for the specified pager-cache.
**
** The spill-size is the minimum number of pages in cache before the cache
** will attempt to spill dirty pages by calling xStress.
*/
int csqlitePcacheSetSpillsize(PCache *, int);

/* Free up as much memory as possible from the page cache */
void csqlitePcacheShrink(PCache*);

#ifdef SQLITE_ENABLE_MEMORY_MANAGEMENT
/* Try to return memory used by the pcache module to the main memory heap */
int csqlitePcacheReleaseMemory(int);
#endif

#ifdef SQLITE_TEST
void csqlitePcacheStats(int*,int*,int*,int*);
#endif

void csqlitePCacheSetDefault(void);

/* Return the header size */
int csqliteHeaderSizePcache(void);
int csqliteHeaderSizePcache1(void);

/* Number of dirty pages as a percentage of the configured cache size */
int csqlitePCachePercentDirty(PCache*);

#ifdef __cplusplus
}  /* end of the 'extern "C"' block */
#endif

#endif /* _PCACHE_H_ */
