// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_STORAGE_SQLITE_H_
#define MUMBA_STORAGE_SQLITE_H_

#include "storage/db/sqlite3.h"

#define STORAGE_VFS_NAME "diskfs"

struct disk_file_t {
  csqlite_file base;
  char key[256];
  size_t key_len;
  void* torrent;
  int journal_seq;
};

// File
int StorageCloseBlob(csqlite_file* ref);
int StorageReadBlob(csqlite_file* ref, void* buf, int size, csqlite_int64 offset);
int StorageWriteBlob(csqlite_file*, const void*, int iAmt, csqlite_int64 iOfst);
int StorageTruncateBlob(csqlite_file*, csqlite_int64 size);
int StorageSyncBlob(csqlite_file*, int flags);
int StorageSizeBlob(csqlite_file*, csqlite_int64 *pSize);
int StorageLockBlob(csqlite_file*, int);
int StorageUnlockBlob(csqlite_file*, int);
int StorageCheckReservedLockBlob(csqlite_file*, int *pResOut);
int StorageFileControl(csqlite_file*, int op, void *pArg);
int StorageSectorSize(csqlite_file*);
int StorageDeviceCharacteristics(csqlite_file*);
//int BlobFetch(csqlite_file*, csqlite_int64 iOfst, int iAmt, void **pp);
//int BlobUnfetch(csqlite_file*, csqlite_int64 iOfst, void *p);

// VFS

int StorageOpenBlob(csqlite_vfs*, const char *zName, csqlite_file*, int flags, int *pOutFlags);
int StorageDeleteBlob(csqlite_vfs*, const char *zName, int syncDir);
int StorageAccessBlob(csqlite_vfs*, const char *zName, int flags, int *pResOut);
int StorageFullPathname(csqlite_vfs*, const char *zName, int nOut, char *zOut);
void* StorageDlOpen(csqlite_vfs*, const char *zFilename);
void StorageDlError(csqlite_vfs*, int nByte, char *zErrMsg);
void (*StorageDlSym(csqlite_vfs*,void*, const char *zSymbol))(void);
void StorageDlClose(csqlite_vfs*, void*);
int StorageRandomness(csqlite_vfs*, int nByte, char *zOut);
int StorageSleep(csqlite_vfs*, int microseconds);
int StorageCurrentTime(csqlite_vfs*, double*);
int StorageGetLastError(csqlite_vfs*, int, char *);
//int StorageSetSystemCall(csqlite_vfs*, const char *zName, csqlite_syscall_ptr);
//csqlite_syscall_ptr StorageGetSystemCall(csqlite_vfs*, const char *zName);
//const char *StorageNextSystemCall(csqlite_vfs*, const char *zName);
  
static csqlite_vfs disk_vfs = {
  1,                                          /* iVersion */
  sizeof(disk_file_t),                                          /* szOsFile */
  255,                                       /* mxPathname */
  0,                                          /* pNext */
  STORAGE_VFS_NAME,                              /* zName */
  0,                                          /* pAppData */
  StorageOpenBlob,                                     /* xOpen */
  StorageDeleteBlob,                                   /* xDelete */
  StorageAccessBlob,                                   /* xAccess */
  StorageFullPathname,                             /* xFullPathname */
  StorageDlOpen,                                   /* xDlOpen */
  StorageDlError,                                  /* xDlError */
  StorageDlSym,                                    /* xDlSym */
  StorageDlClose,                                  /* xDlClose */
  StorageRandomness,                               /* xRandomness */
  StorageSleep,                                    /* xSleep */
  StorageCurrentTime,                              /* xCurrentTime */
  0                                           /* xCurrentTimeInt64 */
};

static csqlite_io_methods disk_io_methods = {
  1,                            /* iVersion */
  StorageCloseBlob,                      /* xClose */
  StorageReadBlob,                       /* xRead */
  StorageWriteBlob,                      /* xWrite */
  StorageTruncateBlob,                   /* xTruncate */
  StorageSyncBlob,                       /* xSync */
  StorageSizeBlob,                   /* xFileSize */
  StorageLockBlob,                       /* xLock */
  StorageUnlockBlob,                     /* xUnlock */
  StorageCheckReservedLockBlob,          /* xCheckReservedLock */
  StorageFileControl,                /* xFileControl */
  StorageSectorSize,                 /* xSectorSize */
  StorageDeviceCharacteristics,      /* xDeviceCharacteristics */
  0,                            /* xShmMap */
  0,                            /* xShmLock */
  0,                            /* xShmBarrier */
  0                             /* xShmUnmap */
};

#endif