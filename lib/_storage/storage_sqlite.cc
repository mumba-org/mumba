// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/logging.h"
#include "base/memory/ref_counted.h"
#include "base/single_thread_task_runner.h"
#include "base/task_runner.h"
#include "base/threading/thread_task_runner_handle.h"
#include "storage/db/sqlite3.h"
#include "storage/db/sqliteInt.h"
#include "storage/storage_sqlite.h"
#include "storage/torrent.h"

// TODO: be big endian/little endian aware
//       as this check will fail on big endian   
static bool IsJournalFile(const char* name, size_t len) {
  if (len > 8  && 
      name[len-1] == 'l' && 
      name[len-2] == 'a' &&
      name[len-3] == 'n' &&
      name[len-4] == 'r' &&
      name[len-5] == 'u' &&
      name[len-6] == 'o' &&
      name[len-7] == 'j') {
    return true;
  }
  return false;
}

int StorageCloseBlob(csqlite_file* ref) {
  disk_file_t* file = reinterpret_cast<disk_file_t*>(ref);
  scoped_refptr<storage::Torrent> torrent(reinterpret_cast<storage::Torrent*>(file->torrent));
  bool is_journal = IsJournalFile(file->key, file->key_len);
  return torrent->Close(is_journal, is_journal ? file->journal_seq : -1);
}

int StorageReadBlob(csqlite_file* ref, void* buf, int size, csqlite_int64 offset) {
  disk_file_t* file = reinterpret_cast<disk_file_t*>(ref);
  scoped_refptr<storage::Torrent> torrent(reinterpret_cast<storage::Torrent*>(file->torrent));
  bool is_journal = IsJournalFile(file->key, file->key_len);
  return torrent->Read(buf, size, offset, is_journal, is_journal ? file->journal_seq : -1);
}

int StorageWriteBlob(csqlite_file* ref, const void* data, int iAmt, csqlite_int64 iOfst) {
  disk_file_t* file = reinterpret_cast<disk_file_t*>(ref);
  scoped_refptr<storage::Torrent> torrent(reinterpret_cast<storage::Torrent*>(file->torrent));
  bool is_journal = IsJournalFile(file->key, file->key_len);
  return torrent->Write(data, iAmt, iOfst, is_journal, is_journal ? file->journal_seq : -1);
}

int StorageTruncateBlob(csqlite_file* ref, csqlite_int64 size) {
  return SQLITE_OK;
}

int StorageSyncBlob(csqlite_file*, int flags) {
  return SQLITE_OK;
}

int StorageSizeBlob(csqlite_file* ref, csqlite_int64 *pSize) {
  disk_file_t* file = reinterpret_cast<disk_file_t*>(ref);
  scoped_refptr<storage::Torrent> torrent(reinterpret_cast<storage::Torrent*>(file->torrent));
  *pSize = torrent->GetSize();
  if (*pSize == -1)
    *pSize = 0;
  
  return SQLITE_OK;
}

int StorageLockBlob(csqlite_file*, int) {
  return SQLITE_OK;
}

int StorageUnlockBlob(csqlite_file*, int) {
  return SQLITE_OK;
}

int StorageCheckReservedLockBlob(csqlite_file*, int *pResOut) {
  return SQLITE_OK;
}

int StorageFileControl(csqlite_file* ref, int op, void *pArg) {
  return SQLITE_OK;
}

int StorageSectorSize(csqlite_file*) {
  return 1024 * 16;
}

int StorageDeviceCharacteristics(csqlite_file*) {
  return SQLITE_IOCAP_SEQUENTIAL | SQLITE_IOCAP_ATOMIC16K;
}
// VFS

int StorageOpenBlob(csqlite_vfs* vfs, const char *zName, csqlite_file* file, int flags, int *pOutFlags) {
  int rc = SQLITE_OK;
  size_t len = strlen(zName);
  
  disk_file_t *real_file = reinterpret_cast<disk_file_t *>(file);
  real_file->base.pMethods = &disk_io_methods;
  real_file->torrent = vfs->pAppData;
  memcpy(real_file->key, zName, len);
  real_file->key_len = len;

  bool is_journal = IsJournalFile(zName, len);

  scoped_refptr<storage::Torrent> torrent(reinterpret_cast<storage::Torrent*>(vfs->pAppData));
  DCHECK(torrent);

  if (is_journal) {
    real_file->journal_seq = torrent->NewJournalEntry();
  }
  ////DLOG(INFO) << " flags: " << flags;
  if (((1<<(flags&7)) & SQLITE_OPEN_CREATE) == 0) {
    rc = torrent->Create(is_journal, is_journal ? real_file->journal_seq : -1);
  } else {
    rc = torrent->Open();
  }
  
  if (pOutFlags)
    *pOutFlags |= SQLITE_OPEN_READWRITE | SQLITE_OPEN_EXCLUSIVE;
  
  return rc;
}

int StorageDeleteBlob(csqlite_vfs* vfs, const char *zName, int syncDir) {
  size_t len = strlen(zName);
  bool is_journal = IsJournalFile(zName, len);
  scoped_refptr<storage::Torrent> torrent(reinterpret_cast<storage::Torrent*>(vfs->pAppData));
  return torrent->Delete(is_journal);
}

int StorageAccessBlob(csqlite_vfs*, const char *zName, int flags, int *pResOut) {
  *pResOut = 0;
  *pResOut &= ~SQLITE_ACCESS_READWRITE;
  return SQLITE_OK;
}

int StorageFullPathname(csqlite_vfs*, const char *zName, int nOut, char *zOut) {
  size_t size = csqliteStrlen30(zName);
  memcpy(zOut, zName, size); 
  zOut[size] = '\0';
  return SQLITE_OK;
}

void* StorageDlOpen(csqlite_vfs*, const char *zFilename) {
  return nullptr;
}

void StorageDlError(csqlite_vfs*, int nByte, char *zErrMsg) {
}

void (*StorageDlSym(csqlite_vfs*,void*, const char *zSymbol))(void) {
  return nullptr;
}

void StorageDlClose(csqlite_vfs*, void*) {
}

int StorageRandomness(csqlite_vfs*, int nByte, char *zOut) {
  return SQLITE_OK;
}

int StorageSleep(csqlite_vfs*, int microseconds) {
  return SQLITE_OK;
}

int StorageCurrentTime(csqlite_vfs*, double*) {
  return SQLITE_OK;
}

int StorageGetLastError(csqlite_vfs*, int, char *) {
  return SQLITE_OK;
}
