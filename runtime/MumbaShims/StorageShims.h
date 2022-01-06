// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_STORAGE_SHIMS_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_STORAGE_SHIMS_H_

#include "Globals.h"

typedef void* StorageRef;
typedef void* DatabaseRef;
typedef void* DatabaseCursorRef;
typedef void* FilebaseRef;
typedef void* FilebaseCursorRef;
typedef void* SharedMemoryRef;

// StorageContext
EXPORT void _StorageDestroy(StorageRef handle);
EXPORT void _StorageGetAllocatedSize(StorageRef handle, void*, void(*)(void*, int64_t));
EXPORT void _StorageListShares(StorageRef handle, void*, 
  void(*)(
   void*,
   int,
   const char**,
   const char**,
   int32_t*,
   int32_t*,
   const char**,
   int64_t*,
   int32_t*,
   int32_t*,
   int64_t*,
   int32_t*));
EXPORT void _StorageFilebaseCreateWithPath(StorageRef handle, void*, const char* name, const char* path, void(*)(void*, int, FilebaseRef));
EXPORT void _StorageFilebaseCreateWithInfohash(StorageRef handle, void*, const char* name, const char* infohash, void(*)(void*, int, FilebaseRef));
EXPORT void _StorageFilebaseOpen(StorageRef handle, void*, const char* name, int create, void(*)(void*, int, FilebaseRef));
EXPORT void _StorageFilebaseExists(StorageRef handle, void*, const char* name, void(*)(void*, int));
EXPORT void _StorageFilebaseListFiles(StorageRef handle, void*, const char* name, 
  void(*)(
    void*, 
    int,
    const char**,
    const char**,
    const char**,
    int32_t*,
    int64_t*,
    int32_t*,
    int32_t*,
    int32_t*,
    int64_t*));

EXPORT void _StorageDatabaseCreate(StorageRef handle, void*, const char* name, const char* keyspace, void(*)(void*, int, DatabaseRef));
EXPORT void _StorageDatabaseCreateWithKeyspaces(StorageRef handle, void*, const char* name, char** keyspaces, int keyspaces_count, void(*)(void*, int, DatabaseRef));
EXPORT void _StorageDatabaseExists(StorageRef handle, void*, const char* name, void(*)(void*, int));
EXPORT void _StorageDatabaseOpen(StorageRef handle, void*, const char* name, int create, void(*)(void*, int, DatabaseRef));
EXPORT void _StorageDatabaseDrop(StorageRef handle, void*, const char* name, void(*)(void*, int));

EXPORT void _DatabaseDestroy(DatabaseRef handle);
EXPORT void _DatabaseClose(DatabaseRef handle, void*, void(*)(void*, int));
EXPORT void _DatabasePut(DatabaseRef handle, void*, const char* keyspace, const char* key, const char* value, int value_size, void(*)(void*, int));
EXPORT void _DatabaseGet(DatabaseRef handle, void*, const char* keyspace, const char* key, void(*)(void*, int, SharedMemoryRef));
EXPORT void _DatabaseDelete(DatabaseRef handle, void*, const char* keyspace, const char* key, void(*)(void*, int));
EXPORT void _DatabaseDeleteAll(DatabaseRef handle, void*, const char* keyspace, void(*)(void*, int));
EXPORT void _DatabaseKeyspaceCreate(DatabaseRef handle, void*, const char* keyspace, void(*)(void*, int));
EXPORT void _DatabaseKeyspaceDrop(DatabaseRef handle, void*, const char* keyspace, void(*)(void*, int));
EXPORT void _DatabaseKeyspaceList(DatabaseRef handle, void*, void(*)(void*, int, int, const char**));
EXPORT void _DatabaseCursorCreate(DatabaseRef handle, const char* keyspace, int order, int write, void* state, void (*callback)(void*, DatabaseCursorRef));

EXPORT void _DatabaseCursorDestroy(DatabaseCursorRef cursor);
EXPORT void _DatabaseCursorIsValid(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int));
EXPORT void _DatabaseCursorFirst(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int));
EXPORT void _DatabaseCursorLast(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int));
EXPORT void _DatabaseCursorPrevious(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int));
EXPORT void _DatabaseCursorNext(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int));
EXPORT void _DatabaseCursorSeekTo(DatabaseCursorRef cursor, const uint8_t* key, int key_size, int seek_op, void* state, void(*callback)(void*, int, int));
EXPORT void _DatabaseCursorDataSize(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int, int));
EXPORT void _DatabaseCursorCount(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int, int));
EXPORT void _DatabaseCursorGetData(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int, const uint8_t*, int));
EXPORT void _DatabaseCursorGetKeyValue(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int, const uint8_t*, int, const uint8_t*, int));
EXPORT void _DatabaseCursorGet(DatabaseCursorRef cursor, const uint8_t* key, int key_size, void* state, void(*callback)(void*, int, const uint8_t*, int));
EXPORT void _DatabaseCursorInsert(DatabaseCursorRef cursor, const uint8_t* key, int key_size, const uint8_t* value, int value_size, void* state, void(*callback)(void*, int));
EXPORT void _DatabaseCursorDelete(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int));
EXPORT void _DatabaseCursorCommit(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int));
EXPORT void _DatabaseCursorRollback(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int));
EXPORT void _DatabaseCursorIsValidBlocking(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int));
EXPORT void _DatabaseCursorFirstBlocking(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int));
EXPORT void _DatabaseCursorLastBlocking(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int));
EXPORT void _DatabaseCursorPreviousBlocking(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int));
EXPORT void _DatabaseCursorNextBlocking(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int));
EXPORT void _DatabaseCursorSeekToBlocking(DatabaseCursorRef cursor, const uint8_t* key, int key_size, int seek_op, void* state, void(*callback)(void*, int, int));
EXPORT void _DatabaseCursorDataSizeBlocking(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int, int));
EXPORT void _DatabaseCursorCountBlocking(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int, int));
EXPORT void _DatabaseCursorGetDataBlocking(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int, const uint8_t*, int));
EXPORT void _DatabaseCursorGetKeyValueBlocking(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int, const uint8_t*, int, const uint8_t*, int));
EXPORT void _DatabaseCursorGetBlocking(DatabaseCursorRef cursor, const uint8_t* key, int key_size, void* state, void(*callback)(void*, int, const uint8_t*, int));
EXPORT void _DatabaseCursorInsertBlocking(DatabaseCursorRef cursor, const uint8_t* key, int key_size, const uint8_t* value, int value_size, void* state, void(*callback)(void*, int));
EXPORT void _DatabaseCursorDeleteBlocking(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int));
EXPORT void _DatabaseCursorCommitBlocking(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int));
EXPORT void _DatabaseCursorRollbackBlocking(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int));

EXPORT void _FilebaseDestroy(FilebaseRef handle);
EXPORT void _FilebaseClose(FilebaseRef handle, void*, void(*)(void*, int));
EXPORT void _FilebaseReadOnce(FilebaseRef handle, const char* file_name, int offset, int size, void* state, void (*callback)(void*, int, SharedMemoryRef));
EXPORT void _FilebaseWriteOnce(FilebaseRef handle, const char* file_name, int data_offset, int data_size, const char* data,  void* state, void (*callback)(void*, int, int));
EXPORT void _FilebaseCursorCreate(FilebaseRef handle, void* state, void (*callback)(void*, FilebaseCursorRef));

EXPORT void _FilebaseCursorDestroy(FilebaseCursorRef cursor);
EXPORT void _FilebaseCursorIsValid(FilebaseCursorRef cursor, void* state, void(*callback)(void*, int));
EXPORT void _FilebaseCursorFirst(FilebaseCursorRef cursor, void* state, void(*callback)(void*, int));
EXPORT void _FilebaseCursorLast(FilebaseCursorRef cursor, void* state, void(*callback)(void*, int));
EXPORT void _FilebaseCursorPrevious(FilebaseCursorRef cursor, void* state, void(*callback)(void*, int));
EXPORT void _FilebaseCursorNext(FilebaseCursorRef cursor, void* state, void(*callback)(void*, int));
EXPORT void _FilebaseCursorSeekTo(FilebaseCursorRef cursor, const uint8_t* key, int key_size, int seek_op, void* state, void(*callback)(void*, int, int));
EXPORT void _FilebaseCursorDataSize(FilebaseCursorRef cursor, void* state, void(*callback)(void*, int, int));
EXPORT void _FilebaseCursorCount(FilebaseCursorRef cursor, void* state, void(*callback)(void*, int, int));
EXPORT void _FilebaseCursorRead(FilebaseCursorRef cursor, const uint8_t* key, int key_size, void* state, void(*callback)(void*, int, const uint8_t*, int));
EXPORT void _FilebaseCursorWrite(DatabaseCursorRef cursor, const uint8_t* key, int key_size, const uint8_t* value, int value_size, void* state, void(*callback)(void*, int));
EXPORT void _FilebaseCursorDelete(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int));
//EXPORT void _FilebaseCursorCommit(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int));
//EXPORT void _FilebaseCursorRollback(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int));


EXPORT void _SharedMemoryDestroy(SharedMemoryRef handle);
EXPORT int _SharedMemoryGetSize(SharedMemoryRef handle);
EXPORT void _SharedMemoryMap(SharedMemoryRef handle, void* state, void(*cb)(void*, char*, int));
EXPORT void _SharedMemoryConstMap(SharedMemoryRef handle, void* state, void(*cb)(void*, const char*, int));

#endif