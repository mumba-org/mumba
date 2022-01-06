// Copyright (c) 2020 Mumba. All rights reserved.public var 
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "StorageShims.h"

#include "StorageHelper.h"
#include "core/shared/domain/storage/storage_manager.h"

void _StorageDestroy(StorageRef handle) {
  delete reinterpret_cast<StorageState *>(handle);
}

void _StorageGetAllocatedSize(StorageRef handle, void* ptr, void(*cb)(void* state, int64_t size)) {
  StorageState* state = reinterpret_cast<StorageState *>(handle); 
  state->GetAllocatedSize(ptr, cb);
}

void _StorageListShares(StorageRef handle, void* ptr, 
  void(*cb)(
   void*,
   int,
   const char** uuid,
   const char**,
   int32_t*,
   int32_t*,
   const char**,
   int64_t*,
   int32_t*,
   int32_t*,
   int64_t*,
   int32_t*)) {
  StorageState* state = reinterpret_cast<StorageState *>(handle); 
  state->ListShares(ptr, cb); 
}

void _StorageFilebaseCreateWithPath(StorageRef handle, void* ptr, const char* name, const char* path, void(*cb)(void*, int, FilebaseRef)) {
  StorageState* state = reinterpret_cast<StorageState *>(handle); 
  state->FilebaseCreateWithPath(ptr, name, path, cb); 
}

void _StorageFilebaseCreateWithInfohash(StorageRef handle, void* ptr, const char* name, const char* infohash, void(*cb)(void*, int, FilebaseRef)) {
  StorageState* state = reinterpret_cast<StorageState *>(handle); 
  state->FilebaseCreateWithInfohash(ptr, name, infohash, cb); 
}

void _StorageFilebaseOpen(StorageRef handle, void* ptr, const char* name, int create, void(*cb)(void*, int, FilebaseRef)) {
  StorageState* state = reinterpret_cast<StorageState *>(handle); 
  state->FilebaseOpen(ptr, name, cb); 
}

void _StorageFilebaseExists(StorageRef handle, void* ptr, const char* name, void(*cb)(void*, int)) {
  StorageState* state = reinterpret_cast<StorageState *>(handle);
  std::string name_string = std::string(name);
  state->FilebaseExists(ptr, name_string, cb);
}

void _StorageFilebaseListFiles(StorageRef handle, void* ptr, const char* name, void(*cb)(
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
    int64_t*)) {
  StorageState* state = reinterpret_cast<StorageState *>(handle);
  std::string name_string = std::string(name);
  state->FilebaseListFiles(ptr, name_string, cb); 
}

void _StorageDatabaseCreateWithKeyspaces(StorageRef handle, void* ptr, const char* name, char** keyspaces, int keyspaces_count, void(*cb)(void*, int, DatabaseRef)) {
  StorageState* state = reinterpret_cast<StorageState *>(handle);
  std::vector<std::string> keyspace_vec;
  for (int i = 0; i < keyspaces_count; i++) {
    keyspace_vec.push_back(std::string(keyspaces[i]));
    free(keyspaces[i]);
  }
  state->DatabaseCreate(ptr, std::string(name), std::move(keyspace_vec), cb);
}

void _StorageDatabaseOpen(StorageRef handle, void* ptr, const char* name, int create, void(*cb)(void*, int, DatabaseRef)) {
  StorageState* state = reinterpret_cast<StorageState *>(handle);
  std::string name_string = std::string(name);
  bool create_if_not_exists = create != 0;
  state->DatabaseOpen(ptr, name_string, create_if_not_exists, cb);
}

void _StorageDatabaseExists(StorageRef handle, void* ptr, const char* name, void(*cb)(void*, int)) {
  StorageState* state = reinterpret_cast<StorageState *>(handle);
  std::string name_string = std::string(name);
  state->DatabaseExists(ptr, name_string, cb); 
}

void _StorageDatabaseCreate(StorageRef handle, void* ptr, const char* name, const char* keyspace, void(*cb)(void*, int, DatabaseRef)) {
  StorageState* state = reinterpret_cast<StorageState *>(handle);
  std::vector<std::string> keyspaces;
  if (keyspace) {
    keyspaces.push_back(std::string(keyspace));
  }
  state->DatabaseCreate(ptr, std::string(name), keyspaces, cb);
}

void _StorageDatabaseDrop(StorageRef handle, void* ptr, const char* name, void(*cb)(void*, int)) {
  StorageState* state = reinterpret_cast<StorageState *>(handle);
  std::string name_string = std::string(name);
  state->DatabaseDrop(ptr, name_string, cb); 
}

void _FilebaseDestroy(FilebaseRef handle) {
  FilebaseState* state = reinterpret_cast<FilebaseState *>(handle);
  delete state;
}

void _FilebaseClose(FilebaseRef handle, void* ptr, void(*cb)(void*, int)) {
  FilebaseState* state = reinterpret_cast<FilebaseState *>(handle);
  state->FilebaseClose(ptr, cb);
}

void _FilebaseReadOnce(FilebaseRef handle, const char* file_name, int offset, int size, void* ptr, void (*cb)(void*, int, SharedMemoryRef)) {
  FilebaseState* state = reinterpret_cast<FilebaseState *>(handle);
  state->FilebaseReadOnce(ptr, std::string(file_name), offset, size, cb);
}

void _FilebaseWriteOnce(FilebaseRef handle, const char* file_name, int data_offset, int data_size, const char* data, void* ptr, void (*callback)(void*, int, int)) {
  FilebaseState* state = reinterpret_cast<FilebaseState *>(handle);
  std::vector<uint8_t> data_vec;
  data_vec.insert(data_vec.end(), reinterpret_cast<const uint8_t *>(data), (reinterpret_cast<const uint8_t *>(data) + data_size));
  state->FilebaseWriteOnce(ptr, std::string(file_name), data_offset, data_size, std::move(data_vec), callback); 
}

void _FilebaseCursorCreate(FilebaseRef handle, void* state, void (*callback)(void*, FilebaseCursorRef)) {
  
}

void _DatabaseDestroy(DatabaseRef handle) {
  DatabaseState* state = reinterpret_cast<DatabaseState *>(handle);
  delete state;
}

void _DatabaseClose(DatabaseRef handle, void* ptr, void(*cb)(void*, int)) {
  DatabaseState* state = reinterpret_cast<DatabaseState *>(handle);
  state->DatabaseClose(ptr, cb);
}

void _DatabasePut(DatabaseRef handle, void* ptr, const char* keyspace, const char* key, const char* value, int value_size, void(*cb)(void*, int)) {
  DatabaseState* state = reinterpret_cast<DatabaseState *>(handle);
  std::string keyspace_string = std::string(keyspace);
  std::string key_string = std::string(key);
  mojo::ScopedSharedBufferHandle write_buffer = mojo::SharedBufferHandle::Create(value_size);
  mojo::ScopedSharedBufferMapping mapping = write_buffer->Map(value_size);
  char* write_ptr = static_cast<char *>(mapping.get());
  memcpy(write_ptr, value, value_size);
  state->DatabasePut(ptr, keyspace_string, key_string, std::move(write_buffer), cb);  
}

void _DatabaseGet(DatabaseRef handle, void* ptr, const char* keyspace, const char* key, void(*cb)(void*, int, SharedMemoryRef)) {
  DatabaseState* state = reinterpret_cast<DatabaseState *>(handle);
  std::string keyspace_string = std::string(keyspace);
  std::string key_string = std::string(key);
  state->DatabaseGet(ptr, keyspace_string, key_string, cb);   
}

void _DatabaseDelete(DatabaseRef handle, void* ptr, const char* keyspace, const char* key, void(*cb)(void*, int)) {
  DatabaseState* state = reinterpret_cast<DatabaseState *>(handle);
  std::string keyspace_string = std::string(keyspace);
  std::string key_string = std::string(key);
  state->DatabaseDelete(ptr, keyspace_string, key_string, cb);
}

void _DatabaseDeleteAll(DatabaseRef handle, void* ptr, const char* keyspace, void(*cb)(void*, int)) {
  DatabaseState* state = reinterpret_cast<DatabaseState *>(handle);
  std::string keyspace_string = std::string(keyspace);
  state->DatabaseDeleteAll(ptr, keyspace_string, cb);
}

void _DatabaseKeyspaceCreate(DatabaseRef handle, void* ptr, const char* keyspace, void(*cb)(void*, int)) {
  DatabaseState* state = reinterpret_cast<DatabaseState *>(handle);
  std::string keyspace_string = std::string(keyspace);
  state->DatabaseKeyspaceCreate(ptr, keyspace_string, cb); 
}

void _DatabaseKeyspaceDrop(DatabaseRef handle, void* ptr, const char* keyspace, void(*cb)(void*, int)) {
  DatabaseState* state = reinterpret_cast<DatabaseState *>(handle);
  std::string keyspace_string = std::string(keyspace);
  state->DatabaseKeyspaceDrop(ptr, keyspace_string, cb); 
}

void _DatabaseKeyspaceList(DatabaseRef handle, void* ptr, void(*cb)(void*, int, int, const char**)) {
  DatabaseState* state = reinterpret_cast<DatabaseState *>(handle);
  state->DatabaseKeyspaceList(ptr, cb); 
}

void _DatabaseCursorCreate(DatabaseRef handle, const char* keyspace, int order, int write, void* ptr, void (*callback)(void*, DatabaseCursorRef)) {
  DatabaseState* state = reinterpret_cast<DatabaseState *>(handle);
  state->DatabaseCursorCreate(ptr, std::string(keyspace), static_cast<common::mojom::Order>(order), write != 0, callback);
}

void _DatabaseCursorDestroy(DatabaseCursorRef cursor) {
  DatabaseCursorState* state = reinterpret_cast<DatabaseCursorState*>(cursor);
  delete state;
}

void _DatabaseCursorIsValid(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int)) {
  DatabaseCursorState* cursor_state = reinterpret_cast<DatabaseCursorState *>(cursor);
  cursor_state->IsValid(state, callback, false);  
}

void _DatabaseCursorIsValidBlocking(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int)) {
  DatabaseCursorState* cursor_state = reinterpret_cast<DatabaseCursorState *>(cursor);
  cursor_state->IsValid(state, callback, true); 
}

void _DatabaseCursorFirst(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int)) {
  DatabaseCursorState* cursor_state = reinterpret_cast<DatabaseCursorState *>(cursor);
  cursor_state->First(state, callback, false);
}

void _DatabaseCursorFirstBlocking(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int)) {
  DatabaseCursorState* cursor_state = reinterpret_cast<DatabaseCursorState *>(cursor);
  cursor_state->First(state, callback, true);
}

void _DatabaseCursorLast(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int)) {
  DatabaseCursorState* cursor_state = reinterpret_cast<DatabaseCursorState *>(cursor);
  cursor_state->Last(state, callback, false);
}

void _DatabaseCursorLastBlocking(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int)) {
  DatabaseCursorState* cursor_state = reinterpret_cast<DatabaseCursorState *>(cursor);
  cursor_state->Last(state, callback, true);
}

void _DatabaseCursorPrevious(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int)) {
  DatabaseCursorState* cursor_state = reinterpret_cast<DatabaseCursorState *>(cursor);
  cursor_state->Previous(state, callback, false);
}

void _DatabaseCursorPreviousBlocking(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int)) {
  DatabaseCursorState* cursor_state = reinterpret_cast<DatabaseCursorState *>(cursor);
  cursor_state->Previous(state, callback, true);
}

void _DatabaseCursorNext(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int)) {
  DatabaseCursorState* cursor_state = reinterpret_cast<DatabaseCursorState *>(cursor);
  cursor_state->Next(state, callback, false);
}

void _DatabaseCursorNextBlocking(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int)) {
  DatabaseCursorState* cursor_state = reinterpret_cast<DatabaseCursorState *>(cursor);
  cursor_state->Next(state, callback, true);
}

void _DatabaseCursorSeekTo(DatabaseCursorRef cursor, const uint8_t* key, int key_size, int seek_op, void* state, void(*callback)(void*, int, int)) {
  DatabaseCursorState* cursor_state = reinterpret_cast<DatabaseCursorState *>(cursor);
  std::vector<uint8_t> key_vec;
  key_vec.reserve(key_size);
  key_vec.insert(key_vec.end(), key, key + key_size);
  cursor_state->SeekTo(std::move(key_vec), static_cast<common::mojom::Seek>(seek_op), state, callback, false);
}

void _DatabaseCursorSeekToBlocking(DatabaseCursorRef cursor, const uint8_t* key, int key_size, int seek_op, void* state, void(*callback)(void*, int, int)) {
  DatabaseCursorState* cursor_state = reinterpret_cast<DatabaseCursorState *>(cursor);
  std::vector<uint8_t> key_vec;
  key_vec.reserve(key_size);
  key_vec.insert(key_vec.end(), key, key + key_size);
  cursor_state->SeekTo(std::move(key_vec), static_cast<common::mojom::Seek>(seek_op), state, callback, true);
}

void _DatabaseCursorDataSize(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int, int)) {
  DatabaseCursorState* cursor_state = reinterpret_cast<DatabaseCursorState *>(cursor);
  cursor_state->DataSize(state, callback, false);
}

void _DatabaseCursorDataSizeBlocking(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int, int)) {
  DatabaseCursorState* cursor_state = reinterpret_cast<DatabaseCursorState *>(cursor);
  cursor_state->DataSize(state, callback, true);
}

void _DatabaseCursorCount(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int, int)) {
  DatabaseCursorState* cursor_state = reinterpret_cast<DatabaseCursorState *>(cursor);
  cursor_state->Count(state, callback, false);
}

void _DatabaseCursorCountBlocking(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int, int)) {
  DatabaseCursorState* cursor_state = reinterpret_cast<DatabaseCursorState *>(cursor);
  cursor_state->Count(state, callback, true);
}

void _DatabaseCursorGetData(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int, const uint8_t*, int)) {
  DatabaseCursorState* cursor_state = reinterpret_cast<DatabaseCursorState *>(cursor);
  cursor_state->GetData(state, callback, false);
}

void _DatabaseCursorGetDataBlocking(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int, const uint8_t*, int)) {
  DatabaseCursorState* cursor_state = reinterpret_cast<DatabaseCursorState *>(cursor);
  cursor_state->GetData(state, callback, true);
}

void _DatabaseCursorGetKeyValue(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int, const uint8_t*, int, const uint8_t*, int)) {
  DatabaseCursorState* cursor_state = reinterpret_cast<DatabaseCursorState *>(cursor);
  cursor_state->GetKeyValue(state, callback, false);
}

void _DatabaseCursorGetKeyValueBlocking(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int, const uint8_t*, int, const uint8_t*, int)) {
  DatabaseCursorState* cursor_state = reinterpret_cast<DatabaseCursorState *>(cursor);
  cursor_state->GetKeyValue(state, callback, true);
}

void _DatabaseCursorGet(DatabaseCursorRef cursor, const uint8_t* key, int key_size, void* state, void(*callback)(void*, int, const uint8_t*, int)) {
  DatabaseCursorState* cursor_state = reinterpret_cast<DatabaseCursorState *>(cursor);
  std::vector<uint8_t> key_vec;
  key_vec.reserve(key_size);
  key_vec.insert(key_vec.end(), key, key + key_size);  
  cursor_state->Get(key_vec, state, callback, false);
}

void _DatabaseCursorGetBlocking(DatabaseCursorRef cursor, const uint8_t* key, int key_size, void* state, void(*callback)(void*, int, const uint8_t*, int)) {
  DatabaseCursorState* cursor_state = reinterpret_cast<DatabaseCursorState *>(cursor);
  std::vector<uint8_t> key_vec;
  key_vec.reserve(key_size);
  key_vec.insert(key_vec.end(), key, key + key_size);
  cursor_state->Get(key_vec, state, callback, true);
}

void _DatabaseCursorInsert(DatabaseCursorRef cursor, const uint8_t* key, int key_size, const uint8_t* value, int value_size, void* state, void(*callback)(void*, int)) {
  DatabaseCursorState* cursor_state = reinterpret_cast<DatabaseCursorState *>(cursor);
  common::mojom::KeyValuePtr kv = common::mojom::KeyValue::New();
  
  kv->key.reserve(key_size);
  kv->key.insert(kv->key.end(), key, key + key_size);

  kv->value.reserve(value_size);
  kv->value.insert(kv->value.end(), value, value + value_size);

  base::StringPiece key_view(reinterpret_cast<const char*>(kv->key.data()), kv->key.size());
  base::StringPiece value_view(reinterpret_cast<const char*>(kv->value.data()), kv->value.size());
 
  //DLOG(INFO) << "_DatabaseCursorInsert: " << key_view << " (" << kv->key.size() << ") : " << value_view << " (" << kv->value.size() << ")";
   
  cursor_state->Insert(std::move(kv), state, callback, false);
}

void _DatabaseCursorInsertBlocking(DatabaseCursorRef cursor, const uint8_t* key, int key_size, const uint8_t* value, int value_size, void* state, void(*callback)(void*, int)) {
  DatabaseCursorState* cursor_state = reinterpret_cast<DatabaseCursorState *>(cursor);
  common::mojom::KeyValuePtr kv = common::mojom::KeyValue::New();

  kv->key.reserve(key_size);
  kv->key.insert(kv->key.end(), key, key + key_size);

  kv->value.reserve(value_size);
  kv->value.insert(kv->value.end(), value, value + value_size);

  base::StringPiece key_view(reinterpret_cast<const char*>(kv->key.data()), kv->key.size());
  base::StringPiece value_view(reinterpret_cast<const char*>(kv->value.data()), kv->value.size());
 
  //DLOG(INFO) << "_DatabaseCursorInsert: " << key_view << " (" << kv->key.size() << ") : " << value_view << " (" << kv->value.size() << ")";

  cursor_state->Insert(std::move(kv), state, callback, true);
}

void _DatabaseCursorDelete(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int)) {
  DatabaseCursorState* cursor_state = reinterpret_cast<DatabaseCursorState *>(cursor);
  cursor_state->Delete(state, callback, false);
}

void _DatabaseCursorDeleteBlocking(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int)) {
  DatabaseCursorState* cursor_state = reinterpret_cast<DatabaseCursorState *>(cursor);
  cursor_state->Delete(state, callback, true);
}

void _DatabaseCursorCommit(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int)) {
  DatabaseCursorState* cursor_state = reinterpret_cast<DatabaseCursorState *>(cursor);
  cursor_state->Commit(state, callback, false);
}

void _DatabaseCursorCommitBlocking(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int)) {
  DatabaseCursorState* cursor_state = reinterpret_cast<DatabaseCursorState *>(cursor);
  cursor_state->Commit(state, callback, true);
}

void _DatabaseCursorRollback(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int)) {
  DatabaseCursorState* cursor_state = reinterpret_cast<DatabaseCursorState *>(cursor);
  cursor_state->Rollback(state, callback, false);
}

void _DatabaseCursorRollbackBlocking(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int)) {
  DatabaseCursorState* cursor_state = reinterpret_cast<DatabaseCursorState *>(cursor);
  cursor_state->Rollback(state, callback, true);
}

void _FilebaseCursorDestroy(FilebaseCursorRef cursor) {

}

void _FilebaseCursorIsValid(FilebaseCursorRef cursor, void* state, void(*callback)(void*, int)) {
  
}

void _FilebaseCursorFirst(FilebaseCursorRef cursor, void* state, void(*callback)(void*, int)) {
  
}

void _FilebaseCursorLast(FilebaseCursorRef cursor, void* state, void(*callback)(void*, int)) {
  
}

void _FilebaseCursorPrevious(FilebaseCursorRef cursor, void* state, void(*callback)(void*, int)) {
  
}

void _FilebaseCursorNext(FilebaseCursorRef cursor, void* state, void(*callback)(void*, int)) {
  
}

void _FilebaseCursorSeekTo(FilebaseCursorRef cursor, const uint8_t* key, int key_size, int seek_op, void* state, void(*callback)(void*, int, int)) {
  
}

void _FilebaseCursorDataSize(FilebaseCursorRef cursor, void* state, void(*callback)(void*, int, int)) {
  
}

void _FilebaseCursorCount(FilebaseCursorRef cursor, void* state, void(*callback)(void*, int, int)) {
  
}

void _FilebaseCursorRead(FilebaseCursorRef cursor, const uint8_t* key, int key_size, void* state, void(*callback)(void*, int, const uint8_t*, int)) {
  
}

void _FilebaseCursorWrite(DatabaseCursorRef cursor, const uint8_t* key, int key_size, const uint8_t* value, int value_size, void* state, void(*callback)(void*, int)) {
  
}

void _FilebaseCursorDelete(DatabaseCursorRef cursor, void* state, void(*callback)(void*, int)) {

}

void _SharedMemoryDestroy(SharedMemoryRef handle) {
  SharedMemoryState* sharedmem_state = reinterpret_cast<SharedMemoryState *>(handle);
  delete sharedmem_state; 
}

int _SharedMemoryGetSize(SharedMemoryRef handle) {
  SharedMemoryState* sharedmem_state = reinterpret_cast<SharedMemoryState *>(handle);
  return sharedmem_state->GetSize();
}

void _SharedMemoryMap(SharedMemoryRef handle, void* state, void(*cb)(void*, char*, int)) {
  SharedMemoryState* sharedmem_state = reinterpret_cast<SharedMemoryState *>(handle);
  sharedmem_state->Map(state, cb);
}

void _SharedMemoryConstMap(SharedMemoryRef handle, void* state, void(*cb)(void*, const char*, int)) {
  SharedMemoryState* sharedmem_state = reinterpret_cast<SharedMemoryState *>(handle);
  sharedmem_state->ConstMap(state, cb);
}