// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_STORAGE_HELPER_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_STORAGE_HELPER_H_

#include <memory>

#include "base/macros.h"
#include "EngineCallbacks.h"
#include "base/synchronization/lock.h"
#include "core/shared/domain/module/module_client.h"
#include "core/shared/domain/application/application.h"
#include "core/shared/domain/application/application_instance.h"
#include "core/shared/domain/storage/storage_context.h"
#include "core/shared/common/mojom/storage.mojom.h"

typedef void* DatabaseRef;
typedef void* FilebaseRef;
typedef void* SharedMemoryRef;

class StorageState : public domain::StorageShareObserver {
public:
  StorageState(scoped_refptr<domain::StorageContext> context, domain::ModuleState* module, void* state, StorageShareCallbacks callbacks);
  ~StorageState();

  const scoped_refptr<domain::StorageContext>& context() const {
    return context_;
  }

  domain::ModuleState* module() const { 
    return module_; 
  }

  void GetAllocatedSize(void*, void(*)(void*, int64_t));
  void ListShares(void*, void(*)(void*,
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

  void FilebaseCreateWithPath(void*, const std::string& name, const std::string& source_path, void(*)(void*, int, FilebaseRef));
  void FilebaseCreateWithInfohash(void*, const std::string& name, const std::string& infohash, void(*)(void*, int, FilebaseRef));
  void FilebaseOpen(void*, const std::string& name, void(*)(void*, int, FilebaseRef));
  void FilebaseExists(void*, const std::string& name, void(*)(void*, int));
  void FilebaseListFiles(void*, const std::string& name, void(*)(
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

  void DatabaseCreate(void*, const std::string& name, const std::vector<std::string>& keyspaces, void(*)(void*, int, DatabaseRef));
  void DatabaseOpen(void*, const std::string& name, bool create_if_not_exists, void(*)(void*, int, DatabaseRef));
  void DatabaseExists(void*, const std::string& name, void(*)(void*, int));
  void DatabaseDrop(void*, const std::string& name, void(*)(void*, int));
  
private:

  void GetAllocatedSizeImpl(void*, void(*)(void*, int64_t));
  void ListSharesImpl(void*, void(*)(void*,
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

  void FilebaseCreateWithPathImpl(void*, const std::string& name, const std::string& source_path, void(*)(void*, int, FilebaseRef));
  void FilebaseCreateWithInfohashImpl(void*, const std::string& name, const std::string& infohash, void(*)(void*, int, FilebaseRef));
  void FilebaseOpenImpl(void*, const std::string& name, void(*)(void*, int, FilebaseRef));
  void FilebaseExistsImpl(void*, const std::string& name, void(*)(void*, int));
  void FilebaseListFilesImpl(void*, const std::string& name, void(*)(
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


  void DatabaseCreateImpl(void*, const std::string& name, const std::vector<std::string>& keyspaces, void(*)(void*, int, DatabaseRef));
  void DatabaseOpenImpl(void*, const std::string& name, bool create_if_not_exists, void(*)(void*, int, DatabaseRef));
  void DatabaseExistsImpl(void*, const std::string& name, void(*)(void*, int));
  void DatabaseDropImpl(void*, const std::string& name, void(*)(void*, int));
       
  void OnAllocatedSizeReply(void* ptr, void(*cb)(void*, int64_t), int64_t size);
  void OnListShares(void* ptr, void(*cb)(void*,
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
   int32_t*), std::vector<common::mojom::ShareInfoPtr> shares);

  void OnFilebaseCreate(const std::string& name, void* ptr, void(*cb)(void*, int, FilebaseRef), int result);
  void OnFilebaseOpen(const std::string& name, void* ptr, void(*cb)(void*, int, FilebaseRef), int result);
  void OnFilebaseExists(void* ptr, void(*cb)(void*, int), int result);
  void OnFilebaseListFiles(void* ptr, void(*cb)(
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
    int64_t*), 
    std::vector<common::mojom::ShareStorageEntryPtr> entries);

  void OnDatabaseCreate(const std::string& name, void* ptr, void(*cb)(void*, int, DatabaseRef), int result);
  void OnDatabaseOpen(const std::string& name, void* ptr, void(*cb)(void*, int, DatabaseRef), int result);
  void OnDatabaseExists(void* ptr, void(*cb)(void*, int), int result);
  void OnDatabaseDrop(void* ptr, void(*cb)(void*, int), int result);

  // ShareDelegate

  void OnShareDHTAnnounceReply(const base::UUID& tid, int32_t peers) override;
  void OnShareMetadataReceived(const base::UUID& tid) override;
  void OnShareMetadataError(const base::UUID& tid, int32_t error) override;
  void OnSharePieceReadError(const base::UUID& tid, int32_t piece, int32_t error) override;
  void OnSharePiecePass(const base::UUID& tid, int32_t piece) override;
  void OnSharePieceFailed(const base::UUID& tid, int32_t piece) override;
  void OnSharePieceRead(const base::UUID& tid, int32_t piece, int64_t offset, int64_t size, int64_t block_size, int32_t result) override;
  void OnSharePieceWrite(const base::UUID& tid, int32_t piece, int64_t offset, int64_t size, int64_t block_size, int32_t result) override;
  void OnSharePieceHashFailed(const base::UUID& tid, int32_t piece) override;
  void OnShareCheckingFiles(const base::UUID& tid) override;
  void OnShareDownloadingMetadata(const base::UUID& tid) override;
  void OnShareFileRenamed(const base::UUID& tid, int32_t file_offset, const std::string& name, int32_t error) override;
  void OnShareResumed(const base::UUID& tid) override;
  void OnShareChecked(const base::UUID& tid, common::mojom::DomainStatus status) override;
  void OnSharePieceComplete(const base::UUID& tid, uint32_t piece_offset) override;
  void OnShareFileComplete(const base::UUID& tid, int file_offset) override;
  void OnShareDownloading(const base::UUID& tid) override;
  void OnShareComplete(const base::UUID& tid) override;
  void OnShareSeeding(const base::UUID& tid) override;
  void OnSharePaused(const base::UUID& tid) override;

  scoped_refptr<domain::StorageContext> context_;
  domain::ModuleState* module_;
  void* state_;
  StorageShareCallbacks callbacks_;

  base::WeakPtrFactory<StorageState> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(StorageState);
};

class FilebaseCursorState : public domain::StorageFileCursorDelegate {
public:
  FilebaseCursorState(
    const scoped_refptr<domain::StorageContext>& context, 
    scoped_refptr<base::SingleThreadTaskRunner> module_task_runner,
    void* state, void (*callback)(void*, void*));
  ~FilebaseCursorState() override;

  void IsValid(void* state, void(*callback)(void*, int), bool blocking);
  void First(void* state, void(*callback)(void*, int), bool blocking);
  void Last(void* state, void(*callback)(void*, int), bool blocking);
  void Previous(void* state, void(*callback)(void*, int), bool blocking);
  void Next(void* state, void(*callback)(void*, int), bool blocking);
  void SeekTo(std::vector<uint8_t> key, common::mojom::Seek seek, void* state, void(*callback)(void*, int, int), bool blocking);
  void GetSize(void* state, void(*callback)(void*, int, int), bool blocking);
  void Count(void* state, void(*callback)(void*, int, int), bool blocking);
  void Read(int offset, int size, void* state, void(*callback)(void*, int, const uint8_t*, int), bool blocking);
  void Write(int offset, int size, std::vector<uint8_t> data, void* state, void(*callback)(void*, int, int), bool blocking);
  void Delete(void* state, void(*callback)(void*, int), bool blocking);
  
  void OnCursorAvailable(common::mojom::FileCursorPtr cursor) override;

private:

  void IsValidImpl(void* state, void(*callback)(void*, int), bool blocking);
  void FirstImpl(void* state, void(*callback)(void*, int), bool blocking);
  void LastImpl(void* state, void(*callback)(void*, int), bool blocking);
  void PreviousImpl(void* state, void(*callback)(void*, int), bool blocking);
  void NextImpl(void* state, void(*callback)(void*, int), bool blocking);
  void SeekToImpl(std::vector<uint8_t> key, common::mojom::Seek seek, void* state, void(*callback)(void*, int, int), bool blocking);
  void GetSizeImpl(void* state, void(*callback)(void*, int, int), bool blocking);
  void CountImpl(void* state, void(*callback)(void*, int, int), bool blocking);
  void ReadImpl(int offset, int size, void* state, void(*callback)(void*, int, const uint8_t*, int), bool blocking);
  void WriteImpl(int offset, int size, std::vector<uint8_t> data, void* state, void(*callback)(void*, int, int), bool blocking);
  void DeleteImpl(void* state, void(*callback)(void*, int), bool blocking);
  
  void OnIsValid(bool blocking, void* state, void(*callback)(void*, int), bool valid);
  void OnFirst(bool blocking, void* state, void(*callback)(void*, int), int32_t status);
  void OnLast(bool blocking, void* state, void(*callback)(void*, int), int32_t status);
  void OnPrevious(bool blocking, void* state, void(*callback)(void*, int), int32_t status);
  void OnNext(bool blocking, void* state, void(*callback)(void*, int), int32_t status);
  void OnSeekTo(bool blocking, void* state, void(*callback)(void*, int, int), int32_t result, bool match);
  void OnGetSize(bool blocking, void* state, void(*callback)(void*, int, int), int32_t status, int64_t size);
  void OnCount(bool blocking, void* state, void(*callback)(void*, int, int), int32_t status, int64_t items);
  void OnRead(bool blocking, void* state, void(*callback)(void*, int, const uint8_t*, int), int32_t status, const std::vector<uint8_t>& data);
  void OnWrite(bool blocking, void* state, void(*callback)(void*, int, int), int32_t status, int32_t wrote);
  void OnDelete(bool blocking, void* state, void(*callback)(void*, int), int32_t status);
  
  scoped_refptr<domain::StorageContext> context_;
  scoped_refptr<base::SingleThreadTaskRunner> module_task_runner_;
  common::mojom::FileCursorPtr cursor_;
  void* state_;
  void(*callback_)(void*, void*);

  DISALLOW_COPY_AND_ASSIGN(FilebaseCursorState);
};

class FilebaseState {
public:
  FilebaseState(const std::string& share, const scoped_refptr<domain::StorageContext>& context, domain::ModuleState* module);
  ~FilebaseState();

  const scoped_refptr<domain::StorageContext>& context() const {
    return context_;
  }

  domain::ModuleState* module() const { 
    return module_; 
  }

  void FilebaseAdd(void*, const std::string& file_path, void(*)(void*, int));
  void FilebaseDelete(void*, const std::string& file_name, void(*)(void*, int));
  void FilebaseReadOnce(void*, const std::string& file_name, int offset, int size, void(*)(void*, int, SharedMemoryRef));
  void FilebaseRead(void*, const std::string& file_name, void(*)(void*, int));
  void FilebaseWrite(void*, const std::string& file_name, void(*)(void*, int));
  void FilebaseWriteOnce(void*, const std::string& file_name, int data_offset, int data_size, std::vector<uint8_t> data, void(*)(void*, int, int));
  void FilebaseList(void*, void(*)(void*, int));
  void FilebaseClose(void*, void(*)(void*, int));

  void FilebaseCursorCreate(void* state, bool write, void (*callback)(void*, void*));

private:

  void FilebaseAddImpl(void*, const std::string& file_path, void(*)(void*, int));
  void FilebaseDeleteImpl(void*, const std::string& file_name, void(*)(void*, int));
  void FilebaseReadOnceImpl(void*, const std::string& file_name, int offset, int size, void(*)(void*, int, SharedMemoryRef));
  void FilebaseReadImpl(void*, const std::string& file_name, void(*)(void*, int));
  void FilebaseWriteImpl(void*, const std::string& file_name, void(*)(void*, int));
  void FilebaseWriteOnceImpl(void*, const std::string& file_name, int data_offset, int data_size, std::vector<uint8_t> data, void(*)(void*, int, int));
  void FilebaseListImpl(void*, void(*)(void*, int));
  void FilebaseCloseImpl(void*, void(*)(void*, int));
  void FilebaseCursorCreateImpl(bool write, FilebaseCursorState* cursor);
  
  void OnFilebaseAdd(void* ptr, void(*cb)(void*, int), int result);
  void OnFilebaseDelete(void* ptr, void(*cb)(void*, int), int result);
  void OnFilebaseReadOnce(void* ptr, void(*)(void*, int, SharedMemoryRef), int status, mojo::ScopedSharedBufferHandle buffer, int size);
  void OnFilebaseRead(void* ptr, void(*cb)(void*, int), int result);
  void OnFilebaseWrite(void* ptr, void(*cb)(void*, int), int result);
  void OnFilebaseWriteOnce(void* ptr, void(*cb)(void*, int, int), int result, int bytes_written);
  void OnFilebaseList(void* ptr, void(*cb)(void*, int), int result);
  void OnFilebaseClose(void* ptr, void(*cb)(void*, int), int result);
  
  std::string share_;
  scoped_refptr<domain::StorageContext> context_;
  domain::ModuleState* module_;
  std::vector<std::unique_ptr<FilebaseCursorState>> cursors_;
  
  DISALLOW_COPY_AND_ASSIGN(FilebaseState);
};

class DatabaseCursorState : public domain::StorageDataCursorDelegate {
public:
  DatabaseCursorState(
    const scoped_refptr<domain::StorageContext>& context, 
    scoped_refptr<base::SingleThreadTaskRunner> module_task_runner,
    void* state, void (*callback)(void*, void*));
  ~DatabaseCursorState() override;

  void IsValid(void* state, void(*callback)(void*, int), bool blocking);
  void First(void* state, void(*callback)(void*, int), bool blocking);
  void Last(void* state, void(*callback)(void*, int), bool blocking);
  void Previous(void* state, void(*callback)(void*, int), bool blocking);
  void Next(void* state, void(*callback)(void*, int), bool blocking);
  void SeekTo(std::vector<uint8_t> key, common::mojom::Seek seek, void* state, void(*callback)(void*, int, int), bool blocking);
  void DataSize(void* state, void(*callback)(void*, int, int), bool blocking);
  void Count(void* state, void(*callback)(void*, int, int), bool blocking);
  void GetData(void* state, void(*callback)(void*, int, const uint8_t*, int), bool blocking);
  void GetKeyValue(void* state, void(*callback)(void*, int, const uint8_t*, int, const uint8_t*, int), bool blocking);
  void Get(const std::vector<uint8_t>& key, void* state, void(*callback)(void*, int, const uint8_t*, int), bool blocking);
  void Insert(common::mojom::KeyValuePtr kv, void* state, void(*callback)(void*, int), bool blocking);
  void Delete(void* state, void(*callback)(void*, int), bool blocking);
  void Commit(void* state, void(*callback)(void*, int), bool blocking);
  void Rollback(void* state, void(*callback)(void*, int), bool blocking);

  void OnCursorAvailable(common::mojom::DataCursorPtr cursor) override;

private:

  void IsValidImpl(void* state, void(*callback)(void*, int), bool blocking);
  void FirstImpl(void* state, void(*callback)(void*, int), bool blocking);
  void LastImpl(void* state, void(*callback)(void*, int), bool blocking);
  void PreviousImpl(void* state, void(*callback)(void*, int), bool blocking);
  void NextImpl(void* state, void(*callback)(void*, int), bool blocking);
  void SeekToImpl(std::vector<uint8_t> key, common::mojom::Seek seek, void* state, void(*callback)(void*, int, int), bool blocking);
  void DataSizeImpl(void* state, void(*callback)(void*, int, int), bool blocking);
  void CountImpl(void* state, void(*callback)(void*, int, int), bool blocking);
  void GetDataImpl(void* state, void(*callback)(void*, int, const uint8_t*, int), bool blocking);
  void GetKeyValueImpl(void* state, void(*callback)(void*, int, const uint8_t*, int, const uint8_t*, int), bool blocking);
  void GetImpl(const std::vector<uint8_t>& key, void* state, void(*callback)(void*, int, const uint8_t*, int), bool blocking);
  void InsertImpl(common::mojom::KeyValuePtr kv, void* state, void(*callback)(void*, int), bool blocking);
  void DeleteImpl(void* state, void(*callback)(void*, int), bool blocking);
  void CommitImpl(void* state, void(*callback)(void*, int), bool blocking);
  void RollbackImpl(void* state, void(*callback)(void*, int), bool blocking);

  void OnIsValid(bool blocking, void* state, void(*callback)(void*, int), bool valid);
  void OnFirst(bool blocking, void* state, void(*callback)(void*, int), int32_t status);
  void OnLast(bool blocking, void* state, void(*callback)(void*, int), int32_t status);
  void OnPrevious(bool blocking, void* state, void(*callback)(void*, int), int32_t status);
  void OnNext(bool blocking, void* state, void(*callback)(void*, int), int32_t status);
  void OnSeekTo(bool blocking, void* state, void(*callback)(void*, int, int), int32_t result, bool match);
  void OnDataSize(bool blocking, void* state, void(*callback)(void*, int, int), int32_t status, int64_t size);
  void OnCount(bool blocking, void* state, void(*callback)(void*, int, int), int32_t status, int64_t items);
  void OnGetData(bool blocking, void* state, void(*callback)(void*, int, const uint8_t*, int), int32_t status, const std::vector<uint8_t>& data);
  void OnGetKeyValue(bool blocking, void* state, void(*callback)(void*, int, const uint8_t*, int, const uint8_t*, int), int32_t status, common::mojom::KeyValuePtr kv);
  void OnGet(bool blocking, void* state, void(*callback)(void*, int, const uint8_t*, int), int32_t status, common::mojom::KeyValuePtr kv);
  void OnInsert(bool blocking, void* state, void(*callback)(void*, int), int32_t status);
  void OnDelete(bool blocking, void* state, void(*callback)(void*, int), int32_t status);
  void OnCommit(bool blocking, void* state, void(*callback)(void*, int), int32_t status);
  void OnRollback(bool blocking, void* state, void(*callback)(void*, int), int32_t status);
  
  scoped_refptr<domain::StorageContext> context_;
  scoped_refptr<base::SingleThreadTaskRunner> module_task_runner_;
  common::mojom::DataCursorPtr cursor_;
  void* state_;
  void(*callback_)(void*, void*);

  DISALLOW_COPY_AND_ASSIGN(DatabaseCursorState);
};

class DatabaseState {
public:
  DatabaseState(
    const std::string& share,
    const scoped_refptr<domain::StorageContext>& context, 
    domain::ModuleState* module);
  ~DatabaseState();

  const scoped_refptr<domain::StorageContext>& context() const {
    return context_;
  }

  domain::ModuleState* module() const { 
    return module_; 
  }

  void DatabaseClose(void*, void(*)(void*, int));
  void DatabaseGet(void*, const std::string& keyspace, const std::string& key, void(*)(void*, int, SharedMemoryRef));
  void DatabasePut(void*, const std::string& keyspace, const std::string& key, mojo::ScopedSharedBufferHandle value, void(*)(void*, int));
  void DatabaseDelete(void*, const std::string& keyspace, const std::string& key, void(*)(void*, int));
  void DatabaseDeleteAll(void*, const std::string& keyspace, void(*)(void*, int));
  void DatabaseKeyspaceCreate(void*, const std::string& keyspace, void(*)(void*, int));
  void DatabaseKeyspaceDrop(void*, const std::string& keyspace, void(*)(void*, int));
  void DatabaseKeyspaceList(void*, void(*)(void*, int, int, const char**));
  void DatabaseCursorCreate(void*, const std::string& keyspace, common::mojom::Order order, bool write, void (*)(void*, void*));

private:

  void DatabaseCloseImpl(void*, void(*)(void*, int));
  void DatabaseGetImpl(void*, const std::string& keyspace, const std::string& key, void(*)(void*, int, SharedMemoryRef));
  void DatabasePutImpl(void*, const std::string& keyspace, const std::string& key, mojo::ScopedSharedBufferHandle value, void(*)(void*, int));
  void DatabaseDeleteImpl(void*, const std::string& keyspace, const std::string& key, void(*)(void*, int));
  void DatabaseDeleteAllImpl(void*, const std::string& keyspace, void(*)(void*, int));
  void DatabaseKeyspaceCreateImpl(void*, const std::string& keyspace, void(*)(void*, int));
  void DatabaseKeyspaceDropImpl(void*, const std::string& keyspace, void(*)(void*, int));
  void DatabaseKeyspaceListImpl(void*, void(*)(void*, int, int, const char**));
  void DatabaseCursorCreateImpl(const std::string& keyspace, common::mojom::Order order, bool write, DatabaseCursorState* cursor);

  void OnDatabaseClose(void* ptr, void(*cb)(void*, int), int result);
  void OnDatabaseGet(void* ptr, void(*cb)(void*, int, SharedMemoryRef), int result, mojo::ScopedSharedBufferHandle, int bytes);
  void OnDatabasePut(void* ptr, void(*cb)(void*, int), int result);
  void OnDatabaseDelete(void* ptr, void(*cb)(void*, int), int result);
  void OnDatabaseDeleteAll(void* ptr, void(*cb)(void*, int), int result);
  void OnDatabaseKeyspaceCreate(void* ptr, void(*cb)(void*, int), int result);
  void OnDatabaseKeyspaceDrop(void* ptr, void(*cb)(void*, int), int result);
  void OnDatabaseKeyspaceList(void* ptr, void(*cb)(void*, int, int, const char**), int result, int count, const std::vector<std::string>& keyspaces);
  
  std::string share_;
  scoped_refptr<domain::StorageContext> context_;
  domain::ModuleState* module_;
  std::vector<std::unique_ptr<DatabaseCursorState>> cursors_;

  DISALLOW_COPY_AND_ASSIGN(DatabaseState);
};

class SharedMemoryState {
public:
  SharedMemoryState(mojo::SharedBufferHandle shared_handle, int size);
  ~SharedMemoryState();

  int GetSize() const {
    return size_;
  }

  void Map(void* state, void(*cb)(void*, char*, int));
  void ConstMap(void* state, void(*cb)(void*, const char*, int));

private:
  mojo::SharedBufferHandle handle_;
  int size_;

  DISALLOW_COPY_AND_ASSIGN(SharedMemoryState);
};

#endif