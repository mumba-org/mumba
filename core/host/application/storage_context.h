// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_STORAGE_CONTEXT_H_
#define MUMBA_HOST_APPLICATION_STORAGE_CONTEXT_H_

#include "base/macros.h"
#include "base/uuid.h"
#include "base/memory/ref_counted.h"
#include "base/synchronization/lock.h"
#include "base/single_thread_task_runner.h"
#include "base/task_runner.h"
#include "storage/db/db.h"
#include "core/host/share/share_observer.h"
#include "mojo/public/cpp/bindings/binding_set.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "core/shared/common/mojom/storage.mojom.h"

namespace storage {
class StorageManager;
class Transaction;
class Cursor;
}

namespace host {
class Workspace;
class Domain;

class StorageDataCursor : public common::mojom::DataCursor {
public:
  StorageDataCursor(storage::Transaction* transaction, bool write);
  ~StorageDataCursor() override;

  bool is_write() const;
  bool Init(const std::string& keyspace, storage::Order order);
  void IsValid(IsValidCallback callback) override;
  void First(FirstCallback callback) override;
  void Last(LastCallback callback) override;
  void Previous(PreviousCallback callback) override;
  void Next(NextCallback callback) override;
  void SeekTo(const std::vector<uint8_t>& key, common::mojom::Seek seek, SeekToCallback callback) override;
  void DataSize(DataSizeCallback callback) override;
  void Count(CountCallback callback) override;
  void GetData(GetDataCallback callback) override;
  void GetKeyValue(GetKeyValueCallback callback) override;
  void Get(const std::vector<uint8_t>& key, GetCallback callback) override;
  void Insert(common::mojom::KeyValuePtr kv, InsertCallback callback) override;
  void Delete(DeleteCallback callback) override;
  void Commit(CommitCallback callback) override;
  void Rollback(RollbackCallback callback) override;

private:
  storage::Transaction* transaction_;
  storage::Cursor* cursor_;
  bool is_write_;
};

class StorageSQLCursor : public common::mojom::SQLCursor {
public:
  StorageSQLCursor(csqlite_stmt* stmt, int rc, scoped_refptr<base::SequencedTaskRunner> task_runner);
  ~StorageSQLCursor() override;

  void IsValid(IsValidCallback callback) override;
  void First(FirstCallback callback) override;
  void Last(LastCallback callback) override;
  void Previous(PreviousCallback callback) override;
  void Next(NextCallback callback) override;
  void GetBlob(const std::vector<int8_t>& row, GetBlobCallback callback) override;
  void GetString(const std::vector<int8_t>& row, GetStringCallback callback) override;
  void GetInt32(const std::vector<int8_t>& row, GetInt32Callback callback) override;
  void GetInt64(const std::vector<int8_t>& row, GetInt64Callback callback) override;
  void GetDouble(const std::vector<int8_t>& row, GetDoubleCallback callback) override;
  
private:

  int GetColumnIndex(const std::string& name);

  base::Lock lock_;
  csqlite_stmt* stmt_;
  int rc_;
  scoped_refptr<base::SequencedTaskRunner> task_runner_;
  std::unordered_map<std::string, int> colname_map_;
};

// The contexts created by the shells to manage the file io
// each context will be responsible for dispatching the ops
// asked by the shells  
class StorageContext : public ShareObserver,
                       public base::RefCountedThreadSafe<StorageContext> {
public:
  StorageContext(int id, scoped_refptr<Workspace> workspace, Domain* domain);

  int id() const {
    return id_;
  }

  const std::string& domain_name();
  const base::UUID& domain_uuid();
  storage::StorageManager& storage_manager();
  scoped_refptr<base::SequencedTaskRunner> task_runner() const {
    return task_runner_;
  }

  common::mojom::DataCursorPtr CreateBinding(StorageDataCursor* cursor);
  common::mojom::SQLCursorPtr CreateSQLBinding(StorageSQLCursor* cursor);

  // Requests
  int64_t GetAllocatedSize(uint32_t context_id, int32_t req);
  void ListShares(uint32_t context_id, int32_t req, base::OnceCallback<void(std::vector<common::mojom::ShareInfoPtr>)> cb);
  void ListShareEntries(uint32_t context_id, int32_t req, const std::string& tid, base::OnceCallback<void(std::vector<common::mojom::ShareStorageEntryPtr>)> cb);
  void ShareExists(uint32_t context_id, int32_t req, const std::string& tid, base::OnceCallback<void(bool)> cb);
  void ShareCreateWithPath(uint32_t context_id, int32_t req, common::mojom::StorageType type, const std::string& name, const std::vector<std::string>& keyspaces, const std::string& source_path, bool in_memory);
  void ShareCreateWithInfohash(uint32_t context_id, int32_t req, common::mojom::StorageType type, const std::string& name, const std::vector<std::string>& keyspaces, const std::string& infohash);
  void ShareAdd(uint32_t context_id, int32_t req, const std::string& tid, const std::string& url);
  void ShareOpen(uint32_t context_id, int32_t req, common::mojom::StorageType type, const std::string& tid, bool create_if_not_exists);
  void ShareRead(uint32_t context_id, int32_t req, const std::string& tid, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data);
  void ShareWrite(uint32_t context_id, int32_t req, const std::string& tid, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data);
  void ShareClose(uint32_t context_id, int32_t req, const std::string& tid);
  void ShareDelete(uint32_t context_id, int32_t req, const std::string& tid);
  void ShareShare(uint32_t context_id, int32_t req, const std::string& tid);
  void ShareUnshare(uint32_t context_id, int32_t req, const std::string& tid);
  void ShareSubscribe(uint32_t context_id, int32_t req, const std::string& tid);
  void ShareUnsubscribe(uint32_t context_id, int32_t req, const std::string& tid);
  void FileCreate(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file);
  void FileAdd(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file, const std::string& path);
  void FileOpen(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file);
  void FileDelete(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file);
  void FileRename(uint32_t context_id, int32_t req, const std::string& tid, const std::string& input, const std::string& output);
  void FileReadOnce(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file, int64_t offset, int64_t size);
  void FileRead(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data);
  void FileWrite(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data);
  void FileWriteOnce(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file, int64_t offset, int64_t size, const std::vector<uint8_t>& data);
  void FileClose(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file);
 
  void DataClose(uint32_t context_id, int32_t req, const std::string& tid);
  void DataDrop(uint32_t context_id, int32_t req, const std::string& tid);
  void DataCreateKeyspace(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace);
  void DataDeleteKeyspace(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace);
  void DataListKeyspaces(uint32_t context_id, int32_t req, const std::string& tid);
  void DataDelete(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace, const std::string& key);
  void DataDeleteAll(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace);
  void DataPut(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace, const std::string& key, int64_t size, mojo::ScopedSharedBufferHandle data);
  void DataGetOnce(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace, const std::string& key);
  void DataGet(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace, const std::string& key, int64_t size, mojo::ScopedSharedBufferHandle data);
  void DataCreateCursor(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace, common::mojom::Order order, bool write, common::mojom::StorageDispatcherHost::DataCreateCursorCallback callback);
  void DataExecuteQuery(uint32_t context_id, int32_t req, const std::string& tid, const std::string& query, common::mojom::StorageDispatcherHost::DataExecuteQueryCallback callback);
  void IndexResolveId(uint32_t context_id, int32_t req, const std::string& address);

private:

  friend class base::RefCountedThreadSafe<StorageContext>;
  friend class Domain;
  
  void ListSharesImpl(uint32_t context_id, int32_t req, base::OnceCallback<void(std::vector<common::mojom::ShareInfoPtr>)> , std::vector<std::unique_ptr<storage_proto::Info>>, int64_t);
  void ListShareEntriesImpl(uint32_t context_id, int32_t req, const std::string& tid, base::OnceCallback<void(std::vector<common::mojom::ShareStorageEntryPtr>)> cb, std::vector<std::unique_ptr<storage_proto::Info>>, int64_t);

  void ShareExistsImpl(uint32_t context_id, int32_t req, const std::string& tid, base::OnceCallback<void(bool)> cb);
  void ShareCreateWithPathImpl(uint32_t context_id, int32_t req, common::mojom::StorageType type, const std::string& name, const std::vector<std::string>& keyspaces, const std::string& source_path, bool in_memory);
  void ShareCreateWithInfohashImpl(uint32_t context_id, int32_t req, common::mojom::StorageType type, const std::string& name, const std::vector<std::string>& keyspaces, const std::string& infohash);
  void ShareAddImpl(const std::string& tid, const std::string& url);
  void ShareOpenImpl(uint32_t context_id, int32_t req, common::mojom::StorageType type, const std::string& tid, bool create_if_not_exists);
  void ShareReadImpl(uint32_t context_id, int32_t req, const std::string& tid, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data);
  void ShareWriteImpl(uint32_t context_id, int32_t req, const std::string& tid, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data);
  void ShareCloseImpl(uint32_t context_id, int32_t req, const std::string& tid);
  void ShareDeleteImpl(uint32_t context_id, int32_t req, const std::string& tid);
  void ShareShareImpl(const std::string& tid);
  void ShareUnshareImpl(const std::string& tid);
  void ShareSubscribeImpl(const std::string& tid);
  void ShareUnsubscribeImpl(const std::string& tid);
  void FileCreateImpl(const std::string& tid, const std::string& file);
  void FileAddImpl(const std::string& tid, const std::string& file, const std::string& path);
  void FileOpenImpl(const std::string& tid, const std::string& file);
  void FileDeleteImpl(const std::string& tid, const std::string& file);
  void FileRenameImpl(const std::string& tid, const std::string& input, const std::string& output);
  void FileReadOnceImpl(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file, int64_t offset, int64_t size);
  void OnFileReadOnce(uint32_t context_id, int32_t req, base::UUID uuid, const std::string& file, int64_t file_size, mojo::ScopedSharedBufferHandle file_data, int64_t result);
  void FileReadImpl(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data);
  void FileWriteImpl(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data);
  void FileWriteOnceImpl(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file, int64_t offset, int64_t size, const std::vector<uint8_t>& data);
  void OnFileWriteOnce(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file, int64_t file_size, int64_t result);
  //void DataOpenImpl(uint32_t context_id, int32_t req, const std::string& tid);
  void FileCloseImpl(const std::string& tid, const std::string& file);
  
  //int64_t DataCreateImpl(const std::string& tid);
  void DataCloseImpl(uint32_t context_id, int32_t req, const std::string& tid);
  void DataDropImpl(uint32_t context_id, int32_t req, const std::string& tid);
  void DataCreateKeyspaceImpl(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace);
  void DataDeleteKeyspaceImpl(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace);
  void DataListKeyspacesImpl(uint32_t context_id, int32_t req, const std::string& tid);
  void DataDeleteImpl(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace, const std::string& key);
  void DataDeleteAllImpl(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace);
  void DataPutImpl(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace, const std::string& key, int64_t size, mojo::ScopedSharedBufferHandle data);
  void DataGetImpl(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace, const std::string& key, int64_t size, mojo::ScopedSharedBufferHandle data);
  void DataGetOnceImpl(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace, const std::string& key);
  void DataCreateCursorImpl(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace, common::mojom::Order order, bool write, common::mojom::StorageDispatcherHost::DataCreateCursorCallback callback);
  void DataExecuteQueryImpl(uint32_t context_id, int32_t req, const std::string& tid, const std::string& query, common::mojom::StorageDispatcherHost::DataExecuteQueryCallback callback);
  void IndexResolveIdImpl(uint32_t context_id, int32_t req, const std::string& address);
  
  // Responses
  void ReplyContextDestroy(uint32_t context_id, int64_t status);
  void ReplyShareExistsOnIOThread(uint32_t context_id, int32_t req, base::UUID uuid, base::OnceCallback<void(bool)> cb, bool exists);
  void ReplyShareCreate(uint32_t context_id, int32_t req, base::UUID uuid, int64_t result);
  void ReplyShareCreateOnIOThread(uint32_t context_id, int32_t req, base::UUID uuid, int64_t result);
  void ReplyShareAdd(uint32_t context_id, int32_t req, base::UUID uuid, int64_t status);
  void ReplyShareOpen(uint32_t context_id, int32_t req, base::UUID uuid, int64_t status);
  void ReplyShareOpenOnIOThread(uint32_t context_id, int32_t req, base::UUID uuid, int64_t status);
  void ReplyShareClose(uint32_t context_id, int32_t req, base::UUID uuid, int64_t status);
  void ReplyShareDelete(uint32_t context_id, int32_t req, base::UUID uuid, int64_t status);
  void ReplyShareRead(uint32_t context_id, int32_t req, base::UUID uuid, int64_t status, int64_t bytes_readed);
  void ReplyShareWrite(uint32_t context_id, int32_t req, base::UUID uuid, int64_t status, int64_t bytes_written);
  void ReplySharePaused(uint32_t context_id, int32_t req, base::UUID uuid);
  void ReplyShareResumed(uint32_t context_id, int32_t req, base::UUID uuid);
  void ReplyShareChecked(uint32_t context_id, int32_t req, base::UUID uuid, int64_t status);
  void ReplyShareDownloading(uint32_t context_id, int32_t req, base::UUID uuid);
  void ReplyShareComplete(uint32_t context_id, int32_t req, base::UUID uuid);
  void ReplyShareSeeding(uint32_t context_id, int32_t req, base::UUID uuid);
  void ReplyShareShare(uint32_t context_id, int32_t req, base::UUID uuid, int64_t status);
  void ReplyShareUnshare(uint32_t context_id, int32_t req, base::UUID uuid, int64_t status);
  void ReplyShareSubscribe(uint32_t context_id, int32_t req, base::UUID uuid, int64_t status);
  void ReplyShareUnsubscribe(uint32_t context_id, int32_t req, base::UUID uuid, int64_t status);
  void ReplyShareEvent(uint32_t context_id, int32_t req, base::UUID uuid, common::mojom::ShareEventPtr event);
  void ReplyFileCreate(uint32_t context_id, int32_t req, base::UUID uuid, const std::string& file, int64_t status);
  void ReplyFileAdd(uint32_t context_id, int32_t req, base::UUID uuid, const std::string& file, int64_t status);
  void ReplyFileOpen(uint32_t context_id, int32_t req, base::UUID uuid, const std::string& file, int64_t status);
  void ReplyFileDelete(uint32_t context_id, int32_t req, base::UUID uuid, const std::string& file, int64_t status);
  void ReplyFileReadOnce(uint32_t context_id, int32_t req, base::UUID uuid, const std::string& file, int64_t status, int64_t bytes_readed, mojo::ScopedSharedBufferHandle data);
  void ReplyFileRead(uint32_t context_id, int32_t req, base::UUID uuid, const std::string& file, int64_t status, int64_t bytes_written);
  void ReplyFileWrite(uint32_t context_id, int32_t req, base::UUID uuid, const std::string& file, int64_t status, int64_t bytes_written);
  void ReplyFileWriteOnce(uint32_t context_id, int32_t req, base::UUID uuid, const std::string& file, int64_t status, int64_t bytes_readed);
  void ReplyFileClose(uint32_t context_id, int32_t req, base::UUID uuid, const std::string& file, int64_t status);
  void ReplyFileRename(uint32_t context_id, int32_t req, base::UUID uuid, const std::string& file, int64_t status);
  
  //void ReplyDataOpen(uint32_t context_id, int32_t req, const std::string& tid, int64_t status);
  //void ReplyDataOpenOnIOThread(uint32_t context_id, int32_t req, const std::string& tid, int64_t status);
  void ReplyDataClose(uint32_t context_id, int32_t req, base::UUID uuid, int64_t status);
  void ReplyDataCloseOnIOThread(uint32_t context_id, int32_t req, base::UUID uuid, int64_t status);
  //void ReplyDataCreate(uint32_t context_id, int32_t req, const std::string& tid, int64_t status);
  void ReplyDataDrop(uint32_t context_id, int32_t req, base::UUID uuid, int64_t status);
  void ReplyDataCreateKeyspace(uint32_t context_id, int32_t req, base::UUID uuid, const std::string& keyspace, int64_t status);
  void ReplyDataDeleteKeyspace(uint32_t context_id, int32_t req, base::UUID uuid, const std::string& keyspace, int64_t status);
  void ReplyDataListKeyspaces(uint32_t context_id, int32_t req, base::UUID uuid, int64_t status, std::vector<std::string> keyspaces);
  void ReplyDataPut(uint32_t context_id, int32_t req, base::UUID uuid, const std::string& keyspace, int64_t status, int64_t wrote);
  void ReplyDataGet(uint32_t context_id, int32_t req, base::UUID uuid, const std::string& keyspace, int64_t status, int64_t wrote);
  void ReplyDataGetOnce(uint32_t context_id, int32_t req, base::UUID uuid, const std::string& keyspace, int64_t status, int64_t readed, mojo::ScopedSharedBufferHandle data);
  void ReplyDataDelete(uint32_t context_id, int32_t req, base::UUID uuid, const std::string& keyspace, int64_t status);
  void ReplyDataDeleteAll(uint32_t context_id, int32_t req, base::UUID uuid, const std::string& keyspace, int64_t status);
  void ReplyIndexResolveId(uint32_t context_id, int32_t req, const std::string& address, base::UUID resolved, int64_t status);
  void ReplyCreateCursor(common::mojom::StorageDispatcherHost::DataCreateCursorCallback callback, bool ok, common::mojom::DataCursorPtr cursor);
  void ReplyExecuteQuery(common::mojom::StorageDispatcherHost::DataExecuteQueryCallback callback, bool ok, common::mojom::SQLCursorPtr cursor);
  
  void ReplySharePieceRead(uint32_t context_id, int32_t req, base::UUID uuid, int piece, int64_t offset, int64_t size, int64_t block_size, int result);
  void ReplySharePieceWrite(uint32_t context_id, int32_t req, base::UUID uuid, int piece, int64_t offset, int64_t size, int64_t block_size, int result);
  void ReplySharePieceFailed(uint32_t context_id, int32_t req, base::UUID uuid, int piece);
  void ReplySharePieceHashFailed(uint32_t context_id, int32_t req, base::UUID uuid, int piece);
  void ReplySharePieceComplete(uint32_t context_id, int32_t req, base::UUID uuid, uint32_t piece_offset);
  void ReplySharePiecePass(uint32_t context_id, int32_t req, base::UUID uuid, int piece);
  void ReplyShareFileComplete(uint32_t context_id, int32_t req, base::UUID uuid, int file_offset);
  void ReplySharePieceReadError(uint32_t context_id, int32_t req, base::UUID uuid, int piece, int error);
  void ReplyShareMetadataError(uint32_t context_id, int32_t req, base::UUID uuid, int error);
  void ReplyShareMetadataReceived(uint32_t context_id, int32_t req, base::UUID uuid);
  void ReplyShareDHTAnnounceReply(uint32_t context_id, int32_t req, base::UUID uuid, int peers);
  void ReplyShareDownloadingMetadata(uint32_t context_id, int32_t req, base::UUID uuid);
  void ReplyShareCheckingFiles(uint32_t context_id, int32_t req, base::UUID uuid);
  void ReplyShareFileRenamed(uint32_t context_id, int32_t req, base::UUID uuid, int file_offset, const std::string& name);
  void ReplyShareFileRenamedError(uint32_t context_id, int32_t req, base::UUID uuid, int file_offset, int error);

  // ShareObserver
  void OnDHTAnnounceReply(Share* share, int peers) override;
  void OnShareMetadataReceived(Share* share) override;
  void OnShareMetadataError(Share* share, int error) override;
  void OnSharePieceReadError(Share* share, int piece_offset, int error) override;
  void OnSharePiecePass(Share* share, int piece_offset) override;
  void OnSharePieceFailed(Share* share, int piece_offset) override;
  void OnSharePieceRead(Share* share, int piece, int64_t offset, int64_t size, int64_t block_size, int result) override;
  void OnSharePieceWrite(Share* share, int piece, int64_t offset, int64_t size, int64_t block_size, int result) override;
  void OnSharePieceFinished(Share* share, int piece_offset) override;
  void OnSharePieceHashFailed(Share* share, int piece_offset) override;
  void OnShareFileCompleted(Share* share, int piece_offset) override;
  void OnShareFinished(Share* share) override;
  void OnShareDownloading(Share* share) override;
  void OnShareCheckingFiles(Share* share) override;
  void OnShareDownloadingMetadata(Share* share) override;
  void OnShareSeeding(Share* share) override;
  void OnSharePaused(Share* share) override;
  void OnShareResumed(Share* share) override;
  void OnShareChecked(Share* share) override;
  void OnShareDeleted(Share* share) override;
  void OnShareDeletedError(Share* share, int error) override;
  void OnShareFileRenamed(Share* share, int file_offset, const std::string& name) override;
  void OnShareFileRenamedError(Share* share, int index, int error) override;

  ~StorageContext();
  
  int id_;
  scoped_refptr<Workspace> workspace_;
  Domain* domain_;
  //scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
  scoped_refptr<base::SequencedTaskRunner> task_runner_;
  std::vector<std::unique_ptr<StorageDataCursor>> cursors_;
  std::vector<std::unique_ptr<StorageSQLCursor>> sql_cursors_;
  mojo::BindingSet<common::mojom::DataCursor> cursor_bindings_;
  mojo::BindingSet<common::mojom::SQLCursor> sql_cursor_bindings_;
  base::Lock domain_lock_;
  base::Lock workspace_lock_;

  DISALLOW_COPY_AND_ASSIGN(StorageContext);
};

}

#endif