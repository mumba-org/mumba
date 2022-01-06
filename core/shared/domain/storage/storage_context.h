// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_STORAGE_STORAGE_CONTEXT_H_
#define MUMBA_DOMAIN_STORAGE_STORAGE_CONTEXT_H_

#include <unordered_map>

#include "base/macros.h"
#include "base/uuid.h"
#include "base/atomic_sequence_num.h"
#include "base/callback.h"
#include "base/memory/ref_counted.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/mojom/storage.mojom.h"

namespace domain {
class StorageDispatcher;
class StorageManager;
class DataStorage;
class ShareStorage;
class FileStorage;
class StorageIndex;

class CONTENT_EXPORT StorageDataCursorDelegate {
public:
  virtual ~StorageDataCursorDelegate() {}
  virtual void OnCursorAvailable(common::mojom::DataCursorPtr cursor) = 0;
};

class CONTENT_EXPORT StorageFileCursorDelegate {
public:
  virtual ~StorageFileCursorDelegate() {}
  virtual void OnCursorAvailable(common::mojom::FileCursorPtr cursor) = 0;
};

class CONTENT_EXPORT StorageShareObserver {
public:
  virtual ~StorageShareObserver() {}
  virtual void OnShareDHTAnnounceReply(const base::UUID& tid, int32_t peers) = 0;
  virtual void OnShareMetadataReceived(const base::UUID& tid) = 0;
  virtual void OnShareMetadataError(const base::UUID& tid, int32_t error) = 0;
  virtual void OnSharePieceReadError(const base::UUID& tid, int32_t piece, int32_t error) = 0;
  virtual void OnSharePiecePass(const base::UUID& tid, int32_t piece) = 0;
  virtual void OnSharePieceFailed(const base::UUID& tid, int32_t piece) = 0;
  virtual void OnSharePieceRead(const base::UUID& tid, int32_t piece, int64_t offset, int64_t size, int64_t block_size, int32_t result) = 0;
  virtual void OnSharePieceWrite(const base::UUID& tid, int32_t piece, int64_t offset, int64_t size, int64_t block_size, int32_t result) = 0;
  virtual void OnSharePieceHashFailed(const base::UUID& tid, int32_t piece) = 0;
  virtual void OnShareCheckingFiles(const base::UUID& tid) = 0;
  virtual void OnShareDownloadingMetadata(const base::UUID& tid) = 0;
  virtual void OnShareFileRenamed(const base::UUID& tid, int32_t file_offset, const std::string& name, int32_t error) = 0;
  virtual void OnShareResumed(const base::UUID& tid) = 0;
  virtual void OnShareChecked(const base::UUID& tid, common::mojom::DomainStatus status) = 0;
  virtual void OnSharePieceComplete(const base::UUID& tid, uint32_t piece_offset) = 0;
  virtual void OnShareFileComplete(const base::UUID& tid, int file_offset) = 0;
  virtual void OnShareDownloading(const base::UUID& tid) = 0;
  virtual void OnShareComplete(const base::UUID& tid) = 0;
  virtual void OnShareSeeding(const base::UUID& tid) = 0;
  virtual void OnSharePaused(const base::UUID& tid) = 0;
};

class CONTENT_EXPORT StorageContext : public base::RefCountedThreadSafe<StorageContext> {
public:
  StorageContext(StorageManager* manager);

  void set_shared_context(common::mojom::StorageContextPtr shared_context) {
    shared_context_ = std::move(shared_context);
    wait_for_shared_context_.Signal();
  }

  const scoped_refptr<base::SingleThreadTaskRunner>& GetMainTaskRunner() const;
  const scoped_refptr<base::SingleThreadTaskRunner>& GetIOTaskRunner() const;

  int id() const {
    return shared_context_->id;
  }

  DataStorage& data() {
    return *data_storage_;
  }

  FileStorage& file() {
    return *file_storage_;
  }

  ShareStorage& share() {
    return *share_storage_;
  }

  StorageIndex& index() {
    return *storage_index_;
  }

  void GetAllocatedSize(base::Callback<void(int64_t)> callback);
  void ListShares(base::Callback<void(std::vector<common::mojom::ShareInfoPtr>)> callback);
  void ListShareEntries(const base::UUID& tid, 
    base::Callback<void(std::vector<common::mojom::ShareStorageEntryPtr>)> callback);

  void CreateDatabaseCursor(
    const std::string& db_name, 
    const std::string& keyspace, 
    common::mojom::Order order, 
    bool write, 
    StorageDataCursorDelegate* cursor_delegate);

  void AddShareObserver(base::WeakPtr<StorageShareObserver> observer);
  void RemoveShareObserver(StorageShareObserver* observer);

private:
  friend class base::RefCountedThreadSafe<StorageContext>;
  friend class StorageDispatcher;
  friend class DataStorage;
  friend class FileStorage;
  friend class ShareStorage;
  friend class StorageIndex;

  struct RequestData {
    base::Callback<void(int)> callback;
    base::Callback<void(int, int)> size_callback;
    base::Callback<void(int, mojo::ScopedSharedBufferHandle, int)> sharedbuf_callback;
    base::Callback<void(base::UUID, int)> uuid_callback;
    base::Callback<void(int, int, const std::vector<std::string>&)> list_keyspaces_callback;
  };

  ~StorageContext();

  void ShareCreateWithPath(common::mojom::StorageType type, const std::string& name, std::vector<std::string> keyspaces, const std::string& source_path, base::Callback<void(int)> cb);
  void ShareCreateWithInfohash(common::mojom::StorageType type, const std::string& name, std::vector<std::string> keyspaces, const std::string& infohash, base::Callback<void(int)> cb);
  void ShareAdd(const base::UUID& tid, const std::string& url, base::Callback<void(int)> cb);
  void ShareOpen(common::mojom::StorageType type, const std::string& name, bool create_if_not_exists, base::Callback<void(int)> cb);
  void ShareExists(const std::string& name, base::Callback<void(int)> cb);
  void ShareRead(const base::UUID& tid, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data, base::Callback<void(int)> cb);
  void ShareWrite(const base::UUID& tid, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data, base::Callback<void(int)> cb);
  void ShareClose(const std::string& name, base::Callback<void(int)> cb);
  void ShareDelete(const base::UUID& tid, base::Callback<void(int)> cb);
  void ShareShare(const base::UUID& tid, base::Callback<void(int)> cb);
  void ShareUnshare(const base::UUID& tid, base::Callback<void(int)> cb);
  void ShareSubscribe(const base::UUID& tid, base::Callback<void(int)> cb);
  void ShareUnsubscribe(const base::UUID& tid, base::Callback<void(int)> cb);
  void FileCreate(const std::string& share_name, const std::string& file, base::Callback<void(int)> cb);
  void FileAdd(const std::string& share_name, const std::string& file, const std::string& path, base::Callback<void(int)> cb);
  void FileOpen(const std::string& share_name, const std::string& file, base::Callback<void(int)> cb);
  void FileDelete(const std::string& share_name, const std::string& file, base::Callback<void(int)> cb);
  void FileRename(const std::string& share_name, const std::string& input, const std::string& output, base::Callback<void(int)> cb);
  void FileRead(const std::string& share_name, const std::string& file, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data, base::Callback<void(int)> cb);
  void FileReadOnce(const std::string& share_name, const std::string& file, int64_t offset, int64_t size, base::Callback<void(int, mojo::ScopedSharedBufferHandle, int)> cb);
  void FileWrite(const std::string& share_name, const std::string& file, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data, base::Callback<void(int)> cb);
  void FileWriteOnce(const std::string& share_name, const std::string& file, int64_t offset, int64_t size, std::vector<uint8_t> data, base::Callback<void(int, int)> cb);
  void FileClose(const std::string& share_name, const std::string& file, base::Callback<void(int)> cb);
  void FileList(const std::string& share_name, base::Callback<void(std::vector<common::mojom::ShareStorageEntryPtr>)> callback);
  
  //void DataOpen(const base::UUID& tid, base::Callback<void(int)> cb);
  void DataClose(const std::string& db_name, base::Callback<void(int)> cb);
  //void DataCreate(const base::UUID& tid, base::Callback<void(int)> cb);
  void DataDrop(const std::string& db_name, base::Callback<void(int)> cb);
  void DataCreateKeyspace(const std::string& db_name, const std::string& keyspace, base::Callback<void(int)> cb);
  void DataDeleteKeyspace(const std::string& db_name, const std::string& keyspace, base::Callback<void(int)> cb);
  void DataListKeyspaces(const std::string& db_name, base::Callback<void(int, int, const std::vector<std::string>&)> cb);
  void DataPut(const std::string& db_name, const std::string& keyspace, const std::string& key, int64_t size, mojo::ScopedSharedBufferHandle data, base::Callback<void(int)> cb);
  void DataGet(const std::string& db_name, const std::string& keyspace, const std::string& key, int64_t size, mojo::ScopedSharedBufferHandle data, base::Callback<void(int)> cb);
  void DataGetOnce(const std::string& db_name, const std::string& keyspace, const std::string& key, base::Callback<void(int, mojo::ScopedSharedBufferHandle, int)> cb);
  void DataDelete(const std::string& db_name, const std::string& keyspace, const std::string& key, base::Callback<void(int)> cb);
  void DataDeleteAll(const std::string& db_name, const std::string& keyspace, base::Callback<void(int)> cb);
  void IndexResolveId(const std::string& address, base::Callback<void(base::UUID, int)> callback);
  void CreateDatabaseCursorImpl(StorageDataCursorDelegate* cursor_delegate, common::mojom::DataCursorPtr in_cursor);

  // response handlers
  void OnDestroy(common::mojom::DomainStatus status);
  void OnShareCreate(int req, const std::string& tid, common::mojom::DomainStatus status);
  void OnShareAdd(int req, const base::UUID& tid, common::mojom::DomainStatus status);
  void OnShareOpen(int req, const std::string& tid, common::mojom::DomainStatus status);
  void OnShareClose(int req, const base::UUID& tid, common::mojom::DomainStatus status);
  void OnShareDelete(int req, const base::UUID& tid, common::mojom::DomainStatus status);
  void OnShareRead(int req, const base::UUID& tid, common::mojom::DomainStatus status, int64_t bytes_readed);
  void OnShareWrite(int req, const base::UUID& tid, common::mojom::DomainStatus status, int64_t bytes_written);
  void OnShareExists(int req, const std::string& tid, bool result);
  void OnShareShare(int req, const base::UUID& tid, common::mojom::DomainStatus status);
  void OnShareUnshare(int req, const base::UUID& tid, common::mojom::DomainStatus status);
  void OnShareSubscribe(int req, const base::UUID& tid, common::mojom::DomainStatus status);
  void OnShareUnsubscribe(int req, const base::UUID& tid, common::mojom::DomainStatus status);
  void OnShareEvent(int req, const base::UUID& tid, common::mojom::ShareEventPtr event);
  void OnFileCreate(int req, const base::UUID& tid, const std::string& file, common::mojom::DomainStatus status);
  void OnFileAdd(int req, const base::UUID& tid, const std::string& file, common::mojom::DomainStatus status);
  void OnFileOpen(int req, const base::UUID& tid, const std::string& file, common::mojom::DomainStatus status);
  void OnFileDelete(int req, const base::UUID& tid, const std::string& file, common::mojom::DomainStatus status);
  void OnFileReadOnce(int req, const std::string& tid, const std::string& file, common::mojom::DomainStatus status, int64_t bytes_readed, mojo::ScopedSharedBufferHandle data);
  void OnFileRead(int req, const base::UUID& tid, const std::string& file, common::mojom::DomainStatus status, int64_t bytes_written);
  void OnFileWrite(int req, const base::UUID& tid, const std::string& file, common::mojom::DomainStatus status, int64_t bytes_written);
  void OnFileWriteOnce(int req, const std::string& tid, const std::string& file, common::mojom::DomainStatus status, int64_t bytes_written);
  void OnFileClose(int req, const base::UUID& tid, const std::string& file, common::mojom::DomainStatus status);
  void OnFileRename(int req, const base::UUID& tid, const std::string& file, common::mojom::DomainStatus status);
  void OnFileList(base::Callback<void(std::vector<common::mojom::ShareStorageEntryPtr>)> reply_cb, uint32_t context_id, int req, std::vector<common::mojom::ShareStorageEntryPtr> entries);
  void OnDataClose(int req, const std::string& tid, common::mojom::DomainStatus status);
  void OnDataDrop(int req, const std::string& tid, common::mojom::DomainStatus status);
  void OnDataCreateKeyspace(int req, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status);
  void OnDataDeleteKeyspace(int req, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status);
  void OnDataListKeyspaces(int req, const std::string& tid, common::mojom::DomainStatus status, const std::vector<std::string>& keyspaces);
  void OnDataPut(int req, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status, int64_t wrote);
  void OnDataGet(int req, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status, int64_t wrote);
  void OnDataGetOnce(int req, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status, int64_t readed, mojo::ScopedSharedBufferHandle data);
  void OnDataGetFailed(int req, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status);
  void OnDataDelete(int req, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status);
  void OnDataDeleteAll(int req, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status);
  void OnIndexResolveId(int req, const std::string& name, base::UUID id, common::mojom::DomainStatus status);
  void OnGetAllocatedSize(base::Callback<void(int64_t)> reply_cb, uint32_t context_id, int req, int64_t size);
  void OnListShares(base::Callback<void(std::vector<common::mojom::ShareInfoPtr>)> reply_cb, uint32_t context_id, int req, std::vector<common::mojom::ShareInfoPtr> shares);
  void OnListShareEntries(base::Callback<void(std::vector<common::mojom::ShareStorageEntryPtr>)> reply_cb, uint32_t context_id, int req, std::vector<common::mojom::ShareStorageEntryPtr> entries);

  void OnShareDHTAnnounceReply(const base::UUID& tid, int32_t peers);
  void OnShareMetadataReceived(const base::UUID& tid);
  void OnShareMetadataError(const base::UUID& tid, int32_t error);
  void OnSharePieceReadError(const base::UUID& tid, int32_t piece, int32_t error);
  void OnSharePiecePass(const base::UUID& tid, int32_t piece);
  void OnSharePieceFailed(const base::UUID& tid, int32_t piece);
  void OnSharePieceRead(const base::UUID& tid, int32_t piece, int64_t offset, int64_t size, int64_t block_size, int32_t result);
  void OnSharePieceWrite(const base::UUID& tid, int32_t piece, int64_t offset, int64_t size, int64_t block_size, int32_t result);
  void OnSharePieceHashFailed(const base::UUID& tid, int32_t piece);
  void OnShareCheckingFiles(const base::UUID& tid);
  void OnShareDownloadingMetadata(const base::UUID& tid);
  void OnShareFileRenamed(const base::UUID& tid, int32_t file_offset, const std::string& name, int32_t error);
  void OnShareResumed(const base::UUID& tid);
  void OnShareChecked(const base::UUID& tid, common::mojom::DomainStatus status);
  void OnSharePieceComplete(const base::UUID& tid, uint32_t piece_offset);
  void OnShareFileComplete(const base::UUID& tid, int file_offset);
  void OnShareDownloading(const base::UUID& tid);
  void OnShareComplete(const base::UUID& tid);
  void OnShareSeeding(const base::UUID& tid);
  void OnSharePaused(const base::UUID& tid);
  

  int CreateRequest();
  int CreateRequest(base::Callback<void(int)> cb);
  int CreateRequest(base::Callback<void(int, int)> cb);
  int CreateRequest(base::Callback<void(int, mojo::ScopedSharedBufferHandle, int)> cb);
  int CreateRequest(base::Callback<void(base::UUID, int)> cb);
  int CreateRequest(base::Callback<void(int, int, const std::vector<std::string>&)> cb);

  RequestData PopRequest(int req_id);

  void WaitForSharedContextIfNecessary() {
    if (shared_context_) {
      return;
    }
    //DLOG(INFO) << "shared context are not here yet, waiting..";
    wait_for_shared_context_.Wait();    
    //DLOG(INFO) << "shared context is here. wait ended";
  }

  common::mojom::StorageContextPtr shared_context_;

  StorageManager* manager_;
  StorageDispatcher* dispatcher_;

  std::unique_ptr<DataStorage> data_storage_;
  std::unique_ptr<FileStorage> file_storage_;
  std::unique_ptr<ShareStorage> share_storage_;
  std::unique_ptr<StorageIndex> storage_index_;

  base::AtomicSequenceNumber req_sequence_;

  base::Lock requests_lock_;
  std::unordered_map<int, RequestData> requests_;

  bool going_away_;

  std::vector<base::WeakPtr<StorageShareObserver>> share_observers_;

  base::WaitableEvent wait_for_shared_context_;

  DISALLOW_COPY_AND_ASSIGN(StorageContext);
};

}

#endif