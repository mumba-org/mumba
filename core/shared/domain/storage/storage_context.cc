// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/storage/storage_context.h"

#include "net/base/net_errors.h"
#include "core/shared/domain/storage/data_storage.h"
#include "core/shared/domain/storage/file_storage.h"
#include "core/shared/domain/storage/share_storage.h"
#include "core/shared/domain/storage/storage_index.h"
#include "core/shared/domain/storage/storage_dispatcher.h"
#include "core/shared/domain/storage/storage_manager.h"

namespace domain {

StorageContext::StorageContext(StorageManager* manager):
  manager_(manager),
  dispatcher_(manager->storage_dispatcher()),
  data_storage_(new DataStorage(this)),
  file_storage_(new FileStorage(this)),
  share_storage_(new ShareStorage(this)),
  storage_index_(new StorageIndex(this)),
  going_away_(false),
  wait_for_shared_context_(base::WaitableEvent::ResetPolicy::AUTOMATIC, base::WaitableEvent::InitialState::NOT_SIGNALED) {

}

StorageContext::~StorageContext() {
  
}

const scoped_refptr<base::SingleThreadTaskRunner>& StorageContext::GetMainTaskRunner() const {
  return manager_->main_task_runner();
}

const scoped_refptr<base::SingleThreadTaskRunner>& StorageContext::GetIOTaskRunner() const {
  return manager_->io_task_runner();
}

void StorageContext::GetAllocatedSize(base::Callback<void(int64_t)> callback) {
  int req = CreateRequest();
  dispatcher_->GetStorageDispatcherHostInterface()->StorageGetAllocatedSize(
    shared_context_->id, 
    req, 
    base::Bind(&StorageContext::OnGetAllocatedSize, this, std::move(callback)));
}

void StorageContext::ListShares(base::Callback<void(std::vector<common::mojom::ShareInfoPtr>)> callback) {
  int req = CreateRequest();
  dispatcher_->GetStorageDispatcherHostInterface()->StorageListShares(
    shared_context_->id, 
    req, 
    base::Bind(&StorageContext::OnListShares, this, std::move(callback)));
}

void StorageContext::ListShareEntries(
    const base::UUID& tid, 
    base::Callback<void(std::vector<common::mojom::ShareStorageEntryPtr>)> callback) {
  int req = CreateRequest();
  dispatcher_->GetStorageDispatcherHostInterface()->StorageListShareEntries(
    shared_context_->id, 
    req,
    std::string(reinterpret_cast<const char *>(tid.data), 16),
    base::Bind(&StorageContext::OnListShareEntries, this, std::move(callback)));
}

void StorageContext::CreateDatabaseCursor(
  const std::string& db_name, 
  const std::string& keyspace, 
  common::mojom::Order order, 
  bool write,
  StorageDataCursorDelegate* cursor_delegate) {
 //DLOG(INFO) << "StorageContext::CreateDatabaseCursor: cursor_delegate: " << cursor_delegate;
 // DataCreateCursor(uint32 context_id, int32 req, string tid, string keyspace, Order order, bool write) => (DataCursor? cursor);
  int req = CreateRequest();
  dispatcher_->GetStorageDispatcherHostInterface()->DataCreateCursor(
    shared_context_->id, 
    req,
    db_name,
    keyspace,
    order,
    write, 
    base::Bind(&StorageContext::CreateDatabaseCursorImpl, 
      this, 
      base::Unretained(cursor_delegate)));
}

void StorageContext::ExecuteQuery(const std::string& db_name, const std::string& query, StorageDataCursorDelegate* cursor_delegate) {
  int req = CreateRequest();
  DLOG(INFO) << "StorageContext::ExecuteQuery: calling StorageDispatcherHost->DataExecuteQuery(): '" << query << "'";
  dispatcher_->GetStorageDispatcherHostInterface()->DataExecuteQuery(
    shared_context_->id, 
    req,
    db_name,
    query,
    base::Bind(&StorageContext::ExecuteQueryImpl, 
      this, 
      base::Unretained(cursor_delegate)));
}

void StorageContext::ShareCreateWithPath(common::mojom::StorageType type, const std::string& name, std::vector<std::string> keyspaces, const std::string& source_path, bool in_memory, base::Callback<void(int)> cb) {
  int req = CreateRequest(std::move(cb));
  dispatcher_->GetStorageDispatcherHostInterface()->ShareCreateWithPath(shared_context_->id, req, type, name, std::move(keyspaces), source_path, in_memory);
}

void StorageContext::ShareCreateWithInfohash(common::mojom::StorageType type, const std::string& name, std::vector<std::string> keyspaces, const std::string& infohash, base::Callback<void(int)> cb) {
  int req = CreateRequest(std::move(cb));
  dispatcher_->GetStorageDispatcherHostInterface()->ShareCreateWithInfohash(shared_context_->id, req, type, name, std::move(keyspaces), infohash);
}

void StorageContext::ShareAdd(const base::UUID& tid, const std::string& url, base::Callback<void(int)> cb) {
  int req = CreateRequest(std::move(cb));
  dispatcher_->GetStorageDispatcherHostInterface()->ShareAdd(shared_context_->id, req, std::string(reinterpret_cast<const char *>(tid.data), 16), url);
}

void StorageContext::ShareOpen(common::mojom::StorageType type, const std::string& name, bool create_if_not_exists, base::Callback<void(int)> cb) {
  int req = CreateRequest(std::move(cb));
  dispatcher_->GetStorageDispatcherHostInterface()->ShareOpen(shared_context_->id, req, type, name, create_if_not_exists);
}

void StorageContext::ShareExists(const std::string& name, base::Callback<void(int)> cb) {
  int req = CreateRequest(std::move(cb));
  dispatcher_->GetStorageDispatcherHostInterface()->ShareExists(shared_context_->id, req, name,
    base::Bind(&StorageContext::OnShareExists, this, req, name));
}

void StorageContext::ShareRead(const base::UUID& tid, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data, base::Callback<void(int)> cb) {
  int req = CreateRequest(std::move(cb));
  dispatcher_->GetStorageDispatcherHostInterface()->ShareRead(shared_context_->id, req, std::string(reinterpret_cast<const char *>(tid.data), 16), offset, size, std::move(data));
}

void StorageContext::ShareWrite(const base::UUID& tid, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data, base::Callback<void(int)> cb) {
  int req = CreateRequest(std::move(cb));
  dispatcher_->GetStorageDispatcherHostInterface()->ShareWrite(shared_context_->id, req, std::string(reinterpret_cast<const char *>(tid.data), 16), offset, size, std::move(data));
}

void StorageContext::ShareClose(const std::string& name, base::Callback<void(int)> cb) {
  int req = CreateRequest(std::move(cb));
  dispatcher_->GetStorageDispatcherHostInterface()->ShareClose(shared_context_->id, req, name);
}

void StorageContext::ShareDelete(const base::UUID& tid, base::Callback<void(int)> cb) {
  int req = CreateRequest(std::move(cb));
  dispatcher_->GetStorageDispatcherHostInterface()->ShareDelete(shared_context_->id, req, std::string(reinterpret_cast<const char *>(tid.data), 16));
}

void StorageContext::ShareShare(const base::UUID& tid, base::Callback<void(int)> cb) {
  int req = CreateRequest(std::move(cb));
  dispatcher_->GetStorageDispatcherHostInterface()->ShareShare(shared_context_->id, req, std::string(reinterpret_cast<const char *>(tid.data), 16));
}

void StorageContext::ShareUnshare(const base::UUID& tid, base::Callback<void(int)> cb) {
  int req = CreateRequest(std::move(cb));
  dispatcher_->GetStorageDispatcherHostInterface()->ShareUnshare(shared_context_->id, req, std::string(reinterpret_cast<const char *>(tid.data), 16));
}

void StorageContext::ShareSubscribe(const base::UUID& tid, base::Callback<void(int)> cb) {
  int req = CreateRequest(std::move(cb));
  dispatcher_->GetStorageDispatcherHostInterface()->ShareSubscribe(shared_context_->id, req, std::string(reinterpret_cast<const char *>(tid.data), 16));
}

void StorageContext::ShareUnsubscribe(const base::UUID& tid, base::Callback<void(int)> cb) {
  int req = CreateRequest(std::move(cb));
  dispatcher_->GetStorageDispatcherHostInterface()->ShareUnsubscribe(shared_context_->id, req, std::string(reinterpret_cast<const char *>(tid.data), 16));
}

void StorageContext::FileCreate(const std::string& share_name, const std::string& file, base::Callback<void(int)> cb) {
  int req = CreateRequest(std::move(cb));
  dispatcher_->GetStorageDispatcherHostInterface()->FileCreate(shared_context_->id, req, share_name, file);
}

void StorageContext::FileAdd(const std::string& share_name, const std::string& file, const std::string& path, base::Callback<void(int)> cb) {
  int req = CreateRequest(std::move(cb));
  dispatcher_->GetStorageDispatcherHostInterface()->FileAdd(shared_context_->id, req, share_name, file, path);
}

void StorageContext::FileOpen(const std::string& share_name, const std::string& file, base::Callback<void(int)> cb) {
  int req = CreateRequest(std::move(cb));
  dispatcher_->GetStorageDispatcherHostInterface()->FileOpen(shared_context_->id, req, share_name, file);
}

void StorageContext::FileDelete(const std::string& share_name, const std::string& file, base::Callback<void(int)> cb) {
  int req = CreateRequest(std::move(cb));
  dispatcher_->GetStorageDispatcherHostInterface()->FileDelete(shared_context_->id, req, share_name, file);
}

void StorageContext::FileRename(const std::string& share_name, const std::string& input, const std::string& output, base::Callback<void(int)> cb) {
  int req = CreateRequest(std::move(cb));
  dispatcher_->GetStorageDispatcherHostInterface()->FileRename(shared_context_->id, req, share_name, input, output);
}

void StorageContext::FileRead(const std::string& share_name, const std::string& file, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data, base::Callback<void(int)> cb) {
  int req = CreateRequest(std::move(cb));
  dispatcher_->GetStorageDispatcherHostInterface()->FileRead(shared_context_->id, req, share_name, file, offset, size, std::move(data));
}

void StorageContext::FileReadOnce(const std::string& share_name, const std::string& file, int64_t offset, int64_t size, base::Callback<void(int, mojo::ScopedSharedBufferHandle, int)> cb) {
  int req = CreateRequest(std::move(cb));
  dispatcher_->GetStorageDispatcherHostInterface()->FileReadOnce(shared_context_->id, req, share_name, file, offset, size);
}

void StorageContext::FileWrite(const std::string& share_name, const std::string& file, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data, base::Callback<void(int)> cb) {
  int req = CreateRequest(std::move(cb));
  dispatcher_->GetStorageDispatcherHostInterface()->FileWrite(shared_context_->id, req, share_name, file, offset, size, std::move(data));
}

void StorageContext::FileWriteOnce(const std::string& share_name, const std::string& file, int64_t offset, int64_t size, std::vector<uint8_t> data, base::Callback<void(int, int)> cb) {
  int req = CreateRequest(std::move(cb));
  dispatcher_->GetStorageDispatcherHostInterface()->FileWriteOnce(shared_context_->id, req, share_name, file, offset, size, data);
}

void StorageContext::FileClose(const std::string& share_name, const std::string& file, base::Callback<void(int)> cb) {
  int req = CreateRequest(std::move(cb));
  dispatcher_->GetStorageDispatcherHostInterface()->FileClose(shared_context_->id, req, share_name, file);
}

void StorageContext::FileList(const std::string& share_name, base::Callback<void(std::vector<common::mojom::ShareStorageEntryPtr>)> callback) {
  int req = CreateRequest();
  dispatcher_->GetStorageDispatcherHostInterface()->FileList(shared_context_->id, req, share_name,
    base::Bind(&StorageContext::OnFileList, this, std::move(callback)));  
}

// void StorageContext::DataCreate(const base::UUID& tid, base::Callback<void(int)> cb) {
//   int req = CreateRequest(std::move(cb));
//   dispatcher_->GetStorageDispatcherHostInterface()->DataCreate(shared_context_->id, req, std::string(reinterpret_cast<const char *>(tid.data), 16));
// }

void StorageContext::DataDrop(const std::string& db_name, base::Callback<void(int)> cb) {
  int req = CreateRequest(std::move(cb));
  dispatcher_->GetStorageDispatcherHostInterface()->DataDrop(shared_context_->id, req, db_name);
}

void StorageContext::DataCreateKeyspace(const std::string& db_name, const std::string& keyspace, base::Callback<void(int)> cb) {
  int req = CreateRequest(std::move(cb));
  dispatcher_->GetStorageDispatcherHostInterface()->DataCreateKeyspace(shared_context_->id, req, db_name, keyspace);
}

void StorageContext::DataDeleteKeyspace(const std::string& db_name, const std::string& keyspace, base::Callback<void(int)> cb) {
  int req = CreateRequest(std::move(cb));
  dispatcher_->GetStorageDispatcherHostInterface()->DataDeleteKeyspace(shared_context_->id, req, db_name, keyspace);
}

void StorageContext::DataListKeyspaces(const std::string& db_name, base::Callback<void(int, int, const std::vector<std::string>&)> cb) {
  int req = CreateRequest(std::move(cb));
  dispatcher_->GetStorageDispatcherHostInterface()->DataListKeyspaces(shared_context_->id, req, db_name);
}

void StorageContext::DataDelete(const std::string& db_name, const std::string& keyspace, const std::string& key, base::Callback<void(int)> cb) {
  int req = CreateRequest(std::move(cb));
  dispatcher_->GetStorageDispatcherHostInterface()->DataDelete(shared_context_->id, req, db_name, keyspace, key); 
}

void StorageContext::DataDeleteAll(const std::string& db_name, const std::string& keyspace, base::Callback<void(int)> cb) {
  int req = CreateRequest(std::move(cb));
  dispatcher_->GetStorageDispatcherHostInterface()->DataDeleteAll(shared_context_->id, req, db_name, keyspace);   
}

// void StorageContext::DataOpen(const base::UUID& tid, base::Callback<void(int)> cb) {
//   int req = CreateRequest(std::move(cb));
//   dispatcher_->GetStorageDispatcherHostInterface()->DataOpen(shared_context_->id, req, std::string(reinterpret_cast<const char *>(tid.data), 16));
// }

void StorageContext::DataClose(const std::string& db_name, base::Callback<void(int)> cb) {
  int req = CreateRequest(std::move(cb));
  dispatcher_->GetStorageDispatcherHostInterface()->DataClose(shared_context_->id, req, db_name);
}

void StorageContext::DataPut(const std::string& db_name, const std::string& keyspace, const std::string& key, int64_t size, mojo::ScopedSharedBufferHandle data, base::Callback<void(int)> cb) {
  int req = CreateRequest(std::move(cb));
  dispatcher_->GetStorageDispatcherHostInterface()->DataPut(shared_context_->id, req, db_name, keyspace, key, size, std::move(data));
}

void StorageContext::DataGet(const std::string& db_name, const std::string& keyspace, const std::string& key, int64_t size, mojo::ScopedSharedBufferHandle data, base::Callback<void(int)> cb) {
  int req = CreateRequest(std::move(cb));
  dispatcher_->GetStorageDispatcherHostInterface()->DataGet(shared_context_->id, req, db_name, keyspace, key, size, std::move(data));
}

void StorageContext::DataGetOnce(const std::string& db_name, const std::string& keyspace, const std::string& key, base::Callback<void(int, mojo::ScopedSharedBufferHandle, int)> cb) {
  int req = CreateRequest(std::move(cb));
  dispatcher_->GetStorageDispatcherHostInterface()->DataGetOnce(shared_context_->id, req, db_name, keyspace, key);
}

void StorageContext::CreateDatabaseCursorImpl(StorageDataCursorDelegate* cursor_delegate, common::mojom::DataCursorPtr in_cursor) {
  //DLOG(INFO) << "StorageContext::CreateDatabaseCursorImpl: cursor handed over to us. calling delegate. (" << cursor_delegate << ")";
  cursor_delegate->OnCursorAvailable(std::move(in_cursor));
}

void StorageContext::ExecuteQueryImpl(StorageDataCursorDelegate* cursor_delegate, common::mojom::SQLCursorPtr in_cursor) {
  DLOG(INFO) << "StorageContext::ExecuteQueryImpl: passing the cursor";
  cursor_delegate->OnSQLCursorAvailable(std::move(in_cursor));
}

void StorageContext::IndexResolveId(const std::string& address, base::Callback<void(base::UUID, int)> callback) {
  int req = CreateRequest(std::move(callback));
  common::mojom::StorageDispatcherHost* dispatcher_host = dispatcher_->GetStorageDispatcherHostInterface();
  DCHECK(dispatcher_host);
  dispatcher_host->IndexResolveId(shared_context_->id, req, address);
}

void StorageContext::OnDestroy(common::mojom::DomainStatus status) {
  going_away_ = true; 
}

void StorageContext::OnShareCreate(int req, const std::string& tid, common::mojom::DomainStatus status) {
  auto cb = PopRequest(req);
  if (!cb.callback.is_null()) {
    std::move(cb.callback).Run(status == common::mojom::DomainStatus::kOk ? net::OK : net::ERR_FAILED);
  }
}

void StorageContext::OnShareAdd(int req, const base::UUID& tid, common::mojom::DomainStatus status) {
  auto cb = PopRequest(req);
  if (!cb.callback.is_null()) {
    std::move(cb.callback).Run(status == common::mojom::DomainStatus::kOk ? net::OK : net::ERR_FAILED); 
  }
}

void StorageContext::OnShareOpen(int req, const std::string& tid, common::mojom::DomainStatus status) {
  auto cb = PopRequest(req);
  if (!cb.callback.is_null()) { 
    std::move(cb.callback).Run(status == common::mojom::DomainStatus::kOk ? net::OK : net::ERR_FAILED);
  }
}

void StorageContext::OnShareClose(int req, const base::UUID& tid, common::mojom::DomainStatus status) {
  auto cb = PopRequest(req);
  if (!cb.callback.is_null()) {
    std::move(cb.callback).Run(status == common::mojom::DomainStatus::kOk ? net::OK : net::ERR_FAILED);
  }
}

void StorageContext::OnShareDelete(int req, const base::UUID& tid, common::mojom::DomainStatus status) {
  auto cb = PopRequest(req);
  if (!cb.callback.is_null()) {
    std::move(cb.callback).Run(status == common::mojom::DomainStatus::kOk ? net::OK : net::ERR_FAILED);
  }
}

void StorageContext::OnShareRead(int req, const base::UUID& tid, common::mojom::DomainStatus status, int64_t bytes_readed) {
  auto cb = PopRequest(req);
  if (!cb.callback.is_null()) {
    std::move(cb.callback).Run(status == common::mojom::DomainStatus::kOk ? net::OK : net::ERR_FAILED);
  }
}

void StorageContext::OnShareWrite(int req, const base::UUID& tid, common::mojom::DomainStatus status, int64_t bytes_written) {
  auto cb = PopRequest(req);
  if (!cb.callback.is_null()) {
    std::move(cb.callback).Run(status == common::mojom::DomainStatus::kOk ? net::OK : net::ERR_FAILED);
  }
}

void StorageContext::OnShareShare(int req, const base::UUID& tid, common::mojom::DomainStatus status) {
  auto cb = PopRequest(req);
  if (!cb.callback.is_null()) {
    std::move(cb.callback).Run(status == common::mojom::DomainStatus::kOk ? net::OK : net::ERR_FAILED);
  }
}

void StorageContext::OnShareUnshare(int req, const base::UUID& tid, common::mojom::DomainStatus status) {
  auto cb = PopRequest(req);
  if (!cb.callback.is_null()) {
    std::move(cb.callback).Run(status == common::mojom::DomainStatus::kOk ? net::OK : net::ERR_FAILED);
  }
}

void StorageContext::OnShareSubscribe(int req, const base::UUID& tid, common::mojom::DomainStatus status) {
  auto cb = PopRequest(req);
  if (!cb.callback.is_null()) {
    std::move(cb.callback).Run(status == common::mojom::DomainStatus::kOk ? net::OK : net::ERR_FAILED);
  }
}

void StorageContext::OnShareUnsubscribe(int req, const base::UUID& tid, common::mojom::DomainStatus status) {
  auto cb = PopRequest(req);
  if (!cb.callback.is_null()) {
    std::move(cb.callback).Run(status == common::mojom::DomainStatus::kOk ? net::OK : net::ERR_FAILED);
  }
}

void StorageContext::OnShareEvent(int req, const base::UUID& tid, common::mojom::ShareEventPtr event) {

}

void StorageContext::OnFileCreate(int req, const base::UUID& tid, const std::string& file, common::mojom::DomainStatus status) {
  auto cb = PopRequest(req);
  if (!cb.callback.is_null()) {
    std::move(cb.callback).Run(status == common::mojom::DomainStatus::kOk ? net::OK : net::ERR_FAILED);
  }
}

void StorageContext::OnFileAdd(int req, const base::UUID& tid, const std::string& file, common::mojom::DomainStatus status) {
  auto cb = PopRequest(req);
  if (!cb.callback.is_null()) {
    std::move(cb.callback).Run(status == common::mojom::DomainStatus::kOk ? net::OK : net::ERR_FAILED);
  }
}

void StorageContext::OnFileOpen(int req, const base::UUID& tid, const std::string& file, common::mojom::DomainStatus status) {
  auto cb = PopRequest(req);
  if (!cb.callback.is_null()) {
    std::move(cb.callback).Run(status == common::mojom::DomainStatus::kOk ? net::OK : net::ERR_FAILED);
  }
}

void StorageContext::OnFileDelete(int req, const base::UUID& tid, const std::string& file, common::mojom::DomainStatus status) {
  auto cb = PopRequest(req);
  if (!cb.callback.is_null()) {
    std::move(cb.callback).Run(status == common::mojom::DomainStatus::kOk ? net::OK : net::ERR_FAILED);
  }
}

void StorageContext::OnFileReadOnce(int req, const std::string& tid, const std::string& file, common::mojom::DomainStatus status, int64_t readed, mojo::ScopedSharedBufferHandle data) {
  auto cb = PopRequest(req);
  if (!cb.sharedbuf_callback.is_null()) {
    std::move(cb.sharedbuf_callback).Run(status == common::mojom::DomainStatus::kOk ? net::OK : net::ERR_FAILED, std::move(data), readed);
  }
}

void StorageContext::OnFileRead(int req, const base::UUID& tid, const std::string& file, common::mojom::DomainStatus status, int64_t bytes_written) {
  auto cb = PopRequest(req);
  if (!cb.callback.is_null()) {
    std::move(cb.callback).Run(status == common::mojom::DomainStatus::kOk ? net::OK : net::ERR_FAILED);
  }
}

void StorageContext::OnFileWrite(int req, const base::UUID& tid, const std::string& file, common::mojom::DomainStatus status, int64_t bytes_written) {
  //DLOG(INFO) << "StorageContext::OnFileWrite";
  auto cb = PopRequest(req);
  if (!cb.callback.is_null()) {
    std::move(cb.callback).Run(status == common::mojom::DomainStatus::kOk ? net::OK : net::ERR_FAILED);
  }
}

void StorageContext::OnFileWriteOnce(int req, const std::string& tid, const std::string& file, common::mojom::DomainStatus status, int64_t bytes_written) {
  auto cb = PopRequest(req);
  if (!cb.size_callback.is_null()) {
    std::move(cb.size_callback).Run(status == common::mojom::DomainStatus::kOk ? net::OK : net::ERR_FAILED, static_cast<int>(bytes_written));
  }
}

void StorageContext::OnFileClose(int req, const base::UUID& tid, const std::string& file, common::mojom::DomainStatus status) {
  auto cb = PopRequest(req);
  if (!cb.callback.is_null()) {
    std::move(cb.callback).Run(status == common::mojom::DomainStatus::kOk ? net::OK : net::ERR_FAILED);
  }
}

void StorageContext::OnFileRename(int req, const base::UUID& tid, const std::string& file, common::mojom::DomainStatus status) {
  auto cb = PopRequest(req);
  if (!cb.callback.is_null()) {
    std::move(cb.callback).Run(status == common::mojom::DomainStatus::kOk ? net::OK : net::ERR_FAILED);
  }
}

void StorageContext::OnFileList(base::Callback<void(std::vector<common::mojom::ShareStorageEntryPtr>)> reply_cb, uint32_t context_id, int req, std::vector<common::mojom::ShareStorageEntryPtr> entries) {
  PopRequest(req);
  std::move(reply_cb).Run(std::move(entries));  
}

// void StorageContext::OnDataCreate(int req, const std::string& tid, common::mojom::DomainStatus status) {
//   auto cb = PopRequest(req);
//   if (!cb.callback.is_null()) {
//     std::move(cb.callback).Run(status == common::mojom::DomainStatus::kOk ? net::OK : net::ERR_FAILED);
//   }
// }

void StorageContext::OnDataDrop(int req, const std::string& tid, common::mojom::DomainStatus status) {
  auto cb = PopRequest(req);
  if (!cb.callback.is_null()) {
    std::move(cb.callback).Run(status == common::mojom::DomainStatus::kOk ? net::OK : net::ERR_FAILED);
  }
}

void StorageContext::OnDataCreateKeyspace(int req, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status) {
  auto cb = PopRequest(req);
  if (!cb.callback.is_null()) {
    std::move(cb.callback).Run(status == common::mojom::DomainStatus::kOk ? net::OK : net::ERR_FAILED);
  }
}

void StorageContext::OnDataDeleteKeyspace(int req, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status) {
  auto cb = PopRequest(req);
  if (!cb.callback.is_null()) {
    std::move(cb.callback).Run(status == common::mojom::DomainStatus::kOk ? net::OK : net::ERR_FAILED);
  }
}

void StorageContext::OnDataListKeyspaces(int req, const std::string& tid, common::mojom::DomainStatus status, const std::vector<std::string>& keyspaces) {
  auto cb = PopRequest(req);
  if (!cb.list_keyspaces_callback.is_null()) {
    std::move(cb.list_keyspaces_callback).Run(status == common::mojom::DomainStatus::kOk ? net::OK : net::ERR_FAILED, keyspaces.size(), keyspaces);
  }
}

// void StorageContext::OnDataOpen(int req, const base::UUID& tid, common::mojom::DomainStatus status) {
//   auto cb = PopRequest(req);
//   if (!cb.callback.is_null()) {
//     std::move(cb.callback).Run(status == common::mojom::DomainStatus::kOk ? net::OK : net::ERR_FAILED);
//   }
// }

void StorageContext::OnDataClose(int req, const std::string& tid, common::mojom::DomainStatus status) {
  auto cb = PopRequest(req);
  if (!cb.callback.is_null()) {
    std::move(cb.callback).Run(status == common::mojom::DomainStatus::kOk ? net::OK : net::ERR_FAILED);
  }
}

void StorageContext::OnDataPut(int req, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status, int64_t wrote) {
  auto cb = PopRequest(req);
  if (!cb.callback.is_null()) {
    std::move(cb.callback).Run(status == common::mojom::DomainStatus::kOk ? net::OK : net::ERR_FAILED);
  }
}

void StorageContext::OnDataGet(int req, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status, int64_t wrote) {
  auto cb = PopRequest(req);
  if (!cb.callback.is_null()) {
    std::move(cb.callback).Run(status == common::mojom::DomainStatus::kOk ? net::OK : net::ERR_FAILED);
  }
}

void StorageContext::OnDataGetOnce(int req, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status, int64_t readed, mojo::ScopedSharedBufferHandle data) {
  auto cb = PopRequest(req);
  if (!cb.sharedbuf_callback.is_null()) {
    std::move(cb.sharedbuf_callback).Run(status == common::mojom::DomainStatus::kOk ? net::OK : net::ERR_FAILED, std::move(data), readed);
  }
}

void StorageContext::OnDataGetFailed(int req, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status) {
  auto cb = PopRequest(req);
  if (!cb.sharedbuf_callback.is_null()) {
    mojo::ScopedSharedBufferHandle handle;
    std::move(cb.sharedbuf_callback).Run(status == common::mojom::DomainStatus::kOk ? net::OK : net::ERR_FAILED, std::move(handle), -1);
  } 
}

void StorageContext::OnDataDelete(int req, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status) {
  auto cb = PopRequest(req);
  if (!cb.callback.is_null()) {
    std::move(cb.callback).Run(status == common::mojom::DomainStatus::kOk ? net::OK : net::ERR_FAILED);
  } 
}

void StorageContext::OnDataDeleteAll(int req, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status) {
  auto cb = PopRequest(req);
  if (!cb.callback.is_null()) {
    std::move(cb.callback).Run(status == common::mojom::DomainStatus::kOk ? net::OK : net::ERR_FAILED);
  }
}

void StorageContext::OnIndexResolveId(int req, const std::string& name, base::UUID id, common::mojom::DomainStatus status) {
  auto cb = PopRequest(req);
  if (!cb.uuid_callback.is_null()) {
    std::move(cb.uuid_callback).Run(std::move(id), status == common::mojom::DomainStatus::kOk ? net::OK : net::ERR_FAILED);
  }
}

void StorageContext::OnGetAllocatedSize(base::Callback<void(int64_t)> reply_cb, uint32_t context_id, int req, int64_t size) {
  PopRequest(req);
  std::move(reply_cb).Run(size);  
}

void StorageContext::OnListShares(base::Callback<void(std::vector<common::mojom::ShareInfoPtr>)> reply_cb, uint32_t context_id, int req, std::vector<common::mojom::ShareInfoPtr> shares) {
  PopRequest(req);
  std::move(reply_cb).Run(std::move(shares));
}

void StorageContext::OnListShareEntries(base::Callback<void(std::vector<common::mojom::ShareStorageEntryPtr>)> reply_cb, uint32_t context_id, int req, std::vector<common::mojom::ShareStorageEntryPtr> entries) {
  PopRequest(req);
  std::move(reply_cb).Run(std::move(entries));
}

void StorageContext::OnShareExists(int req, const std::string& tid, bool result) {
  StorageContext::RequestData cb = PopRequest(req);
  if (!cb.callback.is_null()) {
    std::move(cb.callback).Run(result ? 1 : 0);
  }
}

void StorageContext::AddShareObserver(base::WeakPtr<StorageShareObserver> observer) {
  share_observers_.push_back(std::move(observer));
}

void StorageContext::RemoveShareObserver(StorageShareObserver* observer) {
  for (auto it = share_observers_.begin(); it != share_observers_.end(); ++it) {
    if (observer == it->get()) {
      share_observers_.erase(it);
      return;
    }
  }
}

void StorageContext::OnSharePaused(const base::UUID& tid) {
  for (auto it = share_observers_.begin(); it != share_observers_.end(); ++it) {
    if (*it) {
      (*it)->OnSharePaused(tid);
    }
  } 
}

void StorageContext::OnShareResumed(const base::UUID& tid) {
  for (auto it = share_observers_.begin(); it != share_observers_.end(); ++it) {
    if (*it) {
      (*it)->OnShareResumed(tid);
    }
  } 
}

void StorageContext::OnShareChecked(const base::UUID& tid, common::mojom::DomainStatus status) {
  for (auto it = share_observers_.begin(); it != share_observers_.end(); ++it) {
    if (*it) {
      (*it)->OnShareChecked(tid, status);
    }
  } 
}

void StorageContext::OnSharePieceComplete(const base::UUID& tid, uint32_t piece_offset) {
  for (auto it = share_observers_.begin(); it != share_observers_.end(); ++it) {
    if (*it) {
      (*it)->OnSharePieceComplete(tid, piece_offset);
    }
  } 
}

void StorageContext::OnShareFileComplete(const base::UUID& tid, int file_offset) {
  for (auto it = share_observers_.begin(); it != share_observers_.end(); ++it) {
    if (*it) {
      (*it)->OnShareFileComplete(tid, file_offset);
    }
  }
}

void StorageContext::OnShareDownloading(const base::UUID& tid) {
  for (auto it = share_observers_.begin(); it != share_observers_.end(); ++it) {
    if (*it) {
      (*it)->OnShareDownloading(tid);
    }
  }
}

void StorageContext::OnShareComplete(const base::UUID& tid) {
  for (auto it = share_observers_.begin(); it != share_observers_.end(); ++it) {
    if (*it) {
      (*it)->OnShareComplete(tid);
    }
  }
}

void StorageContext::OnShareSeeding(const base::UUID& tid) {
  for (auto it = share_observers_.begin(); it != share_observers_.end(); ++it) {
    if (*it) {
      (*it)->OnShareSeeding(tid);
    }
  }
}

void StorageContext::OnShareDHTAnnounceReply(const base::UUID& tid, int32_t peers) {
  for (auto it = share_observers_.begin(); it != share_observers_.end(); ++it) {
    if (*it) {
      (*it)->OnShareDHTAnnounceReply(tid, peers);
    }
  }
}

void StorageContext::OnShareMetadataReceived(const base::UUID& tid) {
  for (auto it = share_observers_.begin(); it != share_observers_.end(); ++it) {
    if (*it) {
      (*it)->OnShareMetadataReceived(tid);
    }
  }
}

void StorageContext::OnShareMetadataError(const base::UUID& tid, int32_t error) {
  for (auto it = share_observers_.begin(); it != share_observers_.end(); ++it) {
    if (*it) {
      (*it)->OnShareMetadataError(tid, error);
    }
  }
}

void StorageContext::OnSharePieceReadError(const base::UUID& tid, int32_t piece, int32_t error) {
  for (auto it = share_observers_.begin(); it != share_observers_.end(); ++it) {
    if (*it) {
      (*it)->OnSharePieceReadError(tid, piece, error);
    }
  }
}

void StorageContext::OnSharePiecePass(const base::UUID& tid, int32_t piece) {
  for (auto it = share_observers_.begin(); it != share_observers_.end(); ++it) {
    if (*it) {
      (*it)->OnSharePiecePass(tid, piece);
    }
  }
}

void StorageContext::OnSharePieceFailed(const base::UUID& tid, int32_t piece) {
  for (auto it = share_observers_.begin(); it != share_observers_.end(); ++it) {
    if (*it) {
      (*it)->OnSharePieceFailed(tid, piece);
    }
  }
}

void StorageContext::OnSharePieceRead(const base::UUID& tid, int32_t piece, int64_t offset, int64_t size, int64_t block_size, int32_t result) {
  for (auto it = share_observers_.begin(); it != share_observers_.end(); ++it) {
    if (*it) {
      (*it)->OnSharePieceRead(tid, piece, offset, size, block_size, result);
    }
  }
}

void StorageContext::OnSharePieceWrite(const base::UUID& tid, int32_t piece, int64_t offset, int64_t size, int64_t block_size, int32_t result) {
  for (auto it = share_observers_.begin(); it != share_observers_.end(); ++it) {
    if (*it) {
      (*it)->OnSharePieceWrite(tid, piece, offset, size, block_size, result);
    }
  }
}

void StorageContext::OnSharePieceHashFailed(const base::UUID& tid, int32_t piece) {
  for (auto it = share_observers_.begin(); it != share_observers_.end(); ++it) {
    if (*it) {
      (*it)->OnSharePieceHashFailed(tid, piece);
    }
  }
}

void StorageContext::OnShareCheckingFiles(const base::UUID& tid) {
  for (auto it = share_observers_.begin(); it != share_observers_.end(); ++it) {
    if (*it) {
      (*it)->OnShareCheckingFiles(tid);
    }
  }
}

void StorageContext::OnShareDownloadingMetadata(const base::UUID& tid) {
  for (auto it = share_observers_.begin(); it != share_observers_.end(); ++it) {
    if (*it) {
      (*it)->OnShareDownloadingMetadata(tid);
    }
  }
}

void StorageContext::OnShareFileRenamed(const base::UUID& tid, int32_t file_offset, const std::string& name, int32_t error) {
  for (auto it = share_observers_.begin(); it != share_observers_.end(); ++it) {
    if (*it) {
      (*it)->OnShareFileRenamed(tid, file_offset, name, error);
    }
  }
}

int StorageContext::CreateRequest() {
  base::AutoLock lock(requests_lock_);
  
  int req_id = req_sequence_.GetNext() + 1;
  RequestData req_data;
  requests_.emplace(std::make_pair(req_id, std::move(req_data)));
  return req_id;
} 

int StorageContext::CreateRequest(base::Callback<void(int)> cb) {
  base::AutoLock lock(requests_lock_);
  
  int req_id = req_sequence_.GetNext() + 1;
  RequestData req_data;
  req_data.callback = std::move(cb);
  requests_.emplace(std::make_pair(req_id, std::move(req_data)));
  return req_id;
}

int StorageContext::CreateRequest(base::Callback<void(int, int)> cb) {
  base::AutoLock lock(requests_lock_);
  
  int req_id = req_sequence_.GetNext() + 1;
  RequestData req_data;
  req_data.size_callback = std::move(cb);
  requests_.emplace(std::make_pair(req_id, std::move(req_data)));
  return req_id;
}

int StorageContext::CreateRequest(base::Callback<void(int, mojo::ScopedSharedBufferHandle, int)> cb) {
  base::AutoLock lock(requests_lock_);
  
  int req_id = req_sequence_.GetNext() + 1;
  RequestData req_data;
  req_data.sharedbuf_callback = std::move(cb);
  requests_.emplace(std::make_pair(req_id, std::move(req_data)));
  return req_id;
}

int StorageContext::CreateRequest(base::Callback<void(base::UUID, int)> cb) {
  base::AutoLock lock(requests_lock_);
  int req_id = req_sequence_.GetNext() + 1;
  RequestData req_data;
  req_data.uuid_callback = std::move(cb);
  requests_.emplace(std::make_pair(req_id, std::move(req_data)));
  return req_id;
}

int StorageContext::CreateRequest(base::Callback<void(int, int, const std::vector<std::string>&)> cb) {
  base::AutoLock lock(requests_lock_);
  int req_id = req_sequence_.GetNext() + 1;
  RequestData req_data;
  req_data.list_keyspaces_callback = std::move(cb);
  requests_.emplace(std::make_pair(req_id, std::move(req_data)));
  return req_id; 
}

StorageContext::RequestData StorageContext::PopRequest(int req_id) {
  base::AutoLock lock(requests_lock_);
  
  RequestData result;
  auto it = requests_.find(req_id);
  if (it != requests_.end()) {
    result = std::move(it->second);
    requests_.erase(it);
  }
  return result;
}

}