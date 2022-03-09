// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/storage_dispatcher_host.h"

#include "base/task_scheduler/task_traits.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/host_thread.h"
#include "core/host/application/domain.h"
#include "core/host/application/domain_process_host.h"
#include "core/host/application/storage_context.h"
#include "core/host/application/storage_manager.h"

namespace host {

StorageDispatcherHost::StorageDispatcherHost(StorageManager* storage_manager, Domain* shell): 
  storage_manager_(storage_manager),
  domain_(shell),
  storage_dispatcher_host_binding_(this) {
  
}

StorageDispatcherHost::~StorageDispatcherHost() {
  
}

common::mojom::StorageDispatcher* StorageDispatcherHost::GetStorageDispatcherInterface() {
  return storage_dispatcher_interface_.get();
}

void StorageDispatcherHost::AddBinding(common::mojom::StorageDispatcherHostAssociatedRequest request) {
  storage_dispatcher_host_binding_.Bind(std::move(request));
}

void StorageDispatcherHost::ContextCreate(common::mojom::StorageParametersPtr params, ContextCreateCallback cb) {
  // this case is more sync like, the others we dispatch through the context we just created
  scoped_refptr<StorageContext> context = storage_manager_->CreateContext(domain_);
  common::mojom::StorageContextPtr shared_context = common::mojom::StorageContext::New();
  shared_context->id = context->id();
  std::move(cb).Run(std::move(shared_context));
}

void StorageDispatcherHost::ContextDestroy(uint32_t context_id) {
  storage_manager_->DestroyContext(context_id);
}

void StorageDispatcherHost::StorageGetAllocatedSize(uint32_t context_id, int32_t req, StorageGetAllocatedSizeCallback cb) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id); 
  if (!storage_context) {
    std::move(cb).Run(context_id, req, -1);
    return;
  }
  std::move(cb).Run(context_id, req, storage_context->GetAllocatedSize(context_id, req));
}

void StorageDispatcherHost::StorageListShares(uint32_t context_id, int32_t req, StorageListSharesCallback cb) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id);
  storage_context->ListShares(
    context_id, req,
    base::BindOnce(&StorageDispatcherHost::StorageListSharesImpl, base::Unretained(this), context_id, req, base::Passed(std::move(cb))));
}

void StorageDispatcherHost::StorageListSharesImpl(uint32_t context_id, int32_t req, StorageListSharesCallback cb, std::vector<common::mojom::ShareInfoPtr> torrents) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id);
  HostThread::PostTask(HostThread::IO, FROM_HERE, base::BindOnce(std::move(cb), context_id, req, base::Passed(std::move(torrents))));
}

void StorageDispatcherHost::StorageListShareEntries(uint32_t context_id, int32_t req, const std::string& tid, StorageListShareEntriesCallback cb) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id);
  storage_context->ListShareEntries(
    context_id, req, tid,
    base::BindOnce(&StorageDispatcherHost::StorageListShareEntriesImpl, base::Unretained(this), context_id, req, tid, base::Passed(std::move(cb))));
}

void StorageDispatcherHost::StorageListShareEntriesImpl(uint32_t context_id, int32_t req, const std::string& tid, StorageListShareEntriesCallback cb, std::vector<common::mojom::ShareStorageEntryPtr> torrents) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id);
  HostThread::PostTask(
  HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      std::move(cb), 
      context_id, 
      req, 
      base::Passed(std::move(torrents))));
}

void StorageDispatcherHost::ShareExists(uint32_t context_id, int32_t req, const std::string& tid, ShareExistsCallback cb) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id); 
  storage_context->ShareExists(context_id, req, tid, std::move(cb));
}

void StorageDispatcherHost::ShareCreateWithPath(uint32_t context_id, int32_t req, common::mojom::StorageType type, const std::string& name, const std::vector<std::string>& keyspaces, const std::string& source_path, bool in_memory) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id); 
  storage_context->ShareCreateWithPath(context_id, req, type, name, std::move(keyspaces), source_path, in_memory);
}

void StorageDispatcherHost::ShareCreateWithInfohash(uint32_t context_id, int32_t req, common::mojom::StorageType type, const std::string& name, const std::vector<std::string>& keyspaces, const std::string& infohash) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id); 
  storage_context->ShareCreateWithInfohash(context_id, req, type, name, std::move(keyspaces), infohash);
}

void StorageDispatcherHost::ShareAdd(uint32_t context_id, int32_t req, const std::string& tid, const std::string& url) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id); 
  storage_context->ShareAdd(context_id, req, tid, url); 
}

void StorageDispatcherHost::ShareOpen(uint32_t context_id, int32_t req, common::mojom::StorageType type, const std::string& tid, bool create_if_not_exists) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id); 
  storage_context->ShareOpen(context_id, req, type, tid, create_if_not_exists); 
}

void StorageDispatcherHost::ShareRead(uint32_t context_id, int32_t req, const std::string& tid, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id); 
  storage_context->ShareRead(context_id, req, tid, offset, size, std::move(data));
}

void StorageDispatcherHost::ShareWrite(uint32_t context_id, int32_t req, const std::string& tid, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id); 
  storage_context->ShareWrite(context_id, req, tid, offset, size, std::move(data));
}

void StorageDispatcherHost::ShareClose(uint32_t context_id, int32_t req, const std::string& tid) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id); 
  storage_context->ShareClose(context_id, req, tid);
}

void StorageDispatcherHost::ShareDelete(uint32_t context_id, int32_t req, const std::string& tid) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id); 
  storage_context->ShareDelete(context_id, req, tid);
}

void StorageDispatcherHost::ShareShare(uint32_t context_id, int32_t req, const std::string& tid) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id); 
  storage_context->ShareShare(context_id, req, tid);
}

void StorageDispatcherHost::ShareUnshare(uint32_t context_id, int32_t req, const std::string& tid) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id); 
  storage_context->ShareUnshare(context_id, req, tid);  
}

void StorageDispatcherHost::ShareSubscribe(uint32_t context_id, int32_t req, const std::string& tid) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id); 
  storage_context->ShareSubscribe(context_id, req, tid);
}

void StorageDispatcherHost::ShareUnsubscribe(uint32_t context_id, int32_t req, const std::string& tid) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id); 
  storage_context->ShareUnsubscribe(context_id, req, tid);
}

void StorageDispatcherHost::FileCreate(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id); 
  storage_context->FileCreate(context_id, req, tid, file);  
}

void StorageDispatcherHost::FileAdd(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file, const std::string& path) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id); 
  storage_context->FileAdd(context_id, req, tid, file, path);
}

void StorageDispatcherHost::FileOpen(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id); 
  storage_context->FileOpen(context_id, req, tid, file);
}

void StorageDispatcherHost::FileDelete(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id); 
  storage_context->FileDelete(context_id, req, tid, file); 
}

void StorageDispatcherHost::FileRename(uint32_t context_id, int32_t req, const std::string& tid, const std::string& input, const std::string& output) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id); 
  storage_context->FileRename(context_id, req, tid, input, output);
}

void StorageDispatcherHost::FileReadOnce(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file, int64_t offset, int64_t size) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id);
  storage_context->FileReadOnce(context_id, req, tid, file, offset, size);
}

void StorageDispatcherHost::FileRead(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id);
  storage_context->FileRead(context_id, req, tid, file, offset, size, std::move(data)); 
}

void StorageDispatcherHost::FileWrite(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id);
  storage_context->FileWrite(context_id, req, tid, file, offset, size, std::move(data)); 
}

void StorageDispatcherHost::FileWriteOnce(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file, int64_t offset, int64_t size, const std::vector<uint8_t>& data) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id);
  storage_context->FileWriteOnce(context_id, req, tid, file, offset, size, data); 
}

void StorageDispatcherHost::FileClose(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id); 
  storage_context->FileClose(context_id, req, tid, file);
}

void StorageDispatcherHost::FileList(uint32_t context_id, int32_t req, const std::string& tid, FileListCallback cb) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id);
  storage_context->ListShareEntries(context_id, req, tid, base::BindOnce(&StorageDispatcherHost::FileListImpl, base::Unretained(this), context_id, req, tid, base::Passed(std::move(cb))));
}

void StorageDispatcherHost::FileListImpl(uint32_t context_id, int32_t req, const std::string& tid, FileListCallback cb, std::vector<common::mojom::ShareStorageEntryPtr> entries) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id);
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      std::move(cb), 
      context_id, 
      req, 
      base::Passed(std::move(entries))));
}

//void StorageDispatcherHost::DataOpen(uint32_t context_id, int32_t req, const std::string& tid) {
//  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id); 
//  storage_context->DataOpen(context_id, req, tid); 
//}

void StorageDispatcherHost::DataClose(uint32_t context_id, int32_t req, const std::string& tid) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id); 
  storage_context->DataClose(context_id, req, tid); 
}

//void StorageDispatcherHost::DataCreate(uint32_t context_id, int32_t req, const std::string& tid) {
//  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id); 
//  storage_context->DataCreate(context_id, req, tid); 
//}

void StorageDispatcherHost::DataDrop(uint32_t context_id, int32_t req, const std::string& tid) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id); 
  storage_context->DataDrop(context_id, req, tid);
}

void StorageDispatcherHost::DataCreateKeyspace(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id); 
  storage_context->DataCreateKeyspace(context_id, req, tid, keyspace); 
}

void StorageDispatcherHost::DataDeleteKeyspace(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id); 
  storage_context->DataDeleteKeyspace(context_id, req, tid, keyspace);
}

void StorageDispatcherHost::DataListKeyspaces(uint32_t context_id, int32_t req, const std::string& tid) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id); 
  storage_context->DataListKeyspaces(context_id, req, tid);
}

void StorageDispatcherHost::DataPut(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace, const std::string& key, int64_t size, mojo::ScopedSharedBufferHandle data) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id); 
  storage_context->DataPut(context_id, req, tid, keyspace, key, size, std::move(data));
}

void StorageDispatcherHost::DataGetOnce(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace, const std::string& key) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id); 
  storage_context->DataGetOnce(context_id, req, tid, keyspace, key);
}

void StorageDispatcherHost::DataGet(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace, const std::string& key, int64_t size, mojo::ScopedSharedBufferHandle data) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id); 
  storage_context->DataGet(context_id, req, tid, keyspace, key, size, std::move(data));
}

void StorageDispatcherHost::DataDelete(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace, const std::string& key) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id); 
  storage_context->DataDelete(context_id, req, tid, keyspace, key); 
}

void StorageDispatcherHost::DataDeleteAll(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id); 
  storage_context->DataDeleteAll(context_id, req, tid, keyspace);
}

void StorageDispatcherHost::DataCreateCursor(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace, common::mojom::Order order, bool write, DataCreateCursorCallback callback) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id); 
  storage_context->DataCreateCursor(context_id, req, tid, keyspace, order, write, std::move(callback));
}

void StorageDispatcherHost::DataExecuteQuery(uint32_t context_id, int32_t req, const std::string& tid, const std::string& query, DataExecuteQueryCallback callback) {
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id); 
  storage_context->DataExecuteQuery(context_id, req, tid, query, std::move(callback));
}

void StorageDispatcherHost::IndexResolveId(uint32_t context_id, int32_t req, const std::string& address) {
  DCHECK(storage_manager_);
  scoped_refptr<StorageContext> storage_context = storage_manager_->GetContext(context_id); 
  DCHECK(storage_context);
  storage_context->IndexResolveId(context_id, req, address); 
}


}