// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_STORAGE_DISPATCHER_HOST_H_
#define MUMBA_HOST_APPLICATION_STORAGE_DISPATCHER_HOST_H_

#include "base/macros.h"
#include "core/shared/common/mojom/storage.mojom.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "mojo/public/cpp/bindings/associated_binding_set.h"
#include "mojo/public/cpp/bindings/interface_ptr.h"

namespace host {
class StorageManager;
class Domain;

class StorageDispatcherHost : public common::mojom::StorageDispatcherHost {
public:
  StorageDispatcherHost(StorageManager* storage_manager, Domain* shell);
  ~StorageDispatcherHost() override;
  
  common::mojom::StorageDispatcher* GetStorageDispatcherInterface();

  void AddBinding(common::mojom::StorageDispatcherHostAssociatedRequest request);

  void ContextCreate(common::mojom::StorageParametersPtr params, ContextCreateCallback cb) override;
  void ContextDestroy(uint32_t context_id) override;

  // general stuff
  void StorageGetAllocatedSize(uint32_t context_id, int32_t req, StorageGetAllocatedSizeCallback cb) override;
  void StorageListShares(uint32_t context_id, int32_t req, StorageListSharesCallback cb) override;
  void StorageListShareEntries(uint32_t context_id, int32_t req, const std::string& tid, StorageListShareEntriesCallback cb) override;

  // shares
  void ShareExists(uint32_t context_id, int32_t req, const std::string& tid, ShareExistsCallback cb) override;
  void ShareCreateWithPath(uint32_t context_id, int32_t req, common::mojom::StorageType type, const std::string& name, const std::vector<std::string>& keyspaces, const std::string& source_path) override;
  void ShareCreateWithInfohash(uint32_t context_id, int32_t req, common::mojom::StorageType type, const std::string& name, const std::vector<std::string>& keyspaces, const std::string& infohash) override;
  void ShareAdd(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file) override;
  void ShareOpen(uint32_t context_id, int32_t req, common::mojom::StorageType type, const std::string& tid, bool create_if_not_exists) override;
  void ShareRead(uint32_t context_id, int32_t req, const std::string& tid, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data) override;
  void ShareWrite(uint32_t context_id, int32_t req, const std::string& tid, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data) override;
  void ShareClose(uint32_t context_id, int32_t req, const std::string& tid) override;
  void ShareDelete(uint32_t context_id, int32_t req, const std::string& tid) override;
  void ShareShare(uint32_t context_id, int32_t req, const std::string& tid) override;
  void ShareUnshare(uint32_t context_id, int32_t req, const std::string& tid) override;
  void ShareSubscribe(uint32_t context_id, int32_t req, const std::string& tid) override;
  void ShareUnsubscribe(uint32_t context_id, int32_t req, const std::string& tid) override;
  
  // file
  void FileCreate(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file) override;
  void FileAdd(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file, const std::string& path) override;
  void FileOpen(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file) override;
  void FileDelete(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file) override;
  void FileRename(uint32_t context_id, int32_t req, const std::string& tid, const std::string& input, const std::string& output) override;
  void FileReadOnce(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file, int64_t offset, int64_t size) override;
  void FileRead(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data) override;
  void FileWrite(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data) override;
  void FileWriteOnce(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file, int64_t offset, int64_t size, const std::vector<uint8_t>& data) override;
  void FileClose(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file) override;
  void FileList(uint32_t context_id, int32_t req, const std::string& tid, FileListCallback cb) override;
  
  // database
  void DataClose(uint32_t context_id, int32_t req, const std::string& tid) override;
  void DataDrop(uint32_t context_id, int32_t req, const std::string& tid) override;
  void DataCreateKeyspace(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace) override;
  void DataDeleteKeyspace(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace) override;
  void DataListKeyspaces(uint32_t context_id, int32_t req, const std::string& tid) override;
  void DataPut(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace, const std::string& key, int64_t size, mojo::ScopedSharedBufferHandle data) override;
  void DataGet(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace, const std::string& key, int64_t size, mojo::ScopedSharedBufferHandle data) override;
  void DataGetOnce(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace, const std::string& key) override;
  void DataDelete(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace, const std::string& key) override;
  void DataDeleteAll(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace) override;
  void DataCreateCursor(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace, common::mojom::Order order, bool write, DataCreateCursorCallback callback) override;
  
  // index
  void IndexResolveId(uint32_t context_id, int32_t req, const std::string& address) override;

private:
  
  void StorageListSharesImpl(uint32_t context_id, int32_t req, StorageListSharesCallback cb, std::vector<common::mojom::ShareInfoPtr> torrents);
  void StorageListShareEntriesImpl(uint32_t context_id, int32_t req, const std::string& tid, StorageListShareEntriesCallback cb, std::vector<common::mojom::ShareStorageEntryPtr> torrents);
  void FileListImpl(uint32_t context_id, int32_t req, const std::string& tid, FileListCallback cb, std::vector<common::mojom::ShareStorageEntryPtr> entries);

  friend class DomainProcessHost;

  // storage manager (not owned)
  StorageManager* storage_manager_;
  // correspondent shell
  Domain* domain_;
  common::mojom::StorageDispatcherAssociatedPtr storage_dispatcher_interface_;
  mojo::AssociatedBinding<common::mojom::StorageDispatcherHost> storage_dispatcher_host_binding_;

  DISALLOW_COPY_AND_ASSIGN(StorageDispatcherHost);
};

}

#endif