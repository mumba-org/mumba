// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_STORAGE_STORAGE_DISPATCHER_H_
#define MUMBA_DOMAIN_STORAGE_STORAGE_DISPATCHER_H_

#include "base/macros.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/mojom/storage.mojom.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"

namespace domain {
class DomainMainThread;
class StorageManager;

class CONTENT_EXPORT StorageDispatcher : public common::mojom::StorageDispatcher {
public:
  StorageDispatcher();
  ~StorageDispatcher() override;

  StorageManager* storage_manager() const {
    return storage_manager_;
  }
  
  void set_storage_manager(StorageManager* storage_manager) {
    storage_manager_ = storage_manager;
  }

  common::mojom::StorageDispatcherHost* GetStorageDispatcherHostInterface();
  
  void Bind(common::mojom::StorageDispatcherAssociatedRequest request);

  //void OnContextCreate(common::mojom::StorageContextPtr context, common::mojom::DomainStatus status) override;
  void OnContextDestroy(uint32_t context_id, common::mojom::DomainStatus status) override;

  // torrents
  void OnShareCreate(uint32_t context_id, int req, const std::string& tid, common::mojom::DomainStatus status) override;
  void OnShareAdd(uint32_t context_id, int req, const std::string& tid, common::mojom::DomainStatus status) override;
  void OnShareOpen(uint32_t context_id, int req, const std::string& tid, common::mojom::DomainStatus status) override;
  void OnShareClose(uint32_t context_id, int req, const std::string& tid, common::mojom::DomainStatus status) override;
  void OnShareDelete(uint32_t context_id, int req, const std::string& tid, common::mojom::DomainStatus status) override;
  void OnShareRead(uint32_t context_id, int req, const std::string& tid, common::mojom::DomainStatus status, int64_t bytes_readed) override;
  void OnShareWrite(uint32_t context_id, int req, const std::string& tid, common::mojom::DomainStatus status, int64_t bytes_written) override;
  void OnSharePaused(uint32_t context_id, int req, const std::string& tid) override;
  void OnShareResumed(uint32_t context_id, int req, const std::string& tid) override;
  void OnShareChecked(uint32_t context_id, int req, const std::string& tid, common::mojom::DomainStatus status) override;
  void OnSharePieceComplete(uint32_t context_id, int req, const std::string& tid, uint32_t piece_offset) override;
  void OnShareFileComplete(uint32_t context_id, int req, const std::string& tid, int32_t file_offset) override;
  void OnShareDownloading(uint32_t context_id, int req, const std::string& tid) override;
  void OnShareComplete(uint32_t context_id, int req, const std::string& tid) override;
  void OnShareSeeding(uint32_t context_id, int req, const std::string& tid) override;
  void OnShareShare(uint32_t context_id, int req, const std::string& tid, common::mojom::DomainStatus status) override;
  void OnShareUnshare(uint32_t context_id, int req, const std::string& tid, common::mojom::DomainStatus status) override;
  void OnShareSubscribe(uint32_t context_id, int req, const std::string& tid, common::mojom::DomainStatus status) override;
  void OnShareUnsubscribe(uint32_t context_id, int req, const std::string& tid, common::mojom::DomainStatus status) override;
  void OnShareEvent(uint32_t context_id, int req, const std::string& tid, common::mojom::ShareEventPtr event) override;

  void OnShareDHTAnnounceReply(uint32_t context_id, int32_t req, const std::string& tid, int32_t peers) override;
  void OnShareMetadataReceived(uint32_t context_id, int32_t req, const std::string& tid) override;
  void OnShareMetadataError(uint32_t context_id, int32_t req, const std::string& tid, int32_t error) override;
  void OnSharePieceReadError(uint32_t context_id, int32_t req, const std::string& tid, int32_t piece, int32_t error) override;
  void OnSharePiecePass(uint32_t context_id, int32_t req, const std::string& tid, int32_t piece) override;
  void OnSharePieceFailed(uint32_t context_id, int32_t req, const std::string& tid, int32_t piece) override;
  void OnSharePieceRead(uint32_t context_id, int32_t req, const std::string& tid, int32_t piece, int64_t offset, int64_t size, int64_t block_size, int32_t result) override;
  void OnSharePieceWrite(uint32_t context_id, int32_t req, const std::string& tid, int32_t piece, int64_t offset, int64_t size, int64_t block_size, int32_t result) override;
  void OnSharePieceHashFailed(uint32_t context_id, int32_t req, const std::string& tid, int32_t piece) override;
  void OnShareCheckingFiles(uint32_t context_id, int32_t req, const std::string& tid) override;
  void OnShareDownloadingMetadata(uint32_t context_id, int32_t req, const std::string& tid) override;
  void OnShareFileRenamed(uint32_t context_id, int32_t req, const std::string& tid, int32_t file_offset, const std::string& name, int32_t error) override;

  // files
  void OnFileCreate(uint32_t context_id, int req, const std::string& tid, const std::string& file, common::mojom::DomainStatus status) override;
  void OnFileAdd(uint32_t context_id, int req, const std::string& tid, const std::string& file, common::mojom::DomainStatus status) override;
  void OnFileOpen(uint32_t context_id, int req, const std::string& tid, const std::string& file, common::mojom::DomainStatus status) override;
  void OnFileDelete(uint32_t context_id, int req, const std::string& tid, const std::string& file, common::mojom::DomainStatus status) override;
  void OnFileReadOnce(uint32_t context_id, int req, const std::string& tid, const std::string& file, common::mojom::DomainStatus status, int64_t bytes_readed, mojo::ScopedSharedBufferHandle data) override;
  void OnFileRead(uint32_t context_id, int req, const std::string& tid, const std::string& file, common::mojom::DomainStatus status, int64_t bytes_written) override;
  void OnFileWrite(uint32_t context_id, int req, const std::string& tid, const std::string& file, common::mojom::DomainStatus status, int64_t bytes_written) override;
  void OnFileClose(uint32_t context_id, int req, const std::string& tid, const std::string& file, common::mojom::DomainStatus status) override;
  void OnFileRename(uint32_t context_id, int req, const std::string& tid, const std::string& file, common::mojom::DomainStatus status) override;
  void OnFileWriteOnce(uint32_t context_id, int req, const std::string& tid, const std::string& file, common::mojom::DomainStatus status, int64_t bytes_written) override;
  //void OnFileList(uint32_t context_id, int req, const std::string& tid, common::mojom::DomainStatus status, const std::vector<std::string>& files) override;
  
  // data
  void OnDataClose(uint32_t context_id, int req, const std::string& tid, common::mojom::DomainStatus status) override;
  void OnDataDrop(uint32_t context_id, int req, const std::string& tid, common::mojom::DomainStatus status) override;
  void OnDataCreateKeyspace(uint32_t context_id, int req, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status) override;
  void OnDataDeleteKeyspace(uint32_t context_id, int req, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status) override;
  void OnDataListKeyspaces(uint32_t context_id, int req, const std::string& tid, common::mojom::DomainStatus status, const std::vector<std::string>& keyspaces) override;
  void OnDataPut(uint32_t context_id, int req, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status, int64_t wrote) override;
  void OnDataGet(uint32_t context_id, int req, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status, int64_t wrote) override;
  void OnDataGetOnce(uint32_t context_id, int req, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status, int64_t readed, mojo::ScopedSharedBufferHandle data) override;
  void OnDataGetFailed(uint32_t context_id, int req, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status) override;
  void OnDataDelete(uint32_t context_id, int req, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status) override;
  void OnDataDeleteAll(uint32_t context_id, int req, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status) override;
  void OnIndexResolveId(uint32_t context_id, int req, const std::string& address, const std::string& resolved_uuid, common::mojom::DomainStatus status) override;

private:
  // access to StorageDispatcherHostAssociatedPtr heap offset
  friend class DomainMainThread;

  mojo::AssociatedBinding<common::mojom::StorageDispatcher> binding_;
  common::mojom::StorageDispatcherHostAssociatedPtr storage_dispatcher_host_interface_;

  StorageManager* storage_manager_;

  DISALLOW_COPY_AND_ASSIGN(StorageDispatcher);
};

}

#endif