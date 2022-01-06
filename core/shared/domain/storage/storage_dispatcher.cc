// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/storage/storage_dispatcher.h"

#include "core/shared/domain/storage/storage_context.h"
#include "core/shared/domain/storage/storage_manager.h"

namespace domain {

StorageDispatcher::StorageDispatcher(): 
  binding_(this), 
  storage_manager_(nullptr) {
  
}

StorageDispatcher::~StorageDispatcher() {
  storage_manager_ = nullptr;
}

common::mojom::StorageDispatcherHost* StorageDispatcher::GetStorageDispatcherHostInterface() {
  return storage_dispatcher_host_interface_.get();
}

void StorageDispatcher::Bind(common::mojom::StorageDispatcherAssociatedRequest request) {
  binding_.Bind(std::move(request));
}

void StorageDispatcher::OnContextDestroy(uint32_t context_id, common::mojom::DomainStatus status) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnDestroy(status);
}

void StorageDispatcher::OnShareCreate(uint32_t context_id, int req, const std::string& tid, common::mojom::DomainStatus status) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnShareCreate(req, tid, status);
}

void StorageDispatcher::OnShareAdd(uint32_t context_id, int req, const std::string& tid, common::mojom::DomainStatus status) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnShareAdd(req, base::UUID(reinterpret_cast<const uint8_t *>(tid.data())), status);
}

void StorageDispatcher::OnShareOpen(uint32_t context_id, int req, const std::string& tid, common::mojom::DomainStatus status) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnShareOpen(req, tid, status);
}

void StorageDispatcher::OnShareClose(uint32_t context_id, int req, const std::string& tid, common::mojom::DomainStatus status) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnShareClose(req, base::UUID(reinterpret_cast<const uint8_t *>(tid.data())), status);
}

void StorageDispatcher::OnShareDelete(uint32_t context_id, int req, const std::string& tid, common::mojom::DomainStatus status) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnShareDelete(req, base::UUID(reinterpret_cast<const uint8_t *>(tid.data())), status);
}

void StorageDispatcher::OnShareRead(uint32_t context_id, int req, const std::string& tid, common::mojom::DomainStatus status, int64_t bytes_readed) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnShareRead(req, base::UUID(reinterpret_cast<const uint8_t *>(tid.data())), status, bytes_readed);
}

void StorageDispatcher::OnShareWrite(uint32_t context_id, int req, const std::string& tid, common::mojom::DomainStatus status, int64_t bytes_written) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnShareWrite(req, base::UUID(reinterpret_cast<const uint8_t *>(tid.data())), status, bytes_written);
}

void StorageDispatcher::OnShareShare(uint32_t context_id, int req, const std::string& tid, common::mojom::DomainStatus status) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnShareShare(req, base::UUID(reinterpret_cast<const uint8_t *>(tid.data())), status);
}

void StorageDispatcher::OnShareUnshare(uint32_t context_id, int req, const std::string& tid, common::mojom::DomainStatus status) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnShareUnshare(req, base::UUID(reinterpret_cast<const uint8_t *>(tid.data())), status);
}

void StorageDispatcher::OnShareSubscribe(uint32_t context_id, int req, const std::string& tid, common::mojom::DomainStatus status) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnShareSubscribe(req, base::UUID(reinterpret_cast<const uint8_t *>(tid.data())), status);
}

void StorageDispatcher::OnShareUnsubscribe(uint32_t context_id, int req, const std::string& tid, common::mojom::DomainStatus status) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnShareUnsubscribe(req, base::UUID(reinterpret_cast<const uint8_t *>(tid.data())), status);
}

void StorageDispatcher::OnShareEvent(uint32_t context_id, int req, const std::string& tid, common::mojom::ShareEventPtr event) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnShareEvent(req, base::UUID(reinterpret_cast<const uint8_t *>(tid.data())), std::move(event));
}

void StorageDispatcher::OnFileCreate(uint32_t context_id, int req, const std::string& tid, const std::string& file, common::mojom::DomainStatus status) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnFileCreate(req, base::UUID(reinterpret_cast<const uint8_t *>(tid.data())), file, status);
}

void StorageDispatcher::OnFileAdd(uint32_t context_id, int req, const std::string& tid, const std::string& file, common::mojom::DomainStatus status) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnFileAdd(req, base::UUID(reinterpret_cast<const uint8_t *>(tid.data())), file, status);
}

void StorageDispatcher::OnFileOpen(uint32_t context_id, int req, const std::string& tid, const std::string& file, common::mojom::DomainStatus status) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnFileOpen(req, base::UUID(reinterpret_cast<const uint8_t *>(tid.data())), file, status);
}

void StorageDispatcher::OnFileDelete(uint32_t context_id, int req, const std::string& tid, const std::string& file, common::mojom::DomainStatus status) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnFileDelete(req, base::UUID(reinterpret_cast<const uint8_t *>(tid.data())), file, status);
}

void StorageDispatcher::OnFileReadOnce(uint32_t context_id, int req, const std::string& tid, const std::string& file, common::mojom::DomainStatus status, int64_t bytes_readed, mojo::ScopedSharedBufferHandle data) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnFileReadOnce(req, tid, file, status, bytes_readed, std::move(data));
}

void StorageDispatcher::OnFileRead(uint32_t context_id, int req, const std::string& tid, const std::string& file, common::mojom::DomainStatus status, int64_t bytes_written) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnFileRead(req, base::UUID(reinterpret_cast<const uint8_t *>(tid.data())), file, status, bytes_written);
}

void StorageDispatcher::OnFileWrite(uint32_t context_id, int req, const std::string& tid, const std::string& file, common::mojom::DomainStatus status, int64_t bytes_written) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnFileWrite(req, base::UUID(reinterpret_cast<const uint8_t *>(tid.data())), file, status, bytes_written);
}

void StorageDispatcher::OnFileWriteOnce(uint32_t context_id, int req, const std::string& tid, const std::string& file, common::mojom::DomainStatus status, int64_t bytes_written) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnFileWriteOnce(req, tid, file, status, bytes_written);
}

void StorageDispatcher::OnFileClose(uint32_t context_id, int req, const std::string& tid, const std::string& file, common::mojom::DomainStatus status) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnFileClose(req, base::UUID(reinterpret_cast<const uint8_t *>(tid.data())), file, status);
}

void StorageDispatcher::OnFileRename(uint32_t context_id, int req, const std::string& tid, const std::string& file, common::mojom::DomainStatus status) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnFileRename(req, base::UUID(reinterpret_cast<const uint8_t *>(tid.data())), file, status);
}

// void StorageDispatcher::OnFileList(uint32_t context_id, int req, const std::string& tid, common::mojom::DomainStatus status, const std::vector<std::string>& files) {
//   auto storage_context = storage_manager_->GetContext(context_id);
//   storage_context->OnFileList(req, tid, status, files);
// }

// void StorageDispatcher::OnDataOpen(uint32_t context_id, int req, const std::string& tid, common::mojom::DomainStatus status) {
//   //DLOG(INFO) << "StorageDispatcher::OnDataOpen";
//   auto storage_context = storage_manager_->GetContext(context_id);
//   storage_context->OnDataOpen(req, base::UUID(reinterpret_cast<const uint8_t *>(tid.data())), status);
// }

void StorageDispatcher::OnDataClose(uint32_t context_id, int req, const std::string& tid, common::mojom::DomainStatus status) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnDataClose(req, tid, status);
}

// void StorageDispatcher::OnDataCreate(uint32_t context_id, int req, const std::string& tid, common::mojom::DomainStatus status) {
//   //DLOG(INFO) << "StorageDispatcher::OnDataCreate";
//   auto storage_context = storage_manager_->GetContext(context_id);
//   storage_context->OnDataCreate(req, base::UUID(reinterpret_cast<const uint8_t *>(tid.data())), status);
// }

void StorageDispatcher::OnDataDrop(uint32_t context_id, int req, const std::string& tid, common::mojom::DomainStatus status) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnDataDrop(req, tid, status);
}

void StorageDispatcher::OnDataCreateKeyspace(uint32_t context_id, int req, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnDataCreateKeyspace(req, tid, keyspace, status);
}

void StorageDispatcher::OnDataDeleteKeyspace(uint32_t context_id, int req, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnDataDeleteKeyspace(req, tid, keyspace, status);
}

void StorageDispatcher::OnDataListKeyspaces(uint32_t context_id, int req, const std::string& tid, common::mojom::DomainStatus status, const std::vector<std::string>& keyspaces) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnDataListKeyspaces(req, tid, status, keyspaces);
}

void StorageDispatcher::OnDataPut(uint32_t context_id, int req, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status, int64_t wrote) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnDataPut(req, tid, keyspace, status, wrote);
}

void StorageDispatcher::OnDataGet(uint32_t context_id, int req, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status, int64_t wrote) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnDataGet(req, tid, keyspace, status, wrote);
}

void StorageDispatcher::OnDataGetOnce(uint32_t context_id, int req, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status, int64_t readed, mojo::ScopedSharedBufferHandle data) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnDataGetOnce(req, tid, keyspace, status, readed, std::move(data));
}

void StorageDispatcher::OnDataGetFailed(uint32_t context_id, int req, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnDataGetFailed(req, tid, keyspace, status);
}

void StorageDispatcher::OnDataDelete(uint32_t context_id, int req, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnDataDelete(req, tid, keyspace, status);
}

void StorageDispatcher::OnDataDeleteAll(uint32_t context_id, int req, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnDataDeleteAll(req, tid, keyspace, status);
}

void StorageDispatcher::OnIndexResolveId(uint32_t context_id, int req, const std::string& address, const std::string& resolved_uuid, common::mojom::DomainStatus status) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnIndexResolveId(req, address, base::UUID(reinterpret_cast<const uint8_t *>(resolved_uuid.data())), status); 
}

void StorageDispatcher::OnSharePaused(uint32_t context_id, int req, const std::string& tid) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnSharePaused(base::UUID(reinterpret_cast<const uint8_t *>(tid.data())));
}

void StorageDispatcher::OnShareResumed(uint32_t context_id, int req, const std::string& tid) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnShareResumed(base::UUID(reinterpret_cast<const uint8_t *>(tid.data())));
}

void StorageDispatcher::OnShareChecked(uint32_t context_id, int req, const std::string& tid, common::mojom::DomainStatus status) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnShareChecked(base::UUID(reinterpret_cast<const uint8_t *>(tid.data())), status);
}

void StorageDispatcher::OnSharePieceComplete(uint32_t context_id, int req, const std::string& tid, uint32_t piece_offset) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnSharePieceComplete(base::UUID(reinterpret_cast<const uint8_t *>(tid.data())), piece_offset);
}

void StorageDispatcher::OnShareFileComplete(uint32_t context_id, int req, const std::string& tid, int32_t file_offset) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnShareFileComplete(base::UUID(reinterpret_cast<const uint8_t *>(tid.data())), file_offset);
}

void StorageDispatcher::OnShareDownloading(uint32_t context_id, int req, const std::string& tid) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnShareDownloading(base::UUID(reinterpret_cast<const uint8_t *>(tid.data())));
}

void StorageDispatcher::OnShareComplete(uint32_t context_id, int req, const std::string& tid) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnShareComplete(base::UUID(reinterpret_cast<const uint8_t *>(tid.data())));
}

void StorageDispatcher::OnShareSeeding(uint32_t context_id, int req, const std::string& tid) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnShareSeeding(base::UUID(reinterpret_cast<const uint8_t *>(tid.data())));
}

void StorageDispatcher::OnShareDHTAnnounceReply(uint32_t context_id, int32_t req, const std::string& tid, int32_t peers) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnShareDHTAnnounceReply(base::UUID(reinterpret_cast<const uint8_t *>(tid.data())), peers);
}

void StorageDispatcher::OnShareMetadataReceived(uint32_t context_id, int32_t req, const std::string& tid) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnShareMetadataReceived(base::UUID(reinterpret_cast<const uint8_t *>(tid.data())));
}

void StorageDispatcher::OnShareMetadataError(uint32_t context_id, int32_t req, const std::string& tid, int32_t error) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnShareMetadataError(base::UUID(reinterpret_cast<const uint8_t *>(tid.data())), error);
}

void StorageDispatcher::OnSharePieceReadError(uint32_t context_id, int32_t req, const std::string& tid, int32_t piece, int32_t error) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnSharePieceReadError(base::UUID(reinterpret_cast<const uint8_t *>(tid.data())), piece, error);
}

void StorageDispatcher::OnSharePiecePass(uint32_t context_id, int32_t req, const std::string& tid, int32_t piece) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnSharePiecePass(base::UUID(reinterpret_cast<const uint8_t *>(tid.data())), piece);
}

void StorageDispatcher::OnSharePieceFailed(uint32_t context_id, int32_t req, const std::string& tid, int32_t piece) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnSharePieceFailed(base::UUID(reinterpret_cast<const uint8_t *>(tid.data())), piece);
}

void StorageDispatcher::OnSharePieceRead(uint32_t context_id, int32_t req, const std::string& tid, int32_t piece, int64_t offset, int64_t size, int64_t block_size, int32_t result) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnSharePieceRead(base::UUID(reinterpret_cast<const uint8_t *>(tid.data())), piece, offset, size, block_size, result);
}

void StorageDispatcher::OnSharePieceWrite(uint32_t context_id, int32_t req, const std::string& tid, int32_t piece, int64_t offset, int64_t size, int64_t block_size, int32_t result) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnSharePieceWrite(base::UUID(reinterpret_cast<const uint8_t *>(tid.data())), piece, offset, size, block_size, result);
}

void StorageDispatcher::OnSharePieceHashFailed(uint32_t context_id, int32_t req, const std::string& tid, int32_t piece) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnSharePieceHashFailed(base::UUID(reinterpret_cast<const uint8_t *>(tid.data())), piece);
}

void StorageDispatcher::OnShareCheckingFiles(uint32_t context_id, int32_t req, const std::string& tid) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnShareCheckingFiles(base::UUID(reinterpret_cast<const uint8_t *>(tid.data())));
}

void StorageDispatcher::OnShareDownloadingMetadata(uint32_t context_id, int32_t req, const std::string& tid) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnShareDownloadingMetadata(base::UUID(reinterpret_cast<const uint8_t *>(tid.data())));
}
  
void StorageDispatcher::OnShareFileRenamed(uint32_t context_id, int32_t req, const std::string& tid, int32_t file_offset, const std::string& name, int32_t error) {
  auto storage_context = storage_manager_->GetContext(context_id);
  storage_context->OnShareFileRenamed(base::UUID(reinterpret_cast<const uint8_t *>(tid.data())), file_offset, name, error);
}


}