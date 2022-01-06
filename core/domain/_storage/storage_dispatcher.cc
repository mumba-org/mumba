// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/storage/storage_dispatcher.h"

namespace domain {

StorageDispatcher::StorageDispatcher(): binding_(this) {
  
}

StorageDispatcher::~StorageDispatcher() {

}

void StorageDispatcher::Bind(common::mojom::StorageDispatcherAssociatedRequest request) {
  binding_.Bind(std::move(request));
}

void StorageDispatcher::OnContextCreate(common::mojom::StorageContextPtr context, common::mojom::DomainStatus status) {
  //DLOG(INFO) << "StorageDispatcher::OnContextCreate";
}

void StorageDispatcher::OnContextDestroy(common::mojom::StorageContextPtr context, common::mojom::DomainStatus status) {
  //DLOG(INFO) << "StorageDispatcher::OnContextDestroy";
}

void StorageDispatcher::OnTorrentCreate(common::mojom::StorageContextPtr context, const std::string& tid, common::mojom::DomainStatus status) {
  //DLOG(INFO) << "StorageDispatcher::OnTorrentCreate";
}

void StorageDispatcher::OnTorrentAdd(common::mojom::StorageContextPtr context, const std::string& tid, common::mojom::DomainStatus status) {
  //DLOG(INFO) << "StorageDispatcher::OnTorrentAdd";
}

void StorageDispatcher::OnTorrentOpen(common::mojom::StorageContextPtr context, const std::string& tid, common::mojom::DomainStatus status) {
  //DLOG(INFO) << "StorageDispatcher::OnTorrentOpen";
}

void StorageDispatcher::OnTorrentClose(common::mojom::StorageContextPtr context, const std::string& tid, common::mojom::DomainStatus status) {
  //DLOG(INFO) << "StorageDispatcher::OnTorrentClose";
}

void StorageDispatcher::OnTorrentDelete(common::mojom::StorageContextPtr context, const std::string& tid, common::mojom::DomainStatus status) {
  //DLOG(INFO) << "StorageDispatcher::OnTorrentDelete";
}

void StorageDispatcher::OnTorrentRead(common::mojom::StorageContextPtr context, const std::string& tid, common::mojom::DomainStatus status, int64_t bytes_readed) {
  //DLOG(INFO) << "StorageDispatcher::OnTorrentRead";
}

void StorageDispatcher::OnTorrentWrite(common::mojom::StorageContextPtr context, const std::string& tid, common::mojom::DomainStatus status, int64_t bytes_written) {
  //DLOG(INFO) << "StorageDispatcher::OnTorrentWrite";
}

void StorageDispatcher::OnTorrentPaused(common::mojom::StorageContextPtr context, const std::string& tid) {
  //DLOG(INFO) << "StorageDispatcher::OnTorrentPaused";
}

void StorageDispatcher::OnTorrentResumed(common::mojom::StorageContextPtr context, const std::string& tid) {
  //DLOG(INFO) << "StorageDispatcher::OnTorrentResumed";
}

void StorageDispatcher::OnTorrentChecked(common::mojom::StorageContextPtr context, const std::string& tid, common::mojom::DomainStatus status) {
  //DLOG(INFO) << "StorageDispatcher::OnTorrentChecked";
}

void StorageDispatcher::OnTorrentPieceComplete(common::mojom::StorageContextPtr context, const std::string& tid, uint32_t piece_offset) {
  //DLOG(INFO) << "StorageDispatcher::OnTorrentPieceComplete";
}

void StorageDispatcher::OnTorrentFileComplete(common::mojom::StorageContextPtr context, const std::string& tid, const std::string& file) {
  //DLOG(INFO) << "StorageDispatcher::OnTorrentFileComplete";
}

void StorageDispatcher::OnTorrentDownloading(common::mojom::StorageContextPtr context, const std::string& tid) {
  //DLOG(INFO) << "StorageDispatcher::OnTorrentDownloading";
}

void StorageDispatcher::OnTorrentComplete(common::mojom::StorageContextPtr context, const std::string& tid) {
  //DLOG(INFO) << "StorageDispatcher::OnTorrentComplete";
}

void StorageDispatcher::OnTorrentSeeding(common::mojom::StorageContextPtr context, const std::string& tid) {
  //DLOG(INFO) << "StorageDispatcher::OnTorrentSeeding";
}

void StorageDispatcher::OnTorrentShare(common::mojom::StorageContextPtr context, const std::string& tid, common::mojom::DomainStatus status) {
  //DLOG(INFO) << "StorageDispatcher::OnTorrentShare";
}

void StorageDispatcher::OnTorrentUnshare(common::mojom::StorageContextPtr context, const std::string& tid, common::mojom::DomainStatus status) {
  //DLOG(INFO) << "StorageDispatcher::OnTorrentUnshare";
}

void StorageDispatcher::OnTorrentSubscribe(common::mojom::StorageContextPtr context, const std::string& tid, common::mojom::DomainStatus status) {
  //DLOG(INFO) << "StorageDispatcher::OnTorrentSubscribe";
}

void StorageDispatcher::OnTorrentUnsubscribe(common::mojom::StorageContextPtr context, const std::string& tid, common::mojom::DomainStatus status) {
  //DLOG(INFO) << "StorageDispatcher::OnTorrentUnsubscribe";
}

void StorageDispatcher::OnTorrentEvent(common::mojom::StorageContextPtr context, const std::string& tid, common::mojom::TorrentEventPtr event) {
  //DLOG(INFO) << "StorageDispatcher::OnTorrentEvent";
}

void StorageDispatcher::OnFileCreate(common::mojom::StorageContextPtr context, const std::string& tid, const std::string& file, common::mojom::DomainStatus status) {
  //DLOG(INFO) << "StorageDispatcher::OnFileCreate";
}

void StorageDispatcher::OnFileAdd(common::mojom::StorageContextPtr context, const std::string& tid, const std::string& file, common::mojom::DomainStatus status) {
  //DLOG(INFO) << "StorageDispatcher::OnFileAdd";
}

void StorageDispatcher::OnFileOpen(common::mojom::StorageContextPtr context, const std::string& tid, const std::string& file, common::mojom::DomainStatus status) {
  //DLOG(INFO) << "StorageDispatcher::OnFileOpen";
}

void StorageDispatcher::OnFileDelete(common::mojom::StorageContextPtr context, const std::string& tid, const std::string& file, common::mojom::DomainStatus status) {
  //DLOG(INFO) << "StorageDispatcher::OnFileDelete";
}

void StorageDispatcher::OnFileRead(common::mojom::StorageContextPtr context, const std::string& tid, const std::string& file, common::mojom::DomainStatus status, int64_t bytes_readed) {
  //DLOG(INFO) << "StorageDispatcher::OnFileRead";
}

void StorageDispatcher::OnFileWrite(common::mojom::StorageContextPtr context, const std::string& tid, const std::string& file, common::mojom::DomainStatus status, int64_t bytes_written) {
  //DLOG(INFO) << "StorageDispatcher::OnFileWrite";
}

void StorageDispatcher::OnFileClose(common::mojom::StorageContextPtr context, const std::string& tid, const std::string& file, common::mojom::DomainStatus status) {
  //DLOG(INFO) << "StorageDispatcher::OnFileClose";
}

void StorageDispatcher::OnFileRename(common::mojom::StorageContextPtr context, const std::string& tid, const std::string& file, common::mojom::DomainStatus status) {
  //DLOG(INFO) << "StorageDispatcher::OnFileRename";
}

void StorageDispatcher::OnDataCreate(common::mojom::StorageContextPtr context, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status) {
  //DLOG(INFO) << "StorageDispatcher::OnDataCreate";
}

void StorageDispatcher::OnDataDelete(common::mojom::StorageContextPtr context, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status) {
  //DLOG(INFO) << "StorageDispatcher::OnDataDelete";
}

void StorageDispatcher::OnDataOpen(common::mojom::StorageContextPtr context, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status) {
  //DLOG(INFO) << "StorageDispatcher::OnDataOpen";
}

void StorageDispatcher::OnDataClose(common::mojom::StorageContextPtr context, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status) {
  //DLOG(INFO) << "StorageDispatcher::OnDataClose";
}

void StorageDispatcher::OnDataPut(common::mojom::StorageContextPtr context, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status, int64_t wrote) {
  //DLOG(INFO) << "StorageDispatcher::OnDataPut";
}

void StorageDispatcher::OnDataGet(common::mojom::StorageContextPtr context, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status, int64_t readed) {
  //DLOG(INFO) << "StorageDispatcher::OnDataGet";
}


}