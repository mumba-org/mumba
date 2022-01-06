// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_STORAGE_STORAGE_DISPATCHER_H_
#define MUMBA_DOMAIN_STORAGE_STORAGE_DISPATCHER_H_

#include "base/macros.h"
#include "core/shared/common/mojom/storage.mojom.h"
#include "core/domain/domain_context.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"

namespace domain {

class StorageDispatcher : public common::mojom::StorageDispatcher {
public:
  StorageDispatcher();
  ~StorageDispatcher() override;
  
  void Bind(common::mojom::StorageDispatcherAssociatedRequest request);

  void OnContextCreate(common::mojom::StorageContextPtr context, common::mojom::DomainStatus status) override;
  void OnContextDestroy(common::mojom::StorageContextPtr context, common::mojom::DomainStatus status) override;

  // torrents
  void OnTorrentCreate(common::mojom::StorageContextPtr context, const std::string& tid, common::mojom::DomainStatus status) override;
  void OnTorrentAdd(common::mojom::StorageContextPtr context, const std::string& tid, common::mojom::DomainStatus status) override;
  void OnTorrentOpen(common::mojom::StorageContextPtr context, const std::string& tid, common::mojom::DomainStatus status) override;
  void OnTorrentClose(common::mojom::StorageContextPtr context, const std::string& tid, common::mojom::DomainStatus status) override;
  void OnTorrentDelete(common::mojom::StorageContextPtr context, const std::string& tid, common::mojom::DomainStatus status) override;
  void OnTorrentRead(common::mojom::StorageContextPtr context, const std::string& tid, common::mojom::DomainStatus status, int64_t bytes_readed) override;
  void OnTorrentWrite(common::mojom::StorageContextPtr context, const std::string& tid, common::mojom::DomainStatus status, int64_t bytes_written) override;
  void OnTorrentPaused(common::mojom::StorageContextPtr context, const std::string& tid) override;
  void OnTorrentResumed(common::mojom::StorageContextPtr context, const std::string& tid) override;
  void OnTorrentChecked(common::mojom::StorageContextPtr context, const std::string& tid, common::mojom::DomainStatus status) override;
  void OnTorrentPieceComplete(common::mojom::StorageContextPtr context, const std::string& tid, uint32_t piece_offset) override;
  void OnTorrentFileComplete(common::mojom::StorageContextPtr context, const std::string& tid, const std::string& file) override;
  void OnTorrentDownloading(common::mojom::StorageContextPtr context, const std::string& tid) override;
  void OnTorrentComplete(common::mojom::StorageContextPtr context, const std::string& tid) override;
  void OnTorrentSeeding(common::mojom::StorageContextPtr context, const std::string& tid) override;
  void OnTorrentShare(common::mojom::StorageContextPtr context, const std::string& tid, common::mojom::DomainStatus status) override;
  void OnTorrentUnshare(common::mojom::StorageContextPtr context, const std::string& tid, common::mojom::DomainStatus status) override;
  void OnTorrentSubscribe(common::mojom::StorageContextPtr context, const std::string& tid, common::mojom::DomainStatus status) override;
  void OnTorrentUnsubscribe(common::mojom::StorageContextPtr context, const std::string& tid, common::mojom::DomainStatus status) override;
  void OnTorrentEvent(common::mojom::StorageContextPtr context, const std::string& tid, common::mojom::TorrentEventPtr event) override;

  // files
  void OnFileCreate(common::mojom::StorageContextPtr context, const std::string& tid, const std::string& file, common::mojom::DomainStatus status) override;
  void OnFileAdd(common::mojom::StorageContextPtr context, const std::string& tid, const std::string& file, common::mojom::DomainStatus status) override;
  void OnFileOpen(common::mojom::StorageContextPtr context, const std::string& tid, const std::string& file, common::mojom::DomainStatus status) override;
  void OnFileDelete(common::mojom::StorageContextPtr context, const std::string& tid, const std::string& file, common::mojom::DomainStatus status) override;
  void OnFileRead(common::mojom::StorageContextPtr context, const std::string& tid, const std::string& file, common::mojom::DomainStatus status, int64_t bytes_readed) override;
  void OnFileWrite(common::mojom::StorageContextPtr context, const std::string& tid, const std::string& file, common::mojom::DomainStatus status, int64_t bytes_written) override;
  void OnFileClose(common::mojom::StorageContextPtr context, const std::string& tid, const std::string& file, common::mojom::DomainStatus status) override;
  void OnFileRename(common::mojom::StorageContextPtr context, const std::string& tid, const std::string& file, common::mojom::DomainStatus status) override;
  
  // data
  void OnDataCreate(common::mojom::StorageContextPtr context, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status) override;
  void OnDataDelete(common::mojom::StorageContextPtr context, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status) override;
  void OnDataOpen(common::mojom::StorageContextPtr context, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status) override;
  void OnDataClose(common::mojom::StorageContextPtr context, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status) override;
  void OnDataPut(common::mojom::StorageContextPtr context, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status, int64_t wrote) override;
  void OnDataGet(common::mojom::StorageContextPtr context, const std::string& tid, const std::string& keyspace, common::mojom::DomainStatus status, int64_t readed) override;

private:
  
  mojo::AssociatedBinding<common::mojom::StorageDispatcher> binding_;

  DISALLOW_COPY_AND_ASSIGN(StorageDispatcher);
};

}

#endif