// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_CORE_HOST_ROUTE_REGISTRY_ROUTE_SCHEME_H_
#define MUMBA_CORE_HOST_ROUTE_REGISTRY_ROUTE_SCHEME_H_

#include <string>

#include "base/macros.h"
#include "core/host/route/route_observer.h"
#include "storage/torrent.h"
#include "core/host/share/share_observer.h"
#include "core/host/serializable.h"
#include "core/shared/common/mojom/route.mojom.h"

namespace host {
class RouteEntry;
class RouteRegistry;
class RoutePeer;
class RouteHandler;
class HostRpcService;
class Domain;

// The torrent associated with the collection entry
// must be the "root" torrent

class RouteScheme : public Serializable,
                  public RouteObserver,
                  public ShareObserver {
public:
  RouteScheme(RouteRegistry* registry);
  RouteScheme(RouteRegistry* registry,
            common::mojom::RouteEntryPtr entry_ptr,
            common::mojom::RouteEntryExtrasPtr extras);
  ~RouteScheme() override;

  common::mojom::RouteEntryType type() const {
    return entry_->type;
  }

  void set_type(common::mojom::RouteEntryType type) {
    entry_->type = type;
  }

  common::mojom::RouteEntryTransportType transport_type() const {
    return entry_->transport_type;
  }

  void set_transport_type(common::mojom::RouteEntryTransportType transport_type) {
    entry_->transport_type = transport_type;
  }

  common::mojom::RouteEntryRPCMethodType rpc_method_type() const {
    return entry_->rpc_method_type;
  }

  void set_rpc_method_type(common::mojom::RouteEntryRPCMethodType method_type) {
    entry_->rpc_method_type = method_type;
  }

  const std::string& content_type() const {
    return entry_->content_type;
  }

  void set_content_type(const std::string& content_type) {
    entry_->content_type = content_type;
  }

 int64_t content_size() const {
    return entry_->content_size;
  }

  void set_content_size(int64_t content_size) {
    entry_->content_size = content_size;
  }

  const std::string& content_hash_sha1() const {
    return entry_->content_hash_sha1;
  }

  void set_content_hash_sha1(const std::string& content_hash) {
    entry_->content_hash_sha1 = content_hash;
  }

  const std::string& name() const {
    return entry_->name;
  }

  void set_name(const std::string& name) {
    entry_->name = name;
  }

  const base::UUID& uuid() const {
    return uuid_;
  }

  void set_uuid(const base::UUID& uuid) {
    uuid_ = uuid;
    entry_->uuid = std::string(reinterpret_cast<const char*>(uuid_.data), 16);
  }

  void set_uuid(base::UUID&& uuid) {
    uuid_ = std::move(uuid);
    entry_->uuid = std::string(reinterpret_cast<const char*>(uuid_.data), 16);
  }

  const base::string16& title() const {
    return entry_->title;
  }

  void set_title(const base::string16& title) {
    entry_->title = title;
  }

  const GURL& url() const {
    return entry_->url;
  }

  void set_url(const GURL& url) {
    entry_->url = url;
  }

  const std::string& fullname() const {
    return entry_->fullname;
  }

  void set_fullname(const std::string& fullname) {
    entry_->fullname = fullname;
  }

  const std::string& path() const {
    return entry_->path;
  }

  void set_path(const std::string& path) {
    entry_->path = path;
  }

  void set_extras(common::mojom::RouteEntryExtrasPtr extras) {
    extras_ = std::move(extras);
  }

  // bool has_icon_data() const {
  //   return !extras_.is_null();
  // }

  mojo::ScopedSharedBufferMapping icon_data() const {
    auto size = extras_? extras_->icon_data_size : 0;
    DCHECK(size != 0);
    return extras_->icon_data->Map(size);
  }

  int icon_data_size() const {
    return extras_ ? extras_->icon_data_size : 0;
  }

  Share* share() const {
    return share_;
  }

  void set_share(Share* share);

  const std::string& dht_public_key() const {
    return dht_public_key_;
  }

  void set_dht_public_key(const std::string& key) {
    dht_public_key_ = key;
  }

  HostRpcService* service() const {
    return service_;
  }

  void set_service(HostRpcService* service) {
    service_ = service;
  }

  Domain* domain() const {
    return domain_;
  }

  void set_domain(Domain* domain) {
    domain_ = domain;
  }

  const std::vector<RouteEntry *>& entries() const {
    return entries_;
  }

  scoped_refptr<net::IOBufferWithSize> Serialize() const override;

private:
  friend class RouteModel;
  friend class RouteRegistry;
  
  void AddEntry(RouteEntry* entry);
  void RemoveEntry(RouteEntry* entry);

  // RouteObserver
  void OnRouteAdded(RouteEntry* entry) override;
  void OnRouteRemoved(RouteEntry* entry) override;

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

  void load_uuid() {
    if (entry_->uuid.empty()) {
      return;
    }
    DCHECK(entry_->uuid.size() == 16);
    uuid_ = base::UUID(reinterpret_cast<const uint8_t*>(entry_->uuid.data()));  
  }

  RouteRegistry* registry_;
  HostRpcService* service_;
  Share* share_;
  Domain* domain_;
  
  base::UUID uuid_;
  // a tree is also some sort of entry
  common::mojom::RouteEntryPtr entry_;
  common::mojom::RouteEntryExtrasPtr extras_;
  
  std::string name_;
  // entries, owned by RouteModel
  std::vector<RouteEntry *> entries_;
  //std::vector<std::unique_ptr<RoutePeer>> peers_;
  // handlers, owned by RouteModel
  //std::vector<RouteHandler *> handlers_;
  std::string dht_public_key_;

  DISALLOW_COPY_AND_ASSIGN(RouteScheme);
};

}

#endif
