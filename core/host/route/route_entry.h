// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_CORE_HOST_ROUTE_REGISTRY_ROUTE_ENTRY_H_
#define MUMBA_CORE_HOST_ROUTE_REGISTRY_ROUTE_ENTRY_H_

#include <string>
#include <unordered_map>
#include <map>
#include <vector>

#include "base/macros.h"
#include "base/uuid.h"
#include "base/strings/string_util.h"
#include "base/memory/ref_counted_memory.h"
#include "net/rpc/rpc.h"
#include "core/host/serializable.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/mojom/route.mojom.h"
#include "core/host/share/share_observer.h"

namespace host {
class HostRpcService;
class RouteModel;
class RouteRegistry;
class RouteScheme;
class Share;

// envelope for mojom::RoutePtr with some added local-only data 

// A entry might or might not have a torrent associated with it
// in case it doesn't, it's torrent its the same from it's
// 'parent' url collection which is always the 'root' torrent
// of a storage

class RouteEntry : public ShareObserver,
                   public Serializable {
public:
  static char kClassName[];

   RouteEntry():
    service_(nullptr),
    parent_(nullptr),
    share_(nullptr) {
     entry_ = common::mojom::RouteEntry::New();
     extras_ = common::mojom::RouteEntryExtras::New();
     set_uuid(base::UUID::generate());
   }


  RouteEntry(common::mojom::RouteEntryPtr entry_ptr,
             common::mojom::RouteEntryExtrasPtr extras): 
    entry_(std::move(entry_ptr)),
    extras_(std::move(extras)),
    service_(nullptr),
    parent_(nullptr),
    share_(nullptr) {
    load_uuid();
  }
  
  ~RouteEntry() {}

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

  HostRpcService* service() const {
    return service_;
  }

  void set_service(HostRpcService* service) {
    service_ = service;
  }

  void set_extras(common::mojom::RouteEntryExtrasPtr extras) {
    extras_ = std::move(extras);
  }

  // some routes point to user declared RPC methods
  // common routes point to pre-defined entry points
  // this is a way to test for this
  bool is_rpc_method() const {
    return !(rpc_descriptor_.name == "FetchUnary" || 
             rpc_descriptor_.name == "FetchClientStream" || 
             rpc_descriptor_.name == "FetchServerStream" || 
             rpc_descriptor_.name == "FetchBidiStream");
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

  // void set_icon_data(scoped_refptr<base::RefCountedBytes> icon_data) {
  //   entry_->icon_data = icon_data;
  // }

  const net::RpcDescriptor& rpc_descriptor() const {
    return rpc_descriptor_;
  }

  void set_rpc_descriptor(const net::RpcDescriptor& rpc_descriptor) {
    rpc_descriptor_ = rpc_descriptor;
  }

  RouteScheme* parent() const {
    return parent_;
  }

  void set_parent(RouteScheme* parent) {
    parent_ = parent;
  }

  Share* share() const {
    return share_;
  }

  void set_share(Share* share) {
    share_ = share;
  }

  scoped_refptr<net::IOBufferWithSize> Serialize() const override;

  GURL ResolveRpcRoute(const GURL& input_url) const;

private:
  friend class RouteModel;
  friend class RouteRegistry;

  void load_uuid() {
    if (entry_->uuid.empty()) {
      return;
    }
    DCHECK(entry_->uuid.size() == 16);
    uuid_ = base::UUID(reinterpret_cast<const uint8_t*>(entry_->uuid.data()));  
  }

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

  base::UUID uuid_;
  common::mojom::RouteEntryPtr entry_;
  common::mojom::RouteEntryExtrasPtr extras_;
  //scoped_refptr<base::RefCountedBytes> icon_data_;
  HostRpcService* service_;
  net::RpcDescriptor rpc_descriptor_;
  RouteScheme* parent_;
  Share* share_;

  DISALLOW_COPY_AND_ASSIGN(RouteEntry);
};

net::RpcMethodType GetRpcMethodTypeFromEntry(common::mojom::RouteEntryRPCMethodType type);
common::mojom::RouteEntryRPCMethodType GetEntryFromRpcMethodType(net::RpcMethodType type);

}

#endif