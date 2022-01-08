// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/route/route_scheme.h"

#include "core/host/route/route_entry.h"
//#include "core/host/route/route_handler.h"
#include "core/host/route/route_registry.h"
#include "core/host/share/share.h"

namespace host {

RouteScheme::RouteScheme(RouteRegistry* registry): 
  registry_(registry),
  service_(nullptr),
  share_(nullptr),
  domain_(nullptr) {

  entry_ = common::mojom::RouteEntry::New();
  extras_ = common::mojom::RouteEntryExtras::New();
  set_uuid(base::UUID::generate());  

  registry_->AddObserver(this);
}

RouteScheme::RouteScheme(RouteRegistry* registry,
                         common::mojom::RouteEntryPtr entry_ptr,
                         common::mojom::RouteEntryExtrasPtr extras): 
  registry_(registry),
  service_(nullptr),
  share_(nullptr),
  domain_(nullptr),
  entry_(std::move(entry_ptr)),
  extras_(std::move(extras)) {
  
  load_uuid();

  registry_->AddObserver(this);
}

RouteScheme::~RouteScheme() {
  if (share_) {
    share_->RemoveObserver(this);
  }
  registry_->RemoveObserver(this);
}

void RouteScheme::set_share(Share* share) {
  if (share_) {
    share_->RemoveObserver(this);
  }
  share_ = share;
  if (share_) {
    share_->AddObserver(this);
  }
}

// void RouteScheme::AddPeer(std::unique_ptr<RoutePeer> peer) {
//   peers_.push_back(std::move(peer));
// }

// void RouteScheme::RemovePeer(RoutePeer* peer) {
//   for (auto it = peers_.begin(); it != peers_.end(); ++it) {
//     if (it->get() == peer) {
//       peers_.erase(it);
//       return;
//     }
//   }
// }

// void RouteScheme::AddHandler(RouteHandler* handler) {
//   handler->set_collection(this);
//   handler->set_service(service());
//   handlers_.push_back(handler);
// }

// void RouteScheme::RemoveHandler(const std::string& handler_name) {
//   for (auto it = handlers_.begin(); it != handlers_.end(); ++it) {
//     if ((*it)->name() == handler_name) {
//       handlers_.erase(it);
//       return;
//     }
//   }
// }

void RouteScheme::AddEntry(RouteEntry* entry) {
  entries_.push_back(entry);
  entry->set_parent(this);
}

void RouteScheme::RemoveEntry(RouteEntry* entry) {
  for (auto it = entries_.begin(); it != entries_.end(); ++it) {
    if ((*it) == entry) {
      entries_.erase(it);
      entry->set_parent(nullptr);
      return;
    }
  }
}

void RouteScheme::OnRouteAdded(RouteEntry* entry) {
  if (entry->url().scheme() == name_) {
    AddEntry(entry);
  }
}

void RouteScheme::OnRouteRemoved(RouteEntry* entry) {
  if (entry->url().scheme() == name_) {
    RemoveEntry(entry);
  }
}

scoped_refptr<net::IOBufferWithSize> RouteScheme::Serialize() const {
  // FIXME: implement
  return scoped_refptr<net::IOBufferWithSize>();
}

void RouteScheme::OnDHTAnnounceReply(Share* share, int peers) {
  //DLOG(INFO) << "RouteScheme::OnDHTAnnounceReply: " << name_ << " peers: " << peers;
}

void RouteScheme::OnShareMetadataReceived(Share* share) {
  //DLOG(INFO) << "RouteScheme::OnShareMetadataReceived: " << name_;
}

void RouteScheme::OnShareMetadataError(Share* share, int error) {
  //DLOG(INFO) << "RouteScheme::OnShareMetadataError: " << name_;
}

void RouteScheme::OnSharePieceReadError(Share* share, int piece_offset, int error) {
  //DLOG(INFO) << "RouteScheme::OnSharePieceReadError: " << name_;
}

void RouteScheme::OnSharePiecePass(Share* share, int piece_offset) {
  //DLOG(INFO) << "RouteScheme::OnSharePiecePass: " << name_;
}

void RouteScheme::OnSharePieceFailed(Share* share, int piece_offset) {
  //DLOG(INFO) << "RouteScheme::OnSharePieceFailed: " << name_;
}

void RouteScheme::OnSharePieceRead(Share* share, int piece, int64_t offset, int64_t size, int64_t block_size, int result) {
  //DLOG(INFO) << "RouteScheme::OnSharePieceRead: " << name_;
}

void RouteScheme::OnSharePieceWrite(Share* share, int piece, int64_t offset, int64_t size, int64_t block_size, int result) {
  //DLOG(INFO) << "RouteScheme::OnSharePieceWrite: " << name_;
}

void RouteScheme::OnSharePieceFinished(Share* share, int piece_offset) {
  //DLOG(INFO) << "RouteScheme::OnSharePieceFinished: " << name_;
}

void RouteScheme::OnSharePieceHashFailed(Share* share, int piece_offset) {
  //DLOG(INFO) << "RouteScheme::OnSharePieceHashFailed: " << name_;
}

void RouteScheme::OnShareFileCompleted(Share* share, int piece_offset) {
  //DLOG(INFO) << "RouteScheme::OnShareFileCompleted: " << name_;
}

void RouteScheme::OnShareFinished(Share* share) {
  //DLOG(INFO) << "RouteScheme::OnShareFinished: " << name_;
}

void RouteScheme::OnShareDownloading(Share* share) {
  //DLOG(INFO) << "RouteScheme::OnShareDownloading: " << name_;
}

void RouteScheme::OnShareCheckingFiles(Share* share) {
  //DLOG(INFO) << "RouteScheme::OnShareCheckingFiles: " << name_;
}

void RouteScheme::OnShareDownloadingMetadata(Share* share) {
  //DLOG(INFO) << "RouteScheme::OnShareDownloadingMetadata: " << name_;
}

void RouteScheme::OnShareSeeding(Share* share) {
  //DLOG(INFO) << "RouteScheme::OnShareSeeding: " << name_;
}

void RouteScheme::OnSharePaused(Share* share) {
  //DLOG(INFO) << "RouteScheme::OnSharePaused: " << name_;
}

void RouteScheme::OnShareResumed(Share* share) {
  //DLOG(INFO) << "RouteScheme::OnShareResumed: " << name_;
}

void RouteScheme::OnShareChecked(Share* share) {
  //DLOG(INFO) << "RouteScheme::OnShareChecked: " << name_;
}

void RouteScheme::OnShareDeleted(Share* share) {
  //DLOG(INFO) << "RouteScheme::OnShareDeleted: " << name_;
}

void RouteScheme::OnShareDeletedError(Share* share, int error) {
  //DLOG(INFO) << "RouteScheme::OnShareDeletedError: " << name_;
}

void RouteScheme::OnShareFileRenamed(Share* share, int file_offset, const std::string& name) {
  //DLOG(INFO) << "RouteScheme::OnShareFileRenamed: " << name_; 
}

void RouteScheme::OnShareFileRenamedError(Share* share, int index, int error) {
  //DLOG(INFO) << "RouteScheme::OnShareFileRenamedError: " << name_; 
}

}
