// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/api/api_service.h"

#include "core/host/share/share.h"
#include "core/host/api/api_node.h"

namespace host {

APIService::APIService(Share* share, const std::string& id): 
  share_(share),
  id_(id) {
  share_->AddObserver(this);
}

APIService::~APIService() {
  share_->RemoveObserver(this);  
}

void APIService::AddNode(APINode* node) {
  base::AutoLock lock(nodes_lock_);
  nodes_.push_back(node);
}

void APIService::RemoveNode(APINode* node) {
  base::AutoLock lock(nodes_lock_);
  for (auto it = nodes_.begin(); it != nodes_.end(); ++it) {
    if (node == *it) {
       nodes_.erase(it);
       return; 
    }
  }
}

void APIService::OnDHTAnnounceReply(Share* share, int peers) {

}

void APIService::OnShareMetadataReceived(Share* share) {

}

void APIService::OnShareMetadataError(Share* share, int error) {

}

void APIService::OnSharePieceReadError(Share* share, int piece_offset, int error) {

}

void APIService::OnSharePiecePass(Share* share, int piece_offset) {

}

void APIService::OnSharePieceFailed(Share* share, int piece_offset) {

}

void APIService::OnSharePieceRead(Share* share, int piece, int64_t offset, int64_t size, int64_t block_size, int result) {

}

void APIService::OnSharePieceWrite(Share* share, int piece, int64_t offset, int64_t size, int64_t block_size, int result) {

}

void APIService::OnSharePieceFinished(Share* share, int piece_offset) {

}

void APIService::OnSharePieceHashFailed(Share* share, int piece_offset) {

}

void APIService::OnShareFileCompleted(Share* share, int piece_offset) {

}

void APIService::OnShareFinished(Share* share) {

}

void APIService::OnShareDownloading(Share* share) {

}

void APIService::OnShareCheckingFiles(Share* share) {

}

void APIService::OnShareDownloadingMetadata(Share* share) {

}

void APIService::OnShareSeeding(Share* share) {

}

void APIService::OnSharePaused(Share* share) {

}

void APIService::OnShareResumed(Share* share) {

}

void APIService::OnShareChecked(Share* share) {

}

void APIService::OnShareDeleted(Share* share) {

}

void APIService::OnShareDeletedError(Share* share, int error) {

}

void APIService::OnShareFileRenamed(Share* share, int file_offset, const std::string& name) {

}

void APIService::OnShareFileRenamedError(Share* share, int index, int error) {

}


}
