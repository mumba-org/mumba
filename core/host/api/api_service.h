// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_API_API_SERVICE_H_
#define MUMBA_HOST_API_API_SERVICE_H_

#include <string>

#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "base/uuid.h"
#include "base/synchronization/lock.h"
#include "core/host/share/share_observer.h"

namespace host {
class APINode;
class Share;

// wraps a RPC Service and a Share together
// so that remote share services are available
// to be called as they were local    
class APIService : public ShareObserver {
public:
  APIService(Share* share, const std::string& id);
  ~APIService();  

  Share* share() const {
    return share_;
  }

  const std::string& id() const {
    return id_;
  }

  void AddNode(APINode* node);
  void RemoveNode(APINode* node);

private:
  
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

  Share* share_;

  std::string id_;
  
  base::Lock nodes_lock_;
  std::vector<APINode*> nodes_;
  
  DISALLOW_COPY_AND_ASSIGN(APIService);
};

}

#endif