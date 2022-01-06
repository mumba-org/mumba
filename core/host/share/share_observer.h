// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_SHARE_SHARE_OBSERVER_H_
#define MUMBA_HOST_SHARE_SHARE_OBSERVER_H_

#include <string>

#include "base/macros.h"

namespace host {
class Share;

class ShareObserver {
public:
  virtual ~ShareObserver() {}
  virtual void OnDHTAnnounceReply(Share* share, int peers) = 0;
  virtual void OnShareMetadataReceived(Share* share) = 0;
  virtual void OnShareMetadataError(Share* share, int error) = 0;
  virtual void OnSharePieceReadError(Share* share, int piece_offset, int error) = 0;
  virtual void OnSharePiecePass(Share* share, int piece_offset) = 0;
  virtual void OnSharePieceFailed(Share* share, int piece_offset) = 0;
  virtual void OnSharePieceRead(Share* share, int piece, int64_t offset, int64_t size, int64_t block_size, int result) = 0;
  virtual void OnSharePieceWrite(Share* share, int piece, int64_t offset, int64_t size, int64_t block_size, int result) = 0;
  virtual void OnSharePieceFinished(Share* share, int piece_offset) = 0;
  virtual void OnSharePieceHashFailed(Share* share, int piece_offset) = 0;
  virtual void OnShareFileCompleted(Share* share, int piece_offset) = 0;
  virtual void OnShareFinished(Share* share) = 0;
  virtual void OnShareDownloading(Share* share) = 0;
  virtual void OnShareCheckingFiles(Share* share) = 0;
  virtual void OnShareDownloadingMetadata(Share* share) = 0;
  virtual void OnShareSeeding(Share* share) = 0;
  virtual void OnSharePaused(Share* share) = 0;
  virtual void OnShareResumed(Share* share) = 0;
  virtual void OnShareChecked(Share* share) = 0;
  virtual void OnShareDeleted(Share* share) = 0;
  virtual void OnShareDeletedError(Share* share, int error) = 0;
  virtual void OnShareFileRenamed(Share* share, int file_offset, const std::string& name) = 0;
  virtual void OnShareFileRenamedError(Share* share, int index, int error) = 0;
};

}

#endif
