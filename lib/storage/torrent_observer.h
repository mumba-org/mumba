// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_STORAGE_TORRENT_OBSERVER_H_
#define MUMBA_STORAGE_TORRENT_OBSERVER_H_

#include <unordered_map>
#include <string>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "storage/storage_export.h"

namespace storage {
class Torrent;

class STORAGE_EXPORT TorrentObserver {
public:
  virtual ~TorrentObserver() {}
  virtual void OnDHTAnnounceReply(scoped_refptr<Torrent> torrent, int peers) = 0;
  virtual void OnTorrentMetadataReceived(scoped_refptr<Torrent> torrent) = 0;
  virtual void OnTorrentMetadataError(scoped_refptr<Torrent> torrent, int error) = 0;
  virtual void OnTorrentPieceReadError(scoped_refptr<Torrent> torrent, int piece_offset, int error) = 0;
  virtual void OnTorrentPiecePass(scoped_refptr<Torrent> torrent, int piece_offset) = 0;
  virtual void OnTorrentPieceFailed(scoped_refptr<Torrent> torrent, int piece_offset) = 0;
  virtual void OnTorrentPieceRead(scoped_refptr<Torrent> torrent, int piece, int64_t offset, int64_t size, int64_t block_size, int result) = 0;
  virtual void OnTorrentPieceWrite(scoped_refptr<Torrent> torrent, int piece, int64_t offset, int64_t size, int64_t block_size, int result) = 0;
  virtual void OnTorrentPieceFinished(scoped_refptr<Torrent> torrent, int piece_offset) = 0;
  virtual void OnTorrentPieceHashFailed(scoped_refptr<Torrent> torrent, int piece_offset) = 0;
  virtual void OnTorrentFileCompleted(scoped_refptr<Torrent> torrent, int piece_offset) = 0;
  virtual void OnTorrentFinished(scoped_refptr<Torrent> torrent) = 0;
  virtual void OnTorrentDownloading(scoped_refptr<Torrent> torrent) = 0;
  virtual void OnTorrentCheckingFiles(scoped_refptr<Torrent> torrent) = 0;
  virtual void OnTorrentDownloadingMetadata(scoped_refptr<Torrent> torrent) = 0;
  virtual void OnTorrentSeeding(scoped_refptr<Torrent> torrent) = 0;
  virtual void OnTorrentPaused(scoped_refptr<Torrent> torrent) = 0;
  virtual void OnTorrentResumed(scoped_refptr<Torrent> torrent) = 0;
  virtual void OnTorrentChecked(scoped_refptr<Torrent> torrent) = 0;
  virtual void OnTorrentDeleted(scoped_refptr<Torrent> torrent) = 0;
  virtual void OnTorrentDeletedError(scoped_refptr<Torrent> torrent, int error) = 0;
  virtual void OnTorrentFileRenamed(scoped_refptr<Torrent> torrent, int file_offset, const std::string& name) = 0;
  virtual void OnTorrentFileRenamedError(scoped_refptr<Torrent> torrent, int index, int error) = 0;

  //void OnTorrentBlockFinished(scoped_refptr<Torrent> torrent, lt::tcp::endpoint const& ep, lt::peer_id const& peer_id, int block_num, int piece_offset) = 0;
  
};

}

#endif