// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_STORAGE_TORRENT_CACHE_
#define MUMBA_STORAGE_TORRENT_CACHE_

#include <string>

#include "base/macros.h"
#include "base/uuid.h"
#include "base/memory/ref_counted.h"
#include "storage/storage_export.h"
#include "storage/proto/storage.pb.h"

namespace storage {
class Torrent;
class IOHandler;

// TODO: now that we have this, we can control the registry
//       database through here, and leave it to the torrent manager
//       instead of the StorageBackend
class STORAGE_EXPORT TorrentCache {
public:
  virtual ~TorrentCache() {}
  virtual scoped_refptr<Torrent> NewTorrent(IOHandler* io_handler, const base::UUID& id, bool is_root = false) = 0;
  virtual scoped_refptr<Torrent> NewTorrent(IOHandler* io_handler, std::unique_ptr<storage_proto::Info> info, bool is_root) = 0;
  virtual scoped_refptr<Torrent> GetTorrent(int index) const = 0;
  virtual scoped_refptr<Torrent> GetTorrent(const base::UUID& id) const = 0;
  virtual void AddTorrent(int index, scoped_refptr<Torrent> torrent) = 0;
  virtual void RemoveTorrent(int index) = 0;
  virtual size_t TorrentCount() const = 0;
  virtual bool HasTorrent(int index) const = 0;
  virtual bool HasTorrent(const base::UUID& id) const = 0;
  virtual bool AddTorrentToSessionOrUpdate(const scoped_refptr<Torrent>& torrent) = 0;
};

}

#endif