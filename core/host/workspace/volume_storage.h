// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_WORKSPACE_VOLUME_STORAGE_H_
#define MUMBA_HOST_WORKSPACE_VOLUME_STORAGE_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"
#include "base/callback.h"
#include "base/memory/ref_counted.h"
#include "base/files/file_path.h"
#include "base/strings/string_piece.h"
#include "core/host/workspace/storage_layer.h"

namespace storage {
class Torrent;
class Storage;
class StorageManager;
}

namespace host {
class Volume;
class VolumeStorage : public StorageLayer {
public:
  VolumeStorage(const base::FilePath& path);
  ~VolumeStorage() override;

  storage::StorageManager* storage_manager() const {
  	return storage_manager_.get();
  }

  void Shutdown();

  // StorageLayer
  const base::FilePath& path() const override;
  size_t total_size() override;
  bool Create() override;
  bool Open() override;
  bool IsEmpty() const override;
  bool Empty() override;

  bool VolumeExists(const base::UUID& id);
  void PutVolume(Volume* container, bool sync = false);
  void DropVolume(const std::string& name, bool sync = false);
  scoped_refptr<storage::Torrent> OpenTorrent(
  	const std::string& container_name, 
  	const std::string& torrent_name, 
  	base::Callback<void(int64_t)> cb = base::Callback<void(int64_t)>());

  storage::Storage* GetStorage(const std::string& name);
  
private:

  void OnStorageManagerInit(int result);

  void PutVolumeImpl(Volume* container);
  void DropVolumeImpl(const std::string& name);
  
  base::FilePath path_;

  std::unique_ptr<storage::StorageManager> storage_manager_;
  
  DISALLOW_COPY_AND_ASSIGN(VolumeStorage);
};

}

#endif
