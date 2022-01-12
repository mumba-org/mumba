// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_WORKSPACE_WORKSPACE_STORAGE_H_
#define MUMBA_HOST_WORKSPACE_WORKSPACE_STORAGE_H_

#include <string>
#include <memory>

#include "base/macros.h"
#include "base/uuid.h"
#include "base/callback.h"
#include "base/memory/ref_counted.h"
#include "base/files/file_path.h"
#include "base/strings/string_piece.h"
#include "storage/proto/storage.pb.h"

namespace storage {
class StorageManager;
class Storage;
class Torrent;
}

namespace host {
class VolumeStorage;
class AppStorage;
class BinStorage;
/*
 * Deal with the storage backend of a given Workspace
 */
class WorkspaceStorage {
public:
  WorkspaceStorage(const base::FilePath& root_dir);
  ~WorkspaceStorage();

  const base::FilePath& root_dir() const {
    return root_dir_;
  }
  
  const base::FilePath& volume_dir() const;
  const base::FilePath& app_dir() const;
  const base::FilePath& tmp_dir() const {
    return tmp_dir_;
  }

  const std::string& workspace_disk_name() const {
    return workspace_disk_name_;
  }

  VolumeStorage* volume_storage() const {
    return volume_storage_.get();
  }

  AppStorage* app_storage() const {
    return app_storage_.get();
  }

  BinStorage* bin_storage() const {
    return bin_storage_.get();
  }

  storage::Storage* workspace_disk() const {
    return workspace_disk_;
  }

  size_t total_size() const;

  // generic init. will trigger create of empty
  bool Init(storage::StorageManager* disk_manager, base::Callback<void(int64_t)> cb = base::Callback<void(int64_t)>());
  void Shutdown();
    // to be called in the first run. IsEmpty() must be true
  void Create(base::Callback<void(int64_t)> cb = base::Callback<void(int64_t)>());
  void Open(base::Callback<void(int64_t)> cb = base::Callback<void(int64_t)>());
  bool IsEmpty() const;

  scoped_refptr<storage::Torrent> GetTorrent(const base::UUID& uuid) const;
  scoped_refptr<storage::Torrent> CreateTorrent(storage_proto::InfoKind type, const base::UUID& uuid, const std::string& name, std::vector<std::string> keyspaces = std::vector<std::string>(), base::Callback<void(int64_t)> cb = base::Callback<void(int64_t)>());
  scoped_refptr<storage::Torrent> OpenTorrent(const base::UUID& uuid, base::Callback<void(int64_t)> cb = base::Callback<void(int64_t)>());
  scoped_refptr<storage::Torrent> OpenTorrent(const std::string& name, base::Callback<void(int64_t)> cb = base::Callback<void(int64_t)>());
  bool DeleteTorrent(const base::UUID& uuid);
  bool DeleteTorrent(const std::string& name);
  void OpenDatabaseSync(const base::UUID& uuid);

private:
  void LoadCatalogs();
  void UnloadCatalogs();

  void OnCreate(base::Callback<void(int64_t)> cb, storage::Storage*, int status);
  void OnOpen(base::Callback<void(int64_t)> cb, storage::Storage*, int status);

  base::FilePath root_dir_;
  base::FilePath tmp_dir_;
  std::string workspace_disk_name_;
  storage::Storage* workspace_disk_;
  storage::StorageManager* storage_manager_;
  std::unique_ptr<VolumeStorage> volume_storage_;
  std::unique_ptr<AppStorage> app_storage_;
  std::unique_ptr<BinStorage> bin_storage_;

  DISALLOW_COPY_AND_ASSIGN(WorkspaceStorage);
};

}

#endif