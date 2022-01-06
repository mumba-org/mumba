// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/workspace/workspace_storage.h"

#include "base/synchronization/waitable_event.h"
#include "base/files/file_util.h"
#include "base/path_service.h"
#include "core/shared/common/paths.h"
#include "base/threading/thread_restrictions.h"
#include "core/host/host_thread.h"
#include "core/host/workspace/app_storage.h"
#include "core/host/workspace/volume_storage.h"
#include "storage/storage.h"
#include "storage/db/db.h"
#include "storage/storage_manager.h"
#include "storage/torrent_manager.h"

namespace host {

namespace {
  
const char kVOLUME_DIR[] = "volumes";
const char kAPP_DIR[] = "apps";
const char kTMP_DIR[] = "tmp";

}

WorkspaceStorage::WorkspaceStorage(const base::FilePath& root_dir): 
  root_dir_(root_dir),
  tmp_dir_(root_dir.AppendASCII(kTMP_DIR)),
  workspace_disk_name_("workspace"),
  workspace_disk_(nullptr),
  storage_manager_(nullptr),
  volume_storage_(new VolumeStorage(root_dir.AppendASCII(kVOLUME_DIR))),
  app_storage_(new AppStorage(root_dir.AppendASCII(kAPP_DIR))) {

}

WorkspaceStorage::~WorkspaceStorage() {

}

const base::FilePath& WorkspaceStorage::volume_dir() const {
  return volume_storage_->path();
}

const base::FilePath& WorkspaceStorage::app_dir() const {
  return app_storage_->path();
}

bool WorkspaceStorage::Init(storage::StorageManager* storage_manager, base::Callback<void(int64_t)> cb) {
  storage_manager_ = storage_manager;
  if (IsEmpty()) {
    Create(std::move(cb));
  } else {
    Open(std::move(cb));
  }
  return true;
}

void WorkspaceStorage::Shutdown() {
  UnloadCatalogs();
  volume_storage_->Shutdown();
}

void WorkspaceStorage::Create(base::Callback<void(int64_t)> cb) {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));
  base::ScopedAllowBlockingForTesting allow_blocking;
  volume_storage_->Create();
  app_storage_->Create();
  storage_manager_->CreateStorage(workspace_disk_name_, 
    base::Bind(&WorkspaceStorage::OnCreate, base::Unretained(this), base::Passed(std::move(cb))));
  // create tmp directory
  base::CreateDirectory(tmp_dir_);
  // create main directory in cache
#if defined OS_LINUX    
  std::string root_name("mumba");// = root_dir_.BaseName().value();
  base::FilePath cache_path;
  DCHECK(base::PathService::Get(base::DIR_HOME, &cache_path));
  cache_path = cache_path.AppendASCII(".cache").AppendASCII(root_name);
  if (!base::PathExists(cache_path)) {
    DLOG(INFO) << "creating cache dir at: " << cache_path;
    base::CreateDirectory(cache_path);
  }
#endif  
  // if (workspace_disk_ && volume_store_created && app_store_created && tmp_created) {
  //   OnCreate(net::OK);
  // } else {
  //   OnCreate(net::ERR_FAILED);
  // }
}

void WorkspaceStorage::Open(base::Callback<void(int64_t)> cb) {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));
  volume_storage_->Open();
  app_storage_->Open();
  storage_manager_->OpenStorage(workspace_disk_name_,
    base::Bind(&WorkspaceStorage::OnOpen, base::Unretained(this), base::Passed(std::move(cb))));
}

bool WorkspaceStorage::IsEmpty() const {
  base::ScopedAllowBlockingForTesting allow_blocking;
  return !base::DirectoryExists(root_dir_);
}

size_t WorkspaceStorage::total_size() const {
  return static_cast<size_t>(base::ComputeDirectorySize(root_dir_));
}

scoped_refptr<storage::Torrent> WorkspaceStorage::GetTorrent(const base::UUID& uuid) const {
  if (!storage_manager_->torrent_manager()->HasTorrent(uuid)) {
    storage_manager_->OpenTorrent(workspace_disk_name_, uuid);
  }
  return storage_manager_->torrent_manager()->GetTorrent(uuid);
}

scoped_refptr<storage::Torrent> WorkspaceStorage::CreateTorrent(
    storage_proto::InfoKind type,
    const base::UUID& uuid, 
    const std::string& name, 
    std::vector<std::string> keyspaces, 
    base::Callback<void(int64_t)> cb) {

  return storage_manager_->CreateTorrent(workspace_disk_name_, type, uuid, name, std::move(keyspaces), std::move(cb));
}

scoped_refptr<storage::Torrent> WorkspaceStorage::OpenTorrent(const base::UUID& uuid, base::Callback<void(int64_t)> cb) {
  if (!storage_manager_->torrent_manager()->HasTorrent(uuid)) {
     storage_manager_->OpenTorrent(workspace_disk_name_, uuid, std::move(cb));
  }
  return storage_manager_->torrent_manager()->GetTorrent(uuid);
}

scoped_refptr<storage::Torrent> WorkspaceStorage::OpenTorrent(const std::string& name, base::Callback<void(int64_t)> cb) {
  storage_manager_->OpenTorrent(workspace_disk_name_, name, std::move(cb));
  return storage_manager_->GetTorrent(workspace_disk_name_, name);
}

bool WorkspaceStorage::DeleteTorrent(const base::UUID& uuid) {
  return storage_manager_->DeleteTorrent(workspace_disk_name_, uuid);
}

bool WorkspaceStorage::DeleteTorrent(const std::string& name) {
  return storage_manager_->DeleteTorrent(workspace_disk_name_, name);
}

void WorkspaceStorage::OpenDatabaseSync(const base::UUID& uuid) {
  //base::WaitableEvent holder{ base::WaitableEvent::ResetPolicy::AUTOMATIC, base::WaitableEvent::InitialState::NOT_SIGNALED };
  //storage_manager_->OpenTorrent(workspace_disk_, uuid, base::Bind(&WaitTilOpen, base::Unretained(&holder)));
  //holder.Wait();
  //DLOG(INFO) << "WorkspaceStorage::OpenDatabaseSync: done. db opened";
  scoped_refptr<storage::Torrent> torrent = storage_manager_->torrent_manager()->GetTorrent(uuid);
  if (torrent) {
    storage::Database::Open(torrent);
  } else {
    DLOG(INFO) << "WorkspaceStorage::OpenDatabaseSync: didnt found torrent with id " << uuid.to_string();
  }
}

void WorkspaceStorage::LoadCatalogs() {
  
}

void WorkspaceStorage::UnloadCatalogs() {
  
}

void WorkspaceStorage::OnCreate(base::Callback<void(int64_t)> cb, storage::Storage* storage, int status) {
  if (status == net::OK) {
    workspace_disk_ = storage;
    LoadCatalogs();
  }
  if (!cb.is_null())
    std::move(cb).Run(status);
}

void WorkspaceStorage::OnOpen(base::Callback<void(int64_t)> cb, storage::Storage* storage, int status) {
  if (status == net::OK) {
    workspace_disk_ = storage;
    LoadCatalogs();
  }
  if (!cb.is_null())
    std::move(cb).Run(status);
}

}