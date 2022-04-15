// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/volume/volume_manager.h"

#include "base/path_service.h"
#include "base/base_paths.h"
#include "base/files/file_util.h"
#include "base/task_scheduler/post_task.h"
#include "core/shared/common/paths.h"
#include "core/host/host_thread.h"
#include "core/host/workspace/volume_storage.h"
#include "core/host/volume/volume_model.h"
#include "core/host/volume/volume.h"
#include "core/host/volume/volume_source_model.h"
#include "core/host/volume/volume_source.h"
#include "core/host/workspace/workspace.h"
#include "core/host/share/share_database.h"
#include "storage/db/db.h"
#include "storage/torrent.h"

namespace host {

// namespace {
//   const char kCONTAINERS_DIR[] = "volumes";
//  }

VolumeManager::VolumeManager(scoped_refptr<Workspace> workspace):
  workspace_(workspace),
  clean_shutdown_(false),
  weak_factory_(this) {

}

VolumeManager::~VolumeManager(){
  volumes_.reset();
  sources_.reset();
}

void VolumeManager::Init(scoped_refptr<ShareDatabase> db, DatabasePolicy policy, storage::StorageManager* storage_manager, BundleManager* bundle_manager) { 
  volumes_.reset(new VolumeModel(db, policy));
  sources_.reset(new VolumeSourceModel(db, policy));
  volumes_->Load(workspace_->GetVolumeStorage(), bundle_manager, base::Bind(&VolumeManager::OnLoad, base::Unretained(this)));

  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&Workspace::OnVolumeManagerInitCompleted, 
      workspace_));

}

void VolumeManager::Shutdown() {
  volumes_.reset();
  sources_.reset();
  
  clean_shutdown_ = true;
}

VolumeStorage* VolumeManager::volume_storage() {
  return workspace_->GetVolumeStorage();
}

void VolumeManager::AddVolume(storage::Storage* volume_storage, Bundle* bundle, const base::Callback<void(std::pair<bool, base::UUID>)>& callback) {
  base::PostTaskWithTraitsAndReplyWithResult(
    FROM_HERE,
    {base::MayBlock(), base::WithBaseSyncPrimitives(), base::TaskPriority::USER_BLOCKING},
    base::Bind(
      &VolumeManager::AddVolumeImpl,
        base::Unretained(this),
        base::Unretained(volume_storage),
        base::Unretained(bundle)),
    base::Bind(callback));
}

void VolumeManager::InstallVolume(storage::Storage* volume_storage, Bundle* bundle, base::Callback<void(std::pair<bool, Volume*>)> callback) {
  base::PostTaskWithTraitsAndReplyWithResult(
    FROM_HERE,
    {base::MayBlock(), base::WithBaseSyncPrimitives(), base::TaskPriority::USER_BLOCKING},
    base::Bind(
      &VolumeManager::InstallVolumeImpl,
        base::Unretained(this),
        base::Unretained(volume_storage),
        base::Unretained(bundle)),
    base::Bind(std::move(callback)));
}

void VolumeManager::InstallVolumeSync(
  storage::Storage* volume_storage,
  Bundle* bundle,
  base::Callback<void(std::pair<bool, Volume*>)> callback) {
  auto pair = InstallVolumeImpl(volume_storage, bundle);
  std::move(callback).Run(std::move(pair));
}

void VolumeManager::InsertVolume(Volume* volume) {
  volumes_->InsertVolume(volume->id(), volume);
  workspace_->GetVolumeStorage()->PutVolume(volume);
}

void VolumeManager::RemoveVolume(Volume* volume) {
  volumes_->RemoveVolume(volume->id());
  workspace_->GetVolumeStorage()->DropVolume(volume->name());
}

  // source
void VolumeManager::InsertVolumeSource(VolumeSource* source) {
  sources_->InsertVolumeSource(source->id(), source);
}

void VolumeManager::RemoveVolumeSource(VolumeSource* source) {
  sources_->RemoveVolumeSource(source->id());
}

bool VolumeManager::IsVolumeInstalled(const base::UUID& id) {
  return volumes_->GetVolumeById(id) != nullptr;
}

std::pair<bool, base::UUID> VolumeManager::AddVolumeImpl(storage::Storage* volume_storage, Bundle* bundle) {
  base::UUID result;
  //Volume* volume = volumes_->GetVolumeById(volume_torrent->id());
  //if (volume) {
  //  LOG(ERROR) << "Dont need to install volume from '" << volume_torrent->id().to_string() << "': Volume already installed.";
  //  return std::make_pair(true, result);
  //}
  std::unique_ptr<Volume> owned_volume = Volume::New(volume_storage, bundle);
  Volume* volume = owned_volume.release();

  volumes_->InsertVolume(volume->id(), volume);
  workspace_->GetVolumeStorage()->PutVolume(volume, true);
  result = volume->id();
  return std::make_pair(true, result);
}

std::pair<bool, Volume*> VolumeManager::InstallVolumeImpl(storage::Storage* volume_storage, Bundle* bundle) {
  Volume* pack = nullptr;
  bool result = true;
  auto pair = AddVolumeImpl(volume_storage, bundle);
  if (!pair.first) {
    return std::make_pair(false, nullptr);
  }
  
  pack = volumes_->GetVolumeById(pair.second);
  if (!pack) {
    result = false;
    LOG(ERROR) << "InstallVolume: really bad.. volume added then checkout " <<
      " but we cant find it in the model";
  }
  return std::make_pair(result, pack);
}

void VolumeManager::AddObserver(Observer* observer) {
  observers_.push_back(observer);
}

void VolumeManager::RemoveObserver(Observer* observer) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    if (observer == *it) {
      observers_.erase(it);
      return;
    }
  }
}

void VolumeManager::OnLoad(int r, int count) {
  NotifyVolumesLoad(r, count);
}

void VolumeManager::NotifyVolumeAdded(Volume* volume) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    Observer* observer = *it;
    observer->OnVolumeAdded(volume);
  }
}

void VolumeManager::NotifyVolumeRemoved(Volume* volume) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    Observer* observer = *it;
    observer->OnVolumeRemoved(volume);
  }
}

void VolumeManager::NotifyVolumesLoad(int r, int count) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    Observer* observer = *it;
    observer->OnVolumesLoad(r, count);
  }
}

const google::protobuf::Descriptor* VolumeManager::resource_descriptor() {
  Schema* schema = workspace_->schema_registry()->GetSchemaByName("objects.proto");
  DCHECK(schema);
  return schema->GetMessageDescriptorNamed("Volume");
}

std::string VolumeManager::resource_classname() const {
  return Volume::kClassName;
}

}
