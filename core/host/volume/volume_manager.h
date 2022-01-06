// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_CONTAINER_CONTAINER_MANAGER_H_
#define MUMBA_HOST_CONTAINER_CONTAINER_MANAGER_H_

#include <memory>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/files/file_path.h"
#include "base/atomic_sequence_num.h"
#include "base/memory/weak_ptr.h"
#include "base/single_thread_task_runner.h"
#include "base/uuid.h"
#include "core/host/database_policy.h"

namespace storage {
class Storage;
class StorageManager;
}

namespace host {
class VolumeStorage;
class VolumeSourceModel;
class VolumeModel;
class Volume;
class VolumeSource;
class ShareDatabase;
class BundleManager;
class Bundle;

class VolumeManager {
public:
  class Delegate {
  public:
    virtual ~Delegate() {}
    virtual VolumeStorage* GetVolumeStorage() = 0;
    virtual void OnVolumeManagerInitError() = 0;
    virtual void OnVolumeManagerInitCompleted() = 0;
  };

  class Observer {
  public:
    virtual ~Observer(){}
    virtual void OnVolumesLoad(int r, int count) {}
    virtual void OnVolumeAdded(Volume* volume) {}
    virtual void OnVolumeRemoved(Volume* volume) {}
  };

  VolumeManager(Delegate* delegate);
  ~VolumeManager();

  VolumeModel* volumes() const {
    return volumes_.get();
  }

  VolumeSourceModel* sources() const {
    return sources_.get();
  }

  VolumeStorage* volume_storage();

  void Init(scoped_refptr<ShareDatabase> db, DatabasePolicy policy, storage::StorageManager* storage_manager, BundleManager* bundle_manager);
  void Shutdown();

  // 1 - Add volume 'x.pack'
  //   Manage and control the new volume
  // 2 - Checkout volume
  //   Create a new Domain from the added/managed pack

  // For a full installation, from a given pack to a new shell
  // The add and checkout must be performed in sequence
  // (the install command actually does that)
  void AddVolume(storage::Storage* volume_storage, Bundle* bundle, const base::Callback<void(std::pair<bool, base::UUID>)>& callback);

  bool IsVolumeInstalled(const base::UUID& id);
  
  // add + checkout in one strike
  void InstallVolume(storage::Storage* volume_storage, Bundle* bundle, 
    base::Callback<void(std::pair<bool, Volume*>)> callback);

  void InstallVolumeSync(storage::Storage* volume_storage, Bundle* bundle,
    base::Callback<void(std::pair<bool, Volume*>)> callback);
  
  void InsertVolume(Volume* volume);
  void RemoveVolume(Volume* volume);

  // source
  void InsertVolumeSource(VolumeSource* source);
  void RemoveVolumeSource(VolumeSource* source);

  void AddObserver(Observer* observer);
  void RemoveObserver(Observer* observer);

private:
  
  void OnLoad(int r, int count);

  void NotifyVolumeAdded(Volume* volume);
  void NotifyVolumeRemoved(Volume* volume);
  void NotifyVolumesLoad(int r, int count);

  std::pair<bool, base::UUID> AddVolumeImpl(storage::Storage* volume_storage, Bundle* bundle);
  std::pair<bool, Volume*> InstallVolumeImpl(storage::Storage* volume_storage, Bundle* bundle);

  Delegate* delegate_;
  
  std::unique_ptr<VolumeModel> volumes_;

  std::unique_ptr<VolumeSourceModel> sources_;

  //base::AtomicSequenceNumber volume_idgen_;

  //base::AtomicSequenceNumber source_idgen_;

  //scoped_refptr<base::SingleThreadTaskRunner> background_task_runner_;


  std::vector<Observer *> observers_;

  bool clean_shutdown_;

  base::WeakPtrFactory<VolumeManager> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(VolumeManager);
};
  
}

#endif