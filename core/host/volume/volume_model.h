// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_VOLUME_VOLUME_MODEL_H_
#define MUMBA_HOST_VOLUME_VOLUME_MODEL_H_

#include <vector>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/uuid.h"
#include "core/host/database_policy.h"

namespace host {
class Volume;
class VolumeStorage;
class ShareDatabase;
class BundleManager;

class VolumeModel : public DatabasePolicyObserver {
public:
  VolumeModel(scoped_refptr<ShareDatabase> db, DatabasePolicy policy);
  ~VolumeModel();

  void Load(VolumeStorage* storage, BundleManager* bundle_manager, base::Callback<void(int, int)> cb);

  const std::vector<Volume *>& volumes() const {
    return volumes_;
  }

  std::vector<Volume *>& volumes() {
    return volumes_;
  }

  bool VolumeExists(Volume* volume);
  bool VolumeExists(const base::UUID& id);
  //bool VolumeExists(const std::string& hash, base::UUID* id);
  bool VolumeExists(const std::string& name);
  Volume* GetVolumeById(const base::UUID& id);
  Volume* GetVolumeByName(const std::string& name);
  void InsertVolume(const base::UUID& id, Volume* volume);
  void RemoveVolume(const base::UUID& id);
 
private:

  void InsertVolumeInternal(const base::UUID& id, Volume* volume);
  void RemoveVolumeInternal(const base::UUID& id);

  void InsertVolumeToDB(const base::UUID& id, Volume* volume);
  void RemoveVolumeFromDB(Volume* volume);

  void AddToCache(const base::UUID& id, Volume* volume);
  void RemoveFromCache(const base::UUID& id, bool should_delete = true);
  void RemoveFromCache(Volume* volume, bool should_delete = true);

  void LoadVolumesFromDB(VolumeStorage* storage, BundleManager* bundle_manager, base::Callback<void(int, int)> cb);

  void OnInsertReply(bool result);
  void OnRemoveReply(bool result);
  void MaybeOpen();
  void MaybeClose();

  void OnDatabasePolicyChanged(DatabasePolicy new_policy) override;

  DatabasePolicy policy_;
  scoped_refptr<ShareDatabase> db_;
 
  std::vector<Volume *> volumes_;
  base::Lock lock_;

  DISALLOW_COPY_AND_ASSIGN(VolumeModel);
};


}

#endif