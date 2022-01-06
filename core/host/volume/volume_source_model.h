// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_CONTAINER_SOURCE_MODEL_H_
#define MUMBA_HOST_CONTAINER_SOURCE_MODEL_H_

#include <vector>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/uuid.h"
#include "core/host/database_policy.h"

namespace host {
class VolumeSource;
class ShareDatabase;

class VolumeSourceModel : public DatabasePolicyObserver {
public:
  VolumeSourceModel(scoped_refptr<ShareDatabase> db, DatabasePolicy policy);
  ~VolumeSourceModel();

  void Load();

  bool VolumeSourceExists(VolumeSource* source) const;
  void InsertVolumeSource(const base::UUID& id, VolumeSource* source);
  void RemoveVolumeSource(const base::UUID& id);
 
private:
  void InsertVolumeSourceInternal(const base::UUID& id, VolumeSource* source);
  void RemoveVolumeSourceInternal(const base::UUID& id);

  void InsertVolumeSourceToDB(const base::UUID& id, VolumeSource* source);
  void RemoveVolumeSourceFromDB(VolumeSource* source);

  VolumeSource* GetVolumeSourceById(const base::UUID& id);
  void AddToCache(const base::UUID& id, VolumeSource* source);
  void RemoveFromCache(const base::UUID& id, bool should_delete = true);
  void RemoveFromCache(VolumeSource* source, bool should_delete = true);

  void LoadVolumeSourcesFromDB();

  void OnInsertReply(bool result);
  void OnRemoveReply(bool result);
  void MaybeOpen();
  void MaybeClose();

  void OnDatabasePolicyChanged(DatabasePolicy new_policy) override;

  DatabasePolicy policy_;
  scoped_refptr<ShareDatabase> db_;

  std::vector<VolumeSource *> sources_;

  DISALLOW_COPY_AND_ASSIGN(VolumeSourceModel);
};


}

#endif