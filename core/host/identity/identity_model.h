// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_IDENTITY_IDENTITY_MODEL_H_
#define MUMBA_HOST_IDENTITY_IDENTITY_MODEL_H_

#include <memory>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/uuid.h"
#include "net/base/io_buffer.h"
#include "core/host/database_policy.h"

namespace host {
class Identity;
class ShareDatabase;

class IdentityModel : public DatabasePolicyObserver {
public:
  IdentityModel(scoped_refptr<ShareDatabase> db, DatabasePolicy policy);
  ~IdentityModel();

  const std::vector<Identity *>& identities() const {
    return identities_;
  }

  std::vector<Identity *>& identities() {
    return identities_;
  }

  void Load(base::Callback<void(int, int)> cb);
  bool IdentityExists(Identity* identity) const;
  Identity* GetIdentityById(const base::UUID& id);
  void InsertIdentity(const base::UUID& id, Identity* identity, bool persist = true);
  void RemoveIdentity(const base::UUID& id);
 
  void Close();

private:
  
  void InsertIdentityInternal(const base::UUID& id, Identity* identity, bool persist);
  void RemoveIdentityInternal(const base::UUID& id);

  void InsertIdentityToDB(const base::UUID& id, Identity* identity);
  void RemoveIdentityFromDB(Identity* identity);

  void AddToCache(const base::UUID& id, Identity* identity);
  void RemoveFromCache(const base::UUID& id, bool should_delete = true);
  void RemoveFromCache(Identity* identity, bool should_delete = true);

  void LoadIdentitiesFromDB(base::Callback<void(int, int)> cb);

  void OnInsertReply(bool result);
  void OnRemoveReply(bool result);
  void MaybeOpen();
  void MaybeClose();

  void OnDatabasePolicyChanged(DatabasePolicy new_policy) override;

  DatabasePolicy policy_;
  scoped_refptr<ShareDatabase> db_;
  
  std::vector<Identity *> identities_;

private:

 DISALLOW_COPY_AND_ASSIGN(IdentityModel);
};

}

#endif