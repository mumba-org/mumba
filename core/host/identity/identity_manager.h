// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_IDENTITY_IDENTITY_MANAGER_H_
#define MUMBA_HOST_IDENTITY_IDENTITY_MANAGER_H_

#include <memory>

#include "base/macros.h"
#include "base/synchronization/lock.h"
#include "base/memory/ref_counted.h"
#include "base/files/file_path.h"
#include "base/atomic_sequence_num.h"
#include "base/memory/weak_ptr.h"
#include "base/single_thread_task_runner.h"
#include "base/uuid.h"
#include "core/host/database_policy.h"
#include "third_party/protobuf/src/google/protobuf/descriptor.h"

namespace host {
class IdentityModel;
class Identity;
class ShareDatabase;

class IdentityManager {
public:
  class Observer {
  public:
    virtual ~Observer(){}
    virtual void OnIdentitiesLoad(int r, int count) {}
    virtual void OnIdentityAdded(Identity* id) {}
    virtual void OnIdentityRemoved(Identity* id) {}
  };
  IdentityManager();
  ~IdentityManager();

  IdentityModel* identities() const {
    return identities_.get();
  }

  void Init(scoped_refptr<ShareDatabase> db, DatabasePolicy policy);
  void Shutdown();

  void InsertIdentity(std::unique_ptr<Identity> identity, bool persist = true);
  void RemoveIdentity(Identity* identity);
  void RemoveIdentity(const base::UUID& uuid);

  void AddObserver(Observer* observer);
  void RemoveObserver(Observer* observer);

private:
  void InitImpl();
  void ShutdownImpl();

  void OnLoad(int r, int count);

  void NotifyIdentityAdded(Identity* id);
  void NotifyIdentityRemoved(Identity* id);
  void NotifyIdentitiesLoad(int r, int count);

  std::unique_ptr<IdentityModel> identities_;
  std::vector<Observer*> observers_;
  base::WeakPtrFactory<IdentityManager> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(IdentityManager);
};

}

#endif