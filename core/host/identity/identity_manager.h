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
#include "core/host/identity/identity.h"
#include "core/host/identity/identity_model.h"
#include "core/host/data/resource.h"
#include "third_party/protobuf/src/google/protobuf/descriptor.h"

namespace host {
class ShareDatabase;
class Workspace;

class IdentityManager : public ResourceManager {
public:
  class Observer {
  public:
    virtual ~Observer(){}
    virtual void OnIdentitiesLoad(int r, int count) {}
    virtual void OnIdentityAdded(Identity* id) {}
    virtual void OnIdentityRemoved(Identity* id) {}
  };
  IdentityManager(scoped_refptr<Workspace> workspace);
  ~IdentityManager() override;

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

  // ResourceManager 
  bool HaveResource(const base::UUID& id) override {
    return identities()->IdentityExists(id);
  }

  bool HaveResource(const std::string& name) override {
    return identities()->IdentityExists(name);
  }

  Resource* GetResource(const base::UUID& id) override {
    return identities()->GetIdentityById(id);
  }

  Resource* GetResource(const std::string& name) override {
    return identities()->GetIdentityByName(name);
  }

  const google::protobuf::Descriptor* resource_descriptor() override;
  std::string resource_classname() const override;

private:
  void InitImpl();
  void ShutdownImpl();

  void OnLoad(int r, int count);

  void NotifyIdentityAdded(Identity* id);
  void NotifyIdentityRemoved(Identity* id);
  void NotifyIdentitiesLoad(int r, int count);

  scoped_refptr<Workspace> workspace_;
  std::unique_ptr<IdentityModel> identities_;
  std::vector<Observer*> observers_;
  base::WeakPtrFactory<IdentityManager> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(IdentityManager);
};

}

#endif
