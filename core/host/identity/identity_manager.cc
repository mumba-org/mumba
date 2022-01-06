// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/identity/identity_manager.h"

#include "base/path_service.h"
#include "base/base_paths.h"
#include "base/files/file_util.h"
#include "base/task_scheduler/post_task.h"
#include "core/shared/common/paths.h"
#include "core/host/host_thread.h"
#include "core/host/identity/identity.h"
#include "core/host/identity/identity_model.h"
#include "core/host/share/share_database.h"
#include "core/host/workspace/workspace.h"
#include "storage/torrent.h"

namespace host {

IdentityManager::IdentityManager(): weak_factory_(this) {
  
}

IdentityManager::~IdentityManager() {

}

void IdentityManager::Init(scoped_refptr<ShareDatabase> db, DatabasePolicy policy) {
  identities_ = std::make_unique<IdentityModel>(db, policy);
  // base::PostTaskWithTraits(
  //  FROM_HERE,
  //  { base::MayBlock(),
  //    base::WithBaseSyncPrimitives(),
  //    base::TaskPriority::USER_BLOCKING},
  //  base::Bind(
  //    &IdentityManager::InitImpl,
  //      weak_factory_.GetWeakPtr()));
  InitImpl();
}

void IdentityManager::Shutdown() {
  //base::PostTaskWithTraits(
  // FROM_HERE,
  // { base::MayBlock(),
  //   base::WithBaseSyncPrimitives(),
  //   base::TaskPriority::USER_BLOCKING},
  // base::Bind(
  //   &IdentityManager::ShutdownImpl,
  //     weak_factory_.GetWeakPtr()));
  ShutdownImpl();
}

void IdentityManager::InitImpl() {
  identities_->Load(base::Bind(&IdentityManager::OnLoad, base::Unretained(this)));
}

void IdentityManager::ShutdownImpl() {
  //identities_->Close();
  identities_.reset();
}

void IdentityManager::InsertIdentity(std::unique_ptr<Identity> identity, bool persist) {
  Identity* reference = identity.get();
  identities_->InsertIdentity(identity->id(), identity.release(), persist);
  NotifyIdentityAdded(reference);
}

void IdentityManager::RemoveIdentity(Identity* identity) {
  NotifyIdentityRemoved(identity);
  identities_->RemoveIdentity(identity->id());
}

void IdentityManager::RemoveIdentity(const base::UUID& uuid) {
  Identity* identity = identities_->GetIdentityById(uuid);
  if (identity) {
    NotifyIdentityRemoved(identity);
    identities_->RemoveIdentity(uuid);
  }
}

void IdentityManager::AddObserver(Observer* observer) {
  observers_.push_back(observer);
}

void IdentityManager::RemoveObserver(Observer* observer) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    if (observer == *it) {
      observers_.erase(it);
      return;
    }
  }
}

void IdentityManager::OnLoad(int r, int count) {
  NotifyIdentitiesLoad(r, count);
}

void IdentityManager::NotifyIdentityAdded(Identity* id) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    Observer* observer = *it;
    observer->OnIdentityAdded(id);
  }
}

void IdentityManager::NotifyIdentityRemoved(Identity* id) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    Observer* observer = *it;
    observer->OnIdentityRemoved(id);
  }
}

void IdentityManager::NotifyIdentitiesLoad(int r, int count) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    Observer* observer = *it;
    observer->OnIdentitiesLoad(r, count);
  }
}

}