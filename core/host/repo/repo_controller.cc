// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/repo/repo_controller.h"

#include "base/base64.h"
#include "base/bind.h"
#include "base/task_scheduler/post_task.h"
#include "net/base/net_errors.h"
#include "core/host/repo/repo_manager.h"
#include "core/host/repo/repo_model.h"
#include "core/host/share/share_controller.h"

namespace host {

RepoController::RepoController(RepoManager* manager, ShareController* share_controller):
  manager_(manager),
  share_controller_(share_controller) {

}

RepoController::~RepoController() {
  manager_ = nullptr;
}

void RepoController::AddRepo(const std::string& base64_address, base::Callback<void(int)> callback) {
  std::string decoded_bytes;
  if (!base::Base64Decode(base64_address, &decoded_bytes)) {
    std::move(callback).Run(net::ERR_FAILED);
    return;
  }
  share_controller_->CloneStorageWithDHTAddress(decoded_bytes, base::Bind(&RepoController::OnStorageCloned,
                                                                          base::Unretained(this),
                                                                          base::Passed(std::move(callback))));
}

bool RepoController::RemoveRepo(const std::string& address) {
  return manager_->RemoveRepoByAddress(address);
}

bool RepoController::RemoveRepo(const base::UUID& uuid) {
  return manager_->RemoveRepo(uuid);
}

Repo* RepoController::LookupRepoByAddress(const std::string& address) {
  return manager_->GetRepoByAddress(address);
}

Repo* RepoController::LookupRepoByName(const std::string& name) {
  return manager_->GetRepoByName(name);
}

Repo* RepoController::LookupRepoByUUID(const base::UUID& id) {
  return manager_->GetRepoById(id);
}

bool RepoController::HaveRepoByAddress(const std::string& address) {
  return manager_->RepoExistsByAddress(address);
}

bool RepoController::HaveRepoByName(const std::string& name) {
  return manager_->RepoExistsByName(name);
}

bool RepoController::HaveRepoByUUID(const base::UUID& id) {
  return manager_->RepoExistsById(id);
}

const std::vector<std::unique_ptr<Repo>>& RepoController::ListRepos() {
  return manager_->model()->repos();
}

uint32_t RepoController::CountRepos() {
  return manager_->GetRepoCount();
}

void RepoController::OnStorageCloned(base::Callback<void(int)> callback, int result) {
  // FIXME: the idea now is to add a Repo Entry before calling the user callback
  std::move(callback).Run(result);
}

}
