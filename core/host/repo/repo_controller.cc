// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/repo/repo_controller.h"

#include "core/host/repo/repo_manager.h"
#include "core/host/repo/repo_model.h"

namespace host {

RepoController::RepoController(RepoManager* manager):
  manager_(manager) {

}

RepoController::~RepoController() {
  manager_ = nullptr;
}

void RepoController::AddRepo(const std::string& address) {

}

void RepoController::RemoveRepo(const std::string& address) {

}

void RepoController::RemoveRepo(const base::UUID& uuid) {

}

void RepoController::LookupRepoByAddress(const std::string& address) {

}

void RepoController::LookupRepoByName(const std::string& name) {

}

void RepoController::LookupRepoByUUID(const base::UUID& id) {

}

bool RepoController::HaveRepoByAddress(const std::string& address) {
  return false;
}

bool RepoController::HaveRepoByName(const std::string& name) {
  return false;
}

bool RepoController::HaveRepoByUUID(const base::UUID& id) {
  return false;
}

const std::vector<std::unique_ptr<Repo>>& RepoController::ListRepos() {
  return manager_->model()->repos();
}

uint32_t RepoController::CountRepos() {
  return 0;
}

}
