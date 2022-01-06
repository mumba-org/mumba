// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_REPO_REPO_CONTROLLER_H_
#define MUMBA_HOST_REPO_REPO_CONTROLLER_H_

#include <memory>
#include <vector>

#include "base/macros.h"
#include "base/uuid.h"

namespace host {
class RepoManager;
class Repo;

class RepoController {
public:
  RepoController(RepoManager* manager);
  ~RepoController();

  void AddRepo(const std::string& address);
  void RemoveRepo(const std::string& address);
  void RemoveRepo(const base::UUID& uuid);
  void LookupRepoByAddress(const std::string& address);
  void LookupRepoByName(const std::string& name);
  void LookupRepoByUUID(const base::UUID& id);
  bool HaveRepoByAddress(const std::string& address);
  bool HaveRepoByName(const std::string& name);
  bool HaveRepoByUUID(const base::UUID& id);
  const std::vector<std::unique_ptr<Repo>>& ListRepos();
  uint32_t CountRepos();

private:
  
  RepoManager* manager_;

  DISALLOW_COPY_AND_ASSIGN(RepoController);
};

}

#endif