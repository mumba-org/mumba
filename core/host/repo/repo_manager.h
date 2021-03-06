// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_REPO_REPO_MANAGER_H_
#define MUMBA_HOST_REPO_REPO_MANAGER_H_

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
#include "core/host/data/resource.h"
#include "core/host/repo/repo.h"
#include "third_party/protobuf/src/google/protobuf/descriptor.h"

namespace host {
class RepoModel;
class ShareDatabase;
class RepoManagerObserver;
class Workspace;

class RepoManager : public ResourceManager {
public:
  RepoManager(scoped_refptr<Workspace> workspace);
  ~RepoManager() override;

  RepoModel* model() const {
    return repos_.get();
  }

  void Init(scoped_refptr<ShareDatabase> db, DatabasePolicy policy);
  void Shutdown();

  bool RepoExists(Repo* repo) const;
  bool RepoExistsById(const base::UUID& id) const;
  bool RepoExistsByName(const std::string& name) const;
  bool RepoExistsByAddress(const std::string& address) const;
  Repo* GetRepoById(const base::UUID& id);
  Repo* GetRepoByName(const std::string& name);
  Repo* GetRepoByAddress(const std::string& address);
  void InsertRepo(std::unique_ptr<Repo> repo, bool persist = true);
  bool RemoveRepo(Repo* repo);
  bool RemoveRepo(const base::UUID& uuid);
  bool RemoveRepoByAddress(const std::string& address);
  std::vector<Repo*> GetRepoList() const;
  size_t GetRepoCount() const;
  
  void AddObserver(RepoManagerObserver* observer);
  void RemoveObserver(RepoManagerObserver* observer);

  // ResourceManager 
  bool HaveResource(const base::UUID& id) override {
    return RepoExistsById(id);
  }

  bool HaveResource(const std::string& name) override {
    return RepoExistsByName(name);
  }

  Resource* GetResource(const base::UUID& id) override {
    return GetRepoById(id);
  }

  Resource* GetResource(const std::string& name) override {
    return GetRepoByName(name);
  }

  const google::protobuf::Descriptor* resource_descriptor() override;
  std::string resource_classname() const override;

private:

  void InitImpl();
  void ShutdownImpl();

  void OnLoad(int r, int count);

  void NotifyRepoAdded(Repo* repo);
  void NotifyRepoRemoved(Repo* repo);
  void NotifyReposLoad(int r, int count);

  scoped_refptr<Workspace> workspace_;
  std::unique_ptr<RepoModel> repos_;
  std::vector<RepoManagerObserver*> observers_;

  base::WeakPtrFactory<RepoManager> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(RepoManager);
};

}

#endif