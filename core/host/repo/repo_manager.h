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
#include "third_party/protobuf/src/google/protobuf/descriptor.h"

namespace host {
class RepoModel;
class Repo;
class ShareDatabase;

class RepoManager {
public:
  class Observer {
  public:
    virtual ~Observer(){}
    virtual void OnReposLoad(int r, int count) {}
    virtual void OnRepoAdded(Repo* repo) {}
    virtual void OnRepoRemoved(Repo* repo) {}
  };
  RepoManager();
  ~RepoManager();

  RepoModel* model() const {
    return repos_.get();
  }

  void Init(scoped_refptr<ShareDatabase> db, DatabasePolicy policy);
  void Shutdown();

  void InsertRepo(std::unique_ptr<Repo> repo, bool persist = true);
  void RemoveRepo(Repo* repo);
  void RemoveRepo(const base::UUID& uuid);

  void AddObserver(Observer* observer);
  void RemoveObserver(Observer* observer);

private:

  void InitImpl();
  void ShutdownImpl();

  void OnLoad(int r, int count);

  void NotifyRepoAdded(Repo* repo);
  void NotifyRepoRemoved(Repo* repo);
  void NotifyReposLoad(int r, int count);

  std::unique_ptr<RepoModel> repos_;
  std::vector<Observer*> observers_;

  base::WeakPtrFactory<RepoManager> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(RepoManager);
};

}

#endif