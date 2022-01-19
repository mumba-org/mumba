// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_REPO_REPO_MANAGER_OBSERVER_H_
#define MUMBA_HOST_REPO_REPO_MANAGER_OBSERVER_H_

namespace host {

class RepoManagerObserver {
public:
  virtual ~RepoManagerObserver(){}
  virtual void OnReposLoad(int result_code, int count) {}
  virtual void OnRepoAdded(Repo* repo) {}
  virtual void OnRepoRemoved(Repo* repo) {}
};

}

#endif