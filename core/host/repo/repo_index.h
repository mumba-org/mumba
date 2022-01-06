// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_REPO_REPO_INDEX_H_
#define MUMBA_HOST_REPO_REPO_INDEX_H_

#include <memory>

#include "base/macros.h"

namespace host {
class RepoManager;

// The idea of repo index is to work as a catalog and a nameserver
// for the applications

// The idea is to have a DHT address of its own to keep up
// the database with the application entries

enum class RepoIndexState {
  kINVALID,
  kUNAVAILABLE,
  kSYNCING_METADATA,
  kSYNCING,
  kAVAILABLE,
};

class RepoIndex {
public:
  RepoIndex(RepoManager* manager);
  ~RepoIndex();

  void Init();
  void Shutdown();

  RepoIndexState state() const {
    return state_;
  }

private:
  RepoManager* manager_;
  RepoIndexState state_;

  DISALLOW_COPY_AND_ASSIGN(RepoIndex);
};

}

#endif