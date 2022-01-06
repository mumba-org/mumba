// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/repo/repo_index.h"

namespace host {

RepoIndex::RepoIndex(RepoManager* manager):
 manager_(manager),
 state_(RepoIndexState::kINVALID) {

}

RepoIndex::~RepoIndex() {
 manager_ = nullptr;
}

void RepoIndex::Init() {

}

void RepoIndex::Shutdown() {

}

}
