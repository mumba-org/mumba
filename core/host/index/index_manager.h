// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_INDEX_INDEX_MANAGER_H_
#define MUMBA_HOST_INDEX_INDEX_MANAGER_H_

#include "base/macros.h"

namespace host {
class Index;
/*
 * The index manager
 */
class IndexManager {
public:
  struct CreateOptions {};
  IndexManager();
  ~IndexManager();

  Index* CreateIndex(const std::string& name, const CreateOptions& options);
  void DestroyIndex(const std::string& name);
  void DestroyIndex(const base::UUID& uuid);

private:

 DISALLOW_COPY_AND_ASSIGN(IndexManager);
};

}

#endif