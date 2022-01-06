// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_INDEX_INDEX_CONTROLLER_H_
#define MUMBA_HOST_INDEX_INDEX_CONTROLLER_H_

#include <string>

#include "base/macros.h"
#include "base/uuid.h"
#include "core/host/index/index_manager.h"

namespace host {
class Index;
/* 
 * Index controller - operations on index should be aggregated here
 * eg. create, destroy ..
 */
class IndexController {
public:
  IndexController(IndexManager* manager);
  ~IndexController();

  Index* CreateIndex(const std::string& name, const IndexManager::CreateOptions& options);
  void DestroyIndex(const std::string& name);
  void DestroyIndex(const base::UUID& uuid);

private:
 IndexManager* manager_;
 
 DISALLOW_COPY_AND_ASSIGN(IndexController);
};

}

#endif