// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_INDEX_INDEX_REGISTRY_H_
#define MUMBA_HOST_INDEX_INDEX_REGISTRY_H_

#include "base/macros.h"

namespace host {
class Index;
/*
 * The index registry - IPC interface for application and domain processes
 */
class IndexRegistry : public common::mojom::IndexRegistry {
public:
  IndexRegistry();
  ~IndexRegistry() override;

  void CreateIndex(const std::string& name, const CreateOptions& options, CreateIndexCallback callback) override;
  void DestroyIndex(const std::string& name, DestroyIndexCallback callback) override;
  void DestroyIndexByUUID(const std::string& uuid, DestroyIndexCallback callback) override;

private:

 DISALLOW_COPY_AND_ASSIGN(IndexRegistry);
};

}

#endif