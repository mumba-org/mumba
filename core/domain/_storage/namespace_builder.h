// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_NAMESPACE_BUILDER_H_
#define MUMBA_DOMAIN_NAMESPACE_BUILDER_H_

#include <string>
#include <memory>

#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "base/files/file_path.h"
#include "core/shared/domain/storage/namespace.h"
#include "base/uuid.h"

namespace domain {
class NamespaceManager;

class NamespaceBuilder {
public:
  NamespaceBuilder(const base::FilePath& root_path);
  ~NamespaceBuilder();

  bool Init();
  bool CreateDatabase(bool in_memory);
  bool CreateFilesystem(bool in_memory);

  std::unique_ptr<Namespace> Build(NamespaceManager* manager, bool in_memory);

private:

  base::FilePath root_path_;
  
  //std::string name_;

  base::UUID id_;

  DISALLOW_COPY_AND_ASSIGN(NamespaceBuilder);
};

}

#endif