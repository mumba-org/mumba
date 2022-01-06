// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_EXECUTION_SNAPSHOT_CODE_LOADER_H_
#define MUMBA_DOMAIN_EXECUTION_SNAPSHOT_CODE_LOADER_H_

#include <string>

#include "base/macros.h"
#include "base/files/file_path.h"
#include "base/native_library.h"
#include "core/domain/module/code_loader.h"

namespace domain {
/*
 * V8 snapshot library loader
 * A alternative to native linking libraries
 */ 
class SnapshotFileLoader : public CodeLoader {
public:
  SnapshotFileLoader();
  ~SnapshotFileLoader() override;

  bool is_loaded() const override;
  bool LoadFromLocalFile(const base::FilePath& path) override;
  bool LoadFromMemoryBuffer(void* buffer, size_t size) override;
  void Unload() override;
  
  Address GetCodeEntry(const std::string& name) override;

private:

  bool library_loaded_;

  DISALLOW_COPY_AND_ASSIGN(SnapshotFileLoader); 
};

}

#endif