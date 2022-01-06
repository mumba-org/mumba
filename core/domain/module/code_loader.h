// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_EXECUTION_CODE_LOADER_H_
#define MUMBA_DOMAIN_EXECUTION_CODE_LOADER_H_

#include <string>
#include <memory>

#include "base/macros.h"
#include "base/files/file_path.h"
#include "storage/proto/storage.pb.h"
#include "mojo/public/cpp/system/buffer.h"
#include "core/domain/module/code_entry.h"

namespace domain {

class CodeLoader {
public:
  static std::unique_ptr<CodeLoader> CreateDefault(storage_proto::ExecutableArchitecture arch, bool load_from_memory);

  virtual ~CodeLoader() {}
  virtual bool is_loaded() const = 0;
  virtual bool LoadFromLocalFile(const base::FilePath& path) = 0;
  virtual bool LoadFromMemoryBuffer(void* buffer, size_t size) = 0;
  virtual void Unload() = 0;
  virtual Address GetCodeEntry(const std::string& name) = 0;
};

}

#endif