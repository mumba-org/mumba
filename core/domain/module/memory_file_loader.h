// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_EXECUTION_NATIVE_LIBRARY_MEMORY_LOADER_H_
#define MUMBA_DOMAIN_EXECUTION_NATIVE_LIBRARY_MEMORY_LOADER_H_

#include <string>

#include "base/macros.h"
#include "base/files/file_path.h"
#include "base/files/platform_file.h"
#include "core/domain/module/code_loader.h"

namespace domain {
 
 // A native executable code loader that dont need a persisted file
class MemoryFileLoader : public CodeLoader {
public:
  MemoryFileLoader();
  ~MemoryFileLoader() override;

  bool is_loaded() const override;
  bool LoadFromLocalFile(const base::FilePath& path) override;
  bool LoadFromMemoryBuffer(void* buffer, size_t size) override;
  void Unload() override;
  
  Address GetCodeEntry(const std::string& name) override;

private:
  std::string path_;
  bool library_loaded_;
  base::PlatformFile fd_;
  void* native_library_handle_;
  
  DISALLOW_COPY_AND_ASSIGN(MemoryFileLoader); 
};

}

#endif