// Copyright 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_MODULE_EXECUTABLE_H_
#define MUMBA_DOMAIN_MODULE_EXECUTABLE_H_

#include <string>
#include <map>

#include "base/uuid.h"
#include "base/memory/ref_counted.h"
#include "base/files/file_path.h"
#include "core/domain/module/code.h"
#include "mojo/public/cpp/system/buffer.h"

namespace domain {

class Executable {
public:
  struct InitParams {
    bool readonly = true;
    bool check = false;
    bool in_memory = false;
    bool creating = false;
    base::FilePath path;
    storage_proto::ExecutableFormat format = storage_proto::LIBRARY;
    mojo::ScopedSharedBufferHandle data;
    size_t data_size = 0;
    InitParams() {}
  };

  virtual ~Executable() {}
  virtual bool Init(InitParams params = InitParams()) = 0;
  virtual storage_proto::ExecutableFormat executable_format() const = 0;
  virtual Code* host_code() const = 0;
  virtual const base::UUID& id() const = 0;
  virtual bool SupportsArch(storage_proto::ExecutableArchitecture arch) const = 0;
  virtual bool HostSupported() = 0;
  virtual storage_proto::ExecutableEntry GetStaticEntry(storage_proto::ExecutableEntryCode entry_code) = 0;
  virtual std::string GetEntryName(storage_proto::ExecutableEntry entry) = 0;
  virtual const base::FilePath& path() const = 0;
  virtual const std::string& identifier() const = 0;
  virtual size_t size() = 0;
  virtual void Close() = 0;
};

}

#endif
