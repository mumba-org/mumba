// Copyright 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_MODULE_NATIVE_EXECUTABLE_H_
#define MUMBA_DOMAIN_MODULE_NATIVE_EXECUTABLE_H_

#include <string>
#include <map>

#include "base/uuid.h"
#include "base/memory/ref_counted.h"
#include "base/files/file_path.h"
#include "core/domain/module/executable.h"
#include "core/domain/module/code.h"
#include "mojo/public/cpp/system/buffer.h"

namespace domain {
class StorageContext;

class NativeExecutable : public Executable {
public:
  NativeExecutable(
    base::UUID id,
    const std::string& identifier);

  ~NativeExecutable() override;
  bool Init(InitParams params = InitParams()) override;
  storage_proto::ExecutableFormat executable_format() const override;
  Code* host_code() const override;
  const base::UUID& id() const override;
  bool SupportsArch(storage_proto::ExecutableArchitecture arch) const override;
  bool HostSupported() override;
  storage_proto::ExecutableEntry GetStaticEntry(storage_proto::ExecutableEntryCode entry_code) override;
  std::string GetEntryName(storage_proto::ExecutableEntry entry) override;
  const base::FilePath& path() const override;
  const std::string& identifier() const override;
  size_t size() override;
  void Close() override;

private:
  bool LoadExecutableImage(InitParams params);
  std::string GetStaticEntryName(storage_proto::ExecutableEntryCode entry_code);

  storage_proto::ExecutableArchitecture host_arch_;
  base::UUID id_;
  std::string identifier_;
  std::unique_ptr<storage_proto::Application> application_proto_;
  // a map of architecture -> code
  std::map<int, std::unique_ptr<Code>> codes_;
  bool initialized_;
  base::FilePath path_;
  int loaded_archs_;

  DISALLOW_COPY_AND_ASSIGN(NativeExecutable);
};

}

#endif
