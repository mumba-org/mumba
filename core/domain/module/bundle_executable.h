// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_MODULE_BUNDLE_EXECUTABLE_H_
#define MUMBA_DOMAIN_MODULE_BUNDLE_EXECUTABLE_H_

#include <string>
#include <map>

#include "base/uuid.h"
#include "base/memory/ref_counted.h"
#include "base/files/file_path.h"
#include "core/domain/module/code.h"
#include "core/domain/module/executable.h"
#include "mojo/public/cpp/system/buffer.h"

namespace domain {
class StorageContext;

class BundleExecutable : public Executable {
public:
  BundleExecutable(
    base::UUID id,
    const std::string& identifier,
    scoped_refptr<StorageContext> context);

  ~BundleExecutable() override;
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

  bool AddExecutableFromPath(storage_proto::ExecutableArchitecture arch, const base::FilePath& path);
  bool AddExecutableFromPathForHostArch(const base::FilePath& path);

private:

  void ExtractExecutable(const base::FilePath& path);
  void CreateHeader(storage_proto::ExecutableFormat format);
  void LoadHeader();

  void LoadExecutableImages(bool eager_load);
  void LoadExecutableImage(storage_proto::ExecutableArchitecture arch, int total_archs);
  void LoadHostExecutable();
  bool DecodeExecutableHeader(void* data, size_t size, storage_proto::Code* proto);
  bool GetExecutableContents(void* data, size_t size, base::StringPiece* contents);

  std::string GetStaticEntryName(storage_proto::ExecutableEntryCode entry_code);

  void ReadHeaderData(base::Callback<void(int, mojo::ScopedSharedBufferHandle, int)> cb);
  void ReadData(base::StringPiece key, base::Callback<void(int, mojo::ScopedSharedBufferHandle, int)> cb);
  void ReadDataForArch(storage_proto::ExecutableArchitecture arch, base::Callback<void(int, mojo::ScopedSharedBufferHandle, int)> cb);
  void WriteData(base::StringPiece key, mojo::ScopedSharedBufferHandle data, int64_t size, base::Callback<void(int)> cb);
  void WriteHeaderData(mojo::ScopedSharedBufferHandle data, int64_t size, base::Callback<void(int)> cb);

  void OnHeaderLoad(int status, mojo::ScopedSharedBufferHandle buffer, int readed);
  void OnReadExecutableData(std::string arch_identifier, int status, mojo::ScopedSharedBufferHandle buffer, int readed);
  void OnReadExecutableImage(storage_proto::ExecutableArchitecture arch, int total_archs, int status, mojo::ScopedSharedBufferHandle buffer, int readed);

  storage_proto::ExecutableArchitecture host_arch_;

  //std::unique_ptr<ApplicationFile> file_;
  base::UUID id_;
  std::string identifier_;
  scoped_refptr<StorageContext> context_;

  std::unique_ptr<storage_proto::Application> application_proto_;

  // a map of architecture -> code
  std::map<int, std::unique_ptr<Code>> codes_;
  
  bool initialized_;
  base::FilePath path_;
  std::string app_keyspace_;
  int loaded_archs_;

  DISALLOW_COPY_AND_ASSIGN(BundleExecutable);
};

}

#endif
