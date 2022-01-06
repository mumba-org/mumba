// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_FILE_DESCRIPTOR_INFO_IMPL_H_
#define CONTENT_BROWSER_FILE_DESCRIPTOR_INFO_IMPL_H_

#include <vector>
#include <memory>
//#include "base/memory/scoped_vector.h"
#include "core/common/file_descriptor_info.h"

namespace common {

class FileDescriptorInfoImpl : public FileDescriptorInfo {
 public:
 static std::unique_ptr<FileDescriptorInfo> Create();

  ~FileDescriptorInfoImpl() override;
#if defined(OS_WIN)
  void Share(base::PlatformFile fd) override;
  void Transfer(int id, base::ScopedFILE fd) override;
  base::ScopedFILE ReleaseFD(base::PlatformFile file) override;
  const base::HandlesToInheritVector& GetMapping() const override;
  base::HandlesToInheritVector GetMappingWithIDAdjustment(int delta) const override;
#elif defined(OS_POSIX)
  void Share(int id, base::PlatformFile fd) override;
  void Transfer(int id, base::ScopedFD fd) override;
  int GetIDAt(size_t i) const override;
  base::ScopedFD ReleaseFD(base::PlatformFile file) override;
  const base::FileHandleMappingVector& GetMapping() const override;
  base::FileHandleMappingVector GetMappingWithIDAdjustment(
      int delta) const override;
#endif  
  base::PlatformFile GetFDAt(size_t i) const override;
  size_t GetMappingSize() const override;
  bool OwnsFD(base::PlatformFile file) const override;

 private:
  FileDescriptorInfoImpl();

#if defined(OS_WIN)
  void AddToMapping(base::PlatformFile fd);

  base::HandlesToInheritVector mapping_;
  std::vector<std::unique_ptr<base::ScopedFILE>> owned_descriptors_;
#elif defined(OS_POSIX)  
  void AddToMapping(int id, base::PlatformFile fd);
  bool HasID(int id) const;

  base::FileHandleMappingVector mapping_;
  std::vector<std::unique_ptr<base::ScopedFD>> owned_descriptors_;
  
#endif  
};
}

#endif  // CONTENT_BROWSER_FILE_DESCRIPTOR_INFO_IMPL_H_
