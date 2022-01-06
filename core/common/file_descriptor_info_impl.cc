// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/common/file_descriptor_info_impl.h"

namespace common {

// static
std::unique_ptr<FileDescriptorInfo> FileDescriptorInfoImpl::Create() {
  return std::unique_ptr<FileDescriptorInfo>(new FileDescriptorInfoImpl());
}

FileDescriptorInfoImpl::FileDescriptorInfoImpl() {
}

FileDescriptorInfoImpl::~FileDescriptorInfoImpl() {
}

#if defined(OS_WIN)
void FileDescriptorInfoImpl::Share(base::PlatformFile fd) {
  AddToMapping(fd);
}

void FileDescriptorInfoImpl::Transfer(int id, base::ScopedFILE fd) {
  AddToMapping(fd.get());
  std::unique_ptr<base::ScopedFILE> fd_handle(new base::ScopedFILE(std::move(fd)));
  owned_descriptors_.push_back(std::move(fd_handle));
}

base::PlatformFile FileDescriptorInfoImpl::GetFDAt(size_t i) const {
  return mapping_[i];
}

#elif defined(OS_POSIX)
void FileDescriptorInfoImpl::Share(int id, base::PlatformFile fd) {
  AddToMapping(id, fd);
}

void FileDescriptorInfoImpl::Transfer(int id, base::ScopedFD fd) {
  AddToMapping(id, fd.get());
  std::unique_ptr<base::ScopedFD> fd_handle(new base::ScopedFD(std::move(fd)));
  owned_descriptors_.push_back(std::move(fd_handle));
}

base::PlatformFile FileDescriptorInfoImpl::GetFDAt(size_t i) const {
  return mapping_[i].first;
}

int FileDescriptorInfoImpl::GetIDAt(size_t i) const {
  return mapping_[i].second;
}

bool FileDescriptorInfoImpl::HasID(int id) const {
  for (unsigned i = 0; i < mapping_.size(); ++i) {
    if (mapping_[i].second == id)
      return true;
  }

  return false;
}

#endif


size_t FileDescriptorInfoImpl::GetMappingSize() const {
  return mapping_.size();
}

bool FileDescriptorInfoImpl::OwnsFD(base::PlatformFile file) const {
#if defined(OS_WIN)
  return owned_descriptors_.end() !=
         std::find_if(
             owned_descriptors_.begin(), owned_descriptors_.end(),
             [file](const std::unique_ptr<base::ScopedFILE>& fd) { return fd->get() == file; });
#elif defined(OS_POSIX)
  return owned_descriptors_.end() !=
         std::find_if(
             owned_descriptors_.begin(), owned_descriptors_.end(),
             [file](const std::unique_ptr<base::ScopedFD>& fd) { return fd->get() == file; });
#endif
}
#if defined(OS_WIN)
base::ScopedFILE FileDescriptorInfoImpl::ReleaseFD(base::PlatformFile file) {
  base::ScopedFILE fd;
  auto found = std::find_if(
      owned_descriptors_.begin(), owned_descriptors_.end(),
      [file](const std::unique_ptr<base::ScopedFILE>& fd) { return fd->get() == file; });

  (*found)->swap(fd);
  owned_descriptors_.erase(found);

  return fd;
}
const base::HandlesToInheritVector& FileDescriptorInfoImpl::GetMapping()
    const {
  return mapping_;
}

base::HandlesToInheritVector
FileDescriptorInfoImpl::GetMappingWithIDAdjustment(int delta) const {
  base::HandlesToInheritVector result = mapping_;
  return result;
}

void FileDescriptorInfoImpl::AddToMapping(base::PlatformFile fd) {
  mapping_.push_back(std::move(fd));
}

#elif defined(OS_POSIX)
base::ScopedFD FileDescriptorInfoImpl::ReleaseFD(base::PlatformFile file) {
  DCHECK(OwnsFD(file));

  base::ScopedFD fd;
  auto found = std::find_if(
      owned_descriptors_.begin(), owned_descriptors_.end(),
      [file](const std::unique_ptr<base::ScopedFD>& fd) { return fd->get() == file; });

  (*found)->swap(fd);
  owned_descriptors_.erase(found);

  return fd;
}

const base::FileHandleMappingVector& FileDescriptorInfoImpl::GetMapping()
    const {
  return mapping_;
}

base::FileHandleMappingVector
FileDescriptorInfoImpl::GetMappingWithIDAdjustment(int delta) const {
  base::FileHandleMappingVector result = mapping_;
  // Adding delta to each ID.
  for (unsigned i = 0; i < mapping_.size(); ++i)
    result[i].second += delta;
  return result;
}

void FileDescriptorInfoImpl::AddToMapping(int id, base::PlatformFile fd) {
  DCHECK(!HasID(id));
  mapping_.push_back(std::make_pair(fd, id));
}
#endif

}  // namespace common
