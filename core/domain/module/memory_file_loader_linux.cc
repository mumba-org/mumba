// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/module/memory_file_loader.h"

#include <dlfcn.h>
#include <link.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "base/uuid.h"
#include "base/sha1.h"
#include "base/strings/string_number_conversions.h"

namespace domain {

MemoryFileLoader::MemoryFileLoader():
 path_(),
 library_loaded_(false),
 fd_(base::kInvalidPlatformFile),
 native_library_handle_(nullptr) {
  
  base::UUID tmp_uuid = base::UUID::generate();
  path_ = "/tmp/" + tmp_uuid.to_string() + "XXXXXX";
}

MemoryFileLoader::~MemoryFileLoader() {
  
}

bool MemoryFileLoader::is_loaded() const {
  return library_loaded_;
}

bool MemoryFileLoader::LoadFromLocalFile(const base::FilePath& path) {
  // assert this does not get called in this case
  DCHECK(false);
  return false;
}

bool MemoryFileLoader::LoadFromMemoryBuffer(void* buffer, size_t size) {
  /* 
   * this version here would use memfd.. the problem is that we would
   * need to manipulate Elf headers here
   * So we stick with the simple version where we copy to a file in
   * tmpfs and dlopen from there
   */
  //mem_file_ = memfd_create("_anonymous", MFD_CLOEXEC);
  //if (mem_file_ == -1) {
  //  return false;
  //}
  //size_t wrote = write(mem_file_, buffer.get(), size);
  //if (wrote != size) {
  //  close(mem_file_);
  //  return false;
  //}

  //DCHECK(native_library_handle_);

  //uint8_t hash[20];
  //base::SHA1HashBytes(reinterpret_cast<unsigned char *>(buffer), size, &hash[0]);

  //DLOG(INFO) << "sha1 hash of buffer with size " << size << ":\n" << base::HexEncode(&hash[0], 20).c_str() << "\ntemp file: " << path_ << "\n";
      
  fd_ = mkostemp(const_cast<char *>(path_.c_str()), O_CLOEXEC);
  
  if (fd_ == -1) {
    //DLOG(ERROR) << "failed opening temp file " << path_ << ": " << strerror(errno);
    return false;
  }

  size_t wrote = write(fd_, buffer, size);
  
  if (wrote != size) {
    //DLOG(ERROR) << "failed writing to temp file " << path_ << " wants " << size << " wrote " << wrote;
    close(fd_);
    return false;
  }
  close(fd_);

  native_library_handle_ = dlopen(path_.c_str(), RTLD_NOW | RTLD_GLOBAL);
  if (!native_library_handle_) {
    //DLOG(ERROR) << "failed while opening " << path_ << " as a library";
    close(fd_);
    return false;
  }

  library_loaded_ = true;
  return true;
}

void MemoryFileLoader::Unload() {
  dlclose(native_library_handle_);
}
  
Address MemoryFileLoader::GetCodeEntry(const std::string& name) {
  if (library_loaded_) {
    return reinterpret_cast<Address>(dlsym(native_library_handle_, name.c_str()));
  }
  return kNullAddress;
}

}