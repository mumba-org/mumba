// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/module/local_file_loader.h"

namespace domain {

LocalFileLoader::LocalFileLoader():
 library_loaded_(false) {

}

LocalFileLoader::~LocalFileLoader() {
  if (library_loaded_) {
  	base::UnloadNativeLibrary(native_library_);
  }
}

bool LocalFileLoader::is_loaded() const {
  return library_loaded_;
}

bool LocalFileLoader::LoadFromLocalFile(const base::FilePath& path) {
  base::NativeLibraryLoadError error;
  native_library_ = base::LoadNativeLibrary(path, &error);
  if (!native_library_) {
    LOG(ERROR) << "error loading library '" << path << "': " << error.ToString();
    return false;
  }
  library_loaded_ = true;
  return library_loaded_;
}

bool LocalFileLoader::LoadFromMemoryBuffer(void* buffer, size_t size) {
  return false;
}

void LocalFileLoader::Unload() {
  if (library_loaded_) {
    base::UnloadNativeLibrary(native_library_);
    library_loaded_ = false;
  }
}
  
Address LocalFileLoader::GetCodeEntry(const std::string& name) {
  if (library_loaded_) {
  	return reinterpret_cast<Address>(base::GetFunctionPointerFromNativeLibrary(native_library_, name));
  }
  return kNullAddress;
}

}