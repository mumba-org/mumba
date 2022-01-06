// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/execution/library.h"

#include "base/files/file_path.h"
#include "base/path_service.h"
#include "base/native_library.h"
#include "core/domain/execution/native/native_library.h"
#include "core/shared/domain/storage/namespace.h"

namespace domain {

// static 
Library* Library::LoadLibraryFromName(Namespace* namespace, const std::string& name, Library::Type type) {
  if (type == Library::kNative) {
    base::NativeLibraryLoadError error;
    std::string lib_name = base::GetNativeLibraryName(name);
    base::FilePath library_path;
    PathService::Get(base::DIR_MODULE, &library_path);
    library_path = library_path.AppendASCII(lib_name);
    base::NativeLibrary lib = base::LoadNativeLibrary(library_path, &error);
    if (!lib) {
      LOG(ERROR) << "error loading library '" << lib_name << "': " << error.ToString();
      return nullptr;
    }
    return new NativeLibrary(name, lib);
  } else if (type == Library::kV8) {
    NOTREACHED();
  }
  return nullptr;
}

}