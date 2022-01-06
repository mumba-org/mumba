// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/storage_utils.h"

#include "storage/storage_constants.h"

#include "base/files/file_util.h"

namespace storage {

// bool IsStorageDir(storage_proto::StorageProfile disk_type, const base::FilePath& path) {
//   base::FilePath::StringType base_name = path.BaseName().value();
  
//   // valid for all kinds
//   if (base_name == "disk" || base_name == "data" || base_name == "index" || base_name == "blob") {
//     return true;
//   }

//   // valid only if application kind
//   if (base_name == "bin" && disk_type == storage_proto::APPLICATION_PROFILE) {
//     return true;
//   }

//   return false;
// }

std::string GetIdentifierForArchitecture(storage_proto::ExecutableArchitecture arch) {
  switch (arch) {
    case storage_proto::LINUX_X86_64:
      return "linux-x86-64";
    case storage_proto::LINUX_ARM:
      return "linux-arm";
    case storage_proto::LINUX_AARCH64:
      return "linux-aarch64";
    case storage_proto::DARWIN_X86_64:
      return "darwin-x86-64";
    case storage_proto::DARWIN_ARM:
      return "darwin-arm";
    case storage_proto::DARWIN_AARCH64:
      return "darwin-aarch64";
    case storage_proto::WINDOWS_X86_64:
      return "windows-X86-64";
    case storage_proto::WINDOWS_ARM:
      return "windows-arm";
    case storage_proto::WINDOWS_AARCH64:
      return "windows-aarch";
    case storage_proto::ANY_WASM: 
      return "any-wasm";
    default:
      return "";  
  }
  return "";
}

base::FilePath GetPathForArchitecture(const std::string& db_identifier, storage_proto::ExecutableArchitecture arch) {
  // .../bin/x.app
  base::FilePath dir = base::FilePath();//db_path.DirName();
  std::string name = db_identifier;//db_path.RemoveExtension().BaseName().value();
  std::string key = GetIdentifierForArchitecture(arch);
  return dir.AppendASCII(key).AppendASCII(name);
}

storage_proto::ExecutableArchitecture GetHostArchitecture() {
#if defined(OS_LINUX) && defined(ARCH_CPU_X86_64)
  return storage_proto::LINUX_X86_64;
#elif defined(OS_WIN) && defined(ARCH_CPU_X86_64)
  return storage_proto::WINDOWS_X86_64;
#endif
  CHECK(false);
}

std::string GetIdentifierForHostOS() {
  return GetIdentifierForArchitecture(GetHostArchitecture());
}

base::FilePath GetPackPathFromInputDir(const base::FilePath& input_dir) {
  base::FilePath::StringType name = input_dir.RemoveExtension().BaseName().value();
  return input_dir.DirName().AppendASCII(name + kStorageFileExtensionWithDot);
}

}