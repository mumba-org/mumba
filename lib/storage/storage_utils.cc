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

std::string FormatNameForArchitecture(const std::string& name, storage_proto::ExecutableArchitecture arch, storage_proto::ExecutableFormat format) {
  std::string head;
  switch (arch) {
    case storage_proto::LINUX_X86_64:
    case storage_proto::LINUX_ARM:
    case storage_proto::LINUX_AARCH64: {
      if (format == storage_proto::LIBRARY) {
        head = "lib";
      }
      break;
    }
    case storage_proto::DARWIN_X86_64:
    case storage_proto::DARWIN_ARM:
    case storage_proto::DARWIN_AARCH64:
    case storage_proto::WINDOWS_X86_64:
    case storage_proto::WINDOWS_ARM:
    case storage_proto::WINDOWS_AARCH64:
    case storage_proto::ANY_WASM: 
    default:
      head = "";  
  }
  return head.empty() ? name : head + name;
}

std::string GetIdentifierForArchitecture(storage_proto::ExecutableArchitecture arch) {
  switch (arch) {
    case storage_proto::LINUX_X86_64:
      return "linux-x64";
    case storage_proto::LINUX_ARM:
      return "linux-arm";
    case storage_proto::LINUX_AARCH64:
      return "linux-aarch64";
    case storage_proto::DARWIN_X86_64:
      return "darwin-x64";
    case storage_proto::DARWIN_ARM:
      return "darwin-arm";
    case storage_proto::DARWIN_AARCH64:
      return "darwin-aarch64";
    case storage_proto::WINDOWS_X86_64:
      return "windows-x64";
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
  base::FilePath dir = base::FilePath();
  std::string name = db_identifier;
  std::string key = GetIdentifierForArchitecture(arch);
  return dir.AppendASCII(key).AppendASCII(name);
}

base::FilePath GetPathForArchitecture(const std::string& db_identifier, storage_proto::ExecutableArchitecture arch, storage_proto::ExecutableFormat format) {
  base::FilePath dir = base::FilePath();
  std::string name = FormatNameForArchitecture(db_identifier, arch, format);
  std::string key = GetIdentifierForArchitecture(arch);
  std::string ext;
  if (format == storage_proto::LIBRARY && arch == storage_proto::LINUX_X86_64) {
    ext = ".so";
  } else if (format == storage_proto::LIBRARY && arch == storage_proto::DARWIN_X86_64) {
    ext = ".dylib";
  } else if (format == storage_proto::LIBRARY && arch == storage_proto::WINDOWS_X86_64) {
    ext = ".dll";
  } else if (format == storage_proto::PROGRAM && arch == storage_proto::WINDOWS_X86_64) {
    ext = ".exe";
  } else if (format == storage_proto::PROGRAM && arch == storage_proto::DARWIN_X86_64) {
    ext = ".app";
  }
  return dir.AppendASCII(key).AppendASCII(name + ext);
}

base::FilePath GetFilePathForArchitecture(const std::string& db_identifier, storage_proto::ExecutableArchitecture arch, storage_proto::ExecutableFormat format) {
  base::FilePath dir = base::FilePath();
  std::string name = FormatNameForArchitecture(db_identifier, arch, format);
  std::string key = GetIdentifierForArchitecture(arch);
  std::string ext;
  if (format == storage_proto::LIBRARY && arch == storage_proto::LINUX_X86_64) {
    ext = ".so";
  } else if (format == storage_proto::LIBRARY && arch == storage_proto::DARWIN_X86_64) {
    ext = ".dylib";
  } else if (format == storage_proto::LIBRARY && arch == storage_proto::WINDOWS_X86_64) {
    ext = ".dll";
  } else if (format == storage_proto::PROGRAM && arch == storage_proto::WINDOWS_X86_64) {
    ext = ".exe";
  } else if (format == storage_proto::PROGRAM && arch == storage_proto::DARWIN_X86_64) {
    ext = ".app";
  }
  return dir.AppendASCII(name + ext);
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
#if defined (OS_WIN)
  return input_dir.DirName().Append(name + kStorageFileExtensionWithDot);
#else
  return input_dir.DirName().AppendASCII(name + kStorageFileExtensionWithDot);
#endif
}

}