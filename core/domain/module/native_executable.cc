// Copyright 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/module/native_executable.h"

#include "build/build_config.h"
#include "base/path_service.h"
#include "base/base_paths.h"
#include "base/memory/ref_counted.h"
#include "base/files/file.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/strings/string_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "base/strings/string_piece.h"
#include "base/hash.h"
#include "storage/db/sqliteInt.h"
#include "net/base/file_stream.h"
#include "net/base/io_buffer.h"
#include "crypto/secure_hash.h"
#include "crypto/sha2.h"
#include "core/domain/module/code.h"
#include "core/shared/domain/storage/storage_context.h"
#include "core/shared/domain/storage/data_storage.h"
#include "storage/storage_utils.h"
#include "storage/storage_constants.h"

namespace domain {

namespace {  

// TODO: it would be super cool to instantiate those from protocol buffers
// a protobuf api would describe the entry points in the binary and we would 
// just call them and get the binary
const char kAPP_INIT_ENTRY[] = "ApplicationInit";
const char kAPP_DESTROY_ENTRY[] = "ApplicationDestroy";
const char kAPP_GET_CLIENT_ENTRY[] = "ApplicationGetClient";

}

NativeExecutable::NativeExecutable(
  base::UUID id,
  const std::string& identifier):
    host_arch_(storage::GetHostArchitecture()),
    id_(std::move(id)),
    identifier_(identifier),
    initialized_(false),
#if defined(OS_WIN)
    path_(base::ASCIIToUTF16(identifier)),
#else
    path_(identifier),
#endif
    loaded_archs_(0) {
  
}

NativeExecutable::~NativeExecutable() {
 
}

bool NativeExecutable::Init(InitParams params) {
  initialized_ = LoadExecutableImage(std::move(params));
  return initialized_;
}

storage_proto::ExecutableFormat NativeExecutable::executable_format() const {
  return storage_proto::LIBRARY;
}

Code* NativeExecutable::host_code() const {
  auto it = codes_.find(storage::GetHostArchitecture());
  
  // this architecture is not supported
  if (it == codes_.end()) {
    //DLOG(ERROR) << "NativeExecutable: getting host code failed.";
    return nullptr;
  }

  return it->second.get();
}

const base::UUID& NativeExecutable::id() const {
  return id_;
}

bool NativeExecutable::SupportsArch(storage_proto::ExecutableArchitecture arch) const {
  bool supported = false;
  for (auto it = codes_.begin(); it != codes_.end(); ++it) {
    if (it->second->executable_architecture() == arch) {
      supported = true;
      break;
    }
  }
  return supported;
}

bool NativeExecutable::HostSupported() {
  return SupportsArch(storage::GetHostArchitecture());
}

storage_proto::ExecutableEntry NativeExecutable::GetStaticEntry(storage_proto::ExecutableEntryCode entry_code) {
  storage_proto::ExecutableEntry entry;
  entry.set_kind(storage_proto::ExecutableEntry::STATIC);
  entry.set_code(entry_code);
  return entry;
}

std::string NativeExecutable::GetEntryName(storage_proto::ExecutableEntry entry) {
  if (entry.kind() == storage_proto::ExecutableEntry::STATIC) {
    return GetStaticEntryName(entry.code());
  }
  // dynamic kind of entry
  return entry.name();
}

const base::FilePath& NativeExecutable::path() const {
  return path_;
}

const std::string& NativeExecutable::identifier() const {
  return identifier_;
}

bool NativeExecutable::LoadExecutableImage(InitParams params) {
  // load host arch
  std::unique_ptr<Code> code;
  storage_proto::Code code_proto;
#if defined(OS_WIN)
  code_proto.mutable_resource()->set_path(base::UTF16ToASCII(params.path.value()));
#else  
  code_proto.mutable_resource()->set_path(params.path.value());
#endif
  if (params.in_memory) {
    code = std::make_unique<Code>(std::move(code_proto), std::move(params.data), params.data_size);
  } else {
    code = std::make_unique<Code>(std::move(code_proto));
  }
  if (!code->Load()) {
    return false;
  }
  codes_.emplace(std::make_pair(host_arch_, std::move(code))); 
  loaded_archs_++;
  return true;
}

size_t NativeExecutable::size() {
  auto it = codes_.find(host_arch_);
  if (it == codes_.end()) {
    return 0;
  }
  return it->second->size();
}

void NativeExecutable::Close() {
  auto it = codes_.find(host_arch_);
  if (it == codes_.end()) {
    return;
  }
  return it->second->Unload();
}

std::string NativeExecutable::GetStaticEntryName(storage_proto::ExecutableEntryCode entry_code) {
  switch (entry_code) {
    case storage_proto::APP_INIT:
      return std::string(kAPP_INIT_ENTRY, arraysize(kAPP_INIT_ENTRY));
      break;
    case storage_proto::APP_DESTROY:
      return std::string(kAPP_DESTROY_ENTRY, arraysize(kAPP_DESTROY_ENTRY));
      break;
    case storage_proto::APP_GET_CLIENT:
      return std::string(kAPP_GET_CLIENT_ENTRY, arraysize(kAPP_GET_CLIENT_ENTRY));
      break;
    default:
      NOTREACHED();
  }
  return std::string();
}

}