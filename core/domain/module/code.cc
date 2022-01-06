// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/module/code.h"

#include "base/files/file_path.h"
#include "base/files/file.h"
#include "base/files/file_util.h"
#include "base/strings/string_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "net/base/io_buffer.h"
#include "crypto/sha2.h"
#include "crypto/secure_hash.h"
#include "core/domain/module/code_entry.h"
#include "core/domain/module/code_loader.h"

namespace domain {

Code::Code(storage_proto::Code code_proto):
 code_proto_(std::move(code_proto)),
#if defined(OS_WIN)
 path_(base::ASCIIToUTF16(code_proto_.resource().path())),
#else
 path_(code_proto_.resource().path()),
#endif
 data_size_(0),
 load_from_memory_(false) {
  code_loader_ = CodeLoader::CreateDefault(code_proto_.architecture(), load_from_memory_);
  Init();
}

Code::Code(storage_proto::Code code_proto, mojo::ScopedSharedBufferHandle data, size_t data_size):
 code_proto_(std::move(code_proto)),
#if defined(OS_WIN) 
 path_(base::ASCIIToUTF16(code_proto_.resource().path())),
#else
 path_(code_proto_.resource().path()),
#endif
 data_(std::move(data)),
 data_size_(data_size),
 load_from_memory_(true) {
  code_loader_ = CodeLoader::CreateDefault(code_proto_.architecture(), load_from_memory_);
  Init();
}

Code::~Code() {
  for (auto it = entries_.begin(); it != entries_.end(); it++) {
    delete *it;
  }
  code_loader_->Unload();
}

const base::FilePath& Code::path() const {
  return path_;
}

void Code::set_path(const base::FilePath& path) {
#if defined(OS_POSIX)
  code_proto_.mutable_resource()->set_path(path.value());
#elif defined(OS_WIN)
  code_proto_.mutable_resource()->set_path(base::UTF16ToASCII(path.value()));
#endif
  path_ = path;
}

bool Code::Load() {
  if (code_loader_->is_loaded()) { // already loaded
    return true;
  }

  if (executable_format() == storage_proto::LIBRARY) {
    if (load_from_memory_) {
      mojo::ScopedSharedBufferMapping mapping = data_->Map(data_size_);
      return code_loader_->LoadFromMemoryBuffer(mapping.get(), data_size_);
    } else {
      return code_loader_->LoadFromLocalFile(path_);
    }
  }

  // TODO we should iterate over service descriptor now
  // and create Functions based on the name, func signature
  // etc.. and cache them

  return false;
}

void Code::Unload() {
  if (!code_loader_->is_loaded()) {
    return;
  }  
  code_loader_->Unload();
}

bool Code::Init() {
  if (executable_format() == storage_proto::LIBRARY) {
    return Load();
  }
  return true;
}

CodeEntry* Code::GetEntry(const std::string& name) {
  DCHECK(executable_format() == storage_proto::LIBRARY);
  CodeEntry* entry = GetCachedEntry(name);
  if (entry) {
    return entry;
  }

  Address fn_entry = code_loader_->GetCodeEntry(name);
  if (!fn_entry) {
    return nullptr;
  }
  entry = new CodeEntry{name, fn_entry};
  entries_.push_back(entry);
  return entry;
}

CodeEntry* Code::GetCachedEntry(const std::string& name) {
  for (auto it = entries_.begin(); it != entries_.end(); it++) {
    if ((*it)->name == name) {
      return *it;
    }
  }
  return nullptr;
}

}
