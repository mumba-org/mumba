// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/execution/native/native_library.h"
#include "core/domain/execution/native/native_function.h"

namespace domain {

NativeLibrary::NativeLibrary(const std::string& name, base::NativeLibrary handle): 
  name_(name),
  handle_(handle) {
}

NativeLibrary::~NativeLibrary() {
  for (auto it = entries_.begin(); it != entries_.end(); it++) {
    delete *it;
  }
  base::UnloadNativeLibrary(handle_);
}

NativeFunctionEntry* NativeLibrary::GetEntry(const std::string& name) {
  NativeFunctionEntry* entry = GetCachedEntry(name);
  if (entry) {
    return entry;
  }

  void* fn_ptr = base::GetFunctionPointerFromNativeLibrary(handle_, name);
  if (!fn_ptr) {
    return nullptr;
  }
  entry = new NativeFunctionEntry{name, fn_ptr};
  entries_.push_back(entry);
  return entry;
}

NativeFunctionEntry* NativeLibrary::GetCachedEntry(const std::string& name) {
  for (auto it = entries_.begin(); it != entries_.end(); it++) {
    if ((*it)->name == name) {
      return *it;
    }
  }
  return nullptr;
}

}