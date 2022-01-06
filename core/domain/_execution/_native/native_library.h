// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_EXECUTION_NATIVE_NATIVE_LIBRARY_H_
#define MUMBA_DOMAIN_EXECUTION_NATIVE_NATIVE_LIBRARY_H_

#include <vector>

#include "core/domain/execution/library.h"
#include "core/domain/execution/native/native_function.h"
#include "base/native_library.h"

namespace domain {

class NativeLibrary : public Library {
public:
  NativeLibrary(const std::string& name, base::NativeLibrary handle);
  ~NativeLibrary() override;

  const std::string& name() const override {
    return name_;
  }

  Type type() const override {
    return Library::kNative;
  }

  template <typename R,typename... Args>
  inline Callable<base::MakeUnboundRunType<R, Args...>>
  Bind(const std::string& func_name, Args&&... args) {
    NativeFunctionEntry* entry = GetEntry(func_name);
    if (entry) {
      NativeFunction<R> func(entry);
      return func.Bind(std::forward(args)...);
    }
    return {};
  }

private:

  NativeFunctionEntry* GetEntry(const std::string& name);
  NativeFunctionEntry* GetCachedEntry(const std::string& name);  
  
  std::string name_;

  base::NativeLibrary handle_;

  std::vector<NativeFunctionEntry *> entries_;
  
  DISALLOW_COPY_AND_ASSIGN(NativeLibrary);
};

}

#endif