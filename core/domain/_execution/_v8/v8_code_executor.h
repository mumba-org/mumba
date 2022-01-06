// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_EXECUTION_V8_V8_CODE_EXECUTOR_H_
#define MUMBA_DOMAIN_EXECUTION_V8_V8_CODE_EXECUTOR_H_

#include <string>
#include <unordered_map>

#include "base/macros.h"

namespace v8 {
namespace internal {
class Code;
}
}

namespace domain {
template <typename Functor>
class Function;
class ExecutionContext;

class V8CodeExecutor {
public:
  V8CodeExecutor();
  ~V8CodeExecutor();

  void Init(ExecutionContext* context);

  // Create a callable stub for a C function
  // that make it visible on the V8 isolate
  template <typename Functor>
  void CreateStub(ExecutionContext* context, Function<Functor>* function) {}

  template <typename Functor>
  void Call(ExecutionContext* context, Function<Functor>* function){}

  void CallHello(ExecutionContext* context);

private:
  class BuilderState;

  // map function id : Code
  std::unordered_map<std::string, v8::internal::Code*> codes_;

  DISALLOW_COPY_AND_ASSIGN(V8CodeExecutor);
};

}

#endif