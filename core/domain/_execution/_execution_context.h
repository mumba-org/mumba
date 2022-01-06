// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_EXECUTION_EXECUTION_CONTEXT_H_
#define MUMBA_DOMAIN_EXECUTION_EXECUTION_CONTEXT_H_

// use the V8 variation here

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmacro-redefined"
#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#pragma clang diagnostic pop

#include <v8.h>

namespace v8 {
class Isolate;
class Context;
template <class T>
class Local;
}

namespace gin {
class ContextHolder;
}

namespace domain {
class ExecutionEngine;

class ExecutionContext {
public:
  ExecutionContext(base::WeakPtr<ExecutionEngine> engine, v8::Isolate* isolate);
  ~ExecutionContext();

  v8::Isolate* isolate() const;
  v8::Local<v8::Context> handle() const;

  ExecutionEngine* engine() const {
    return engine_.get();
  }

  void Shutdown();

  void CallHello();

private:

  base::WeakPtr<ExecutionEngine> engine_;
  
  std::unique_ptr<gin::ContextHolder> context_holder_;  
  
  DISALLOW_COPY_AND_ASSIGN(ExecutionContext);
};

}

#endif