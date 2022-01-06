// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/execution/execution_context.h"

#include "gin/public/context_holder.h"
#include "core/domain/execution/execution_engine.h"
//#include "core/domain/execution/v8/v8_code_executor.h"

//#include <v8.h>

namespace domain {

ExecutionContext::ExecutionContext(base::WeakPtr<ExecutionEngine> engine, v8::Isolate* isolate): 
  engine_(std::move(engine)),
  context_holder_(new gin::ContextHolder(isolate)) {
  v8::HandleScope scope(isolate);  
  context_holder_->SetContext(v8::Context::New(isolate));
}

ExecutionContext::~ExecutionContext() {

}

v8::Isolate* ExecutionContext::isolate() const {
  //DLOG(INFO) << "isolate: " << context_holder_->isolate();
  return context_holder_->isolate();
}

v8::Local<v8::Context> ExecutionContext::handle() const {
  return context_holder_->context();
}

void ExecutionContext::Shutdown() {
  context_holder_.reset();
}

void ExecutionContext::CallHello() {
  printf("ExecutionContext::CallHello\n");
  V8CodeExecutor executor;
  executor.Init(this);
  executor.CallHello(this);
}

}