// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.


#include "core/domain/execution/v8/v8_code_executor.h"

#include "core/domain/execution/function.h"
#include "core/domain/execution/execution_context.h"
#include "core/domain/execution/v8/v8_code_builder.h"
#include "core/domain/execution/v8/v8_function.h"
#include "core/domain/execution/native/native_function.h"
// v8
#include "src/allocation.h"
#include "src/objects.h"
//#pragma clang diagnostic push
//#pragma clang diagnostic ignored "-Wunused-variable"
//#include "src/objects-inl.h"
//#include "src/handles-inl.h"
#include "src/globals.h"
//#pragma clang diagnostic pop

using v8::internal::Address;
using v8::internal::Callable;
using v8::internal::Code;
using v8::internal::CallInterfaceDescriptor;
using v8::internal::compiler::CodeAssemblerState;
using v8::internal::Zone;

namespace domain {

class V8CodeExecutor::BuilderState {
public:
  BuilderState(v8::internal::Isolate* isolate,
    const std::string& name,
    CallInterfaceDescriptor descriptor,
    int result_size):
    zone_(isolate->allocator(), ZONE_NAME, v8::internal::SegmentSize::kDefault),
    code_assembler_state_(isolate, &zone_, descriptor, Code::BUILTIN,
                          name.c_str(), v8::internal::PoisoningMitigationLevel::kOff,
                          result_size, 0) {}
  ~BuilderState() {}

  CodeAssemblerState* code_assembler_state() { 
    return &code_assembler_state_;
  }

private:
  Zone zone_;
  CodeAssemblerState code_assembler_state_;
};

V8CodeExecutor::V8CodeExecutor() {

}

V8CodeExecutor::~V8CodeExecutor() {

}

void V8CodeExecutor::Init(ExecutionContext* context) {
  //v8::internal::Isolate* i_isolate = reinterpret_cast<v8::internal::Isolate*>(context->isolate());

}

// void V8CodeExecutor::CreateStub(ExecutionContext* context, Function* function) {

// }

//void V8CodeExecutor::Call(ExecutionContext* context, Function* function) {
  // v8::Isolate* isolate = context->isolate();
  // v8::Isolate::Scope scope(isolate);
  // v8::HandleScope handle_scope(isolate);

  // v8::internal::Isolate* i_isolate = reinterpret_cast<v8::internal::Isolate*>(isolate);

  // //InternalState state(i_isolate, function->name());
  // //TFCodeBuilder builder(state.code_assembler_state());
  // MASMCodeBuilder builder;

  // if (function->type() == Function::kNative) {
  //   NativeFunction* native_fn = static_cast<NativeFunction*>(function);
  //   Code* code = builder.BuildCCall(context, native_fn);
  //   codes_.emplace(function->name(), code);
  //   v8::internal::Handle<Code> code_handle = v8::internal::Handle<Code>::New(code, i_isolate);
    
  //   CallInterfaceDescriptor descriptor = v8::internal::CallTrampolineDescriptor(i_isolate);
  //   Callable callable(code_handle, descriptor);
  // }
//}

void V8CodeExecutor::CallHello(ExecutionContext* context) {
  printf("V8CodeExecutor::CallHello\n");
  //v8::HandleScope handle_scope(isolate);
  v8::Isolate* isolate = context->isolate();
  //v8::internal::Isolate* i_isolate = reinterpret_cast<v8::internal::Isolate*>(isolate);
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  //BuilderState state(i_isolate, "hello");
  //TFCodeBuilder builder(state.code_assembler_state());
  MASMCodeBuilder builder;

  Code* code = builder.BuildHelloCall(context);
  if (code) {
    codes_.emplace("hello", code);
  }
  //v8::internal::Handle<Code> code_handle = v8::internal::Handle<Code>::New(code, i_isolate);
  //CallInterfaceDescriptor descriptor = v8::internal::CallTrampolineDescriptor(i_isolate);  
  //Callable callable(code_handle, descriptor);
  printf("V8CodeExecutor::CallHello end\n");
}

}

