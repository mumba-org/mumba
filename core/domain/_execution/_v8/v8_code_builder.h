// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_EXECUTION_V8_V8_CODE_BUILDER_H_
#define MUMBA_DOMAIN_EXECUTION_V8_V8_CODE_BUILDER_H_

//#ifdef _DEBUG
//#define DEBUG
//#endif 
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmacro-redefined"
#include "src/base/macros.h"
#include "src/allocation.h"
#include "src/builtins/builtins.h"
#include "src/globals.h"
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wundefined-inline"
#include "src/code-stub-assembler.h"
#pragma clang diagnostic pop
#pragma clang diagnostic pop

namespace domain {
class ExecutionContext;

template <typename Functor>
class NativeFunction;

// class V8CodeBuilder {
// public:
//   virtual ~V8CodeBuilder() {}
//   template <typename Functor>
//   virtual v8::internal::Code* BuildCCall(ExecutionContext* context, NativeFunction<Functor>* function) = 0;
//   virtual v8::internal::Code* BuildHelloCall(ExecutionContext* context) = 0;
// };

class TFCodeBuilder : //public V8CodeBuilder,
                      public v8::internal::CodeStubAssembler {
public:
  TFCodeBuilder(v8::internal::compiler::CodeAssemblerState* state);
  ~TFCodeBuilder(); //override;

  template <typename Functor>
  v8::internal::Code* BuildCCall(ExecutionContext* execution_context, NativeFunction<Functor>* function); //override;
  
  v8::internal::Code* BuildHelloCall(ExecutionContext* execution_context); //override;

private:

  void GenerateHello(v8::internal::Isolate* isolate);

  DISALLOW_COPY_AND_ASSIGN(TFCodeBuilder);
};

class MASMCodeBuilder {//: public V8CodeBuilder {
public:
  MASMCodeBuilder();
  ~MASMCodeBuilder();// override;

  template <typename Functor>
  v8::internal::Code* BuildCCall(ExecutionContext* execution_context, NativeFunction<Functor>* function);// override;
  
  v8::internal::Code* BuildHelloCall(ExecutionContext* execution_context); //override;

private:

  DISALLOW_COPY_AND_ASSIGN(MASMCodeBuilder);
};

}

#endif