// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/execution/v8/v8_code_builder.h"

// v8
#include "src/globals.h"
#include "src/builtins/builtins.h"
#include "src/code-events.h"
//#pragma clang diagnostic push
//#pragma clang diagnostic ignored "-Wunused-variable"
//#include "src/objects-inl.h"
//#include "src/handles-inl.h"
//#pragma clang diagnostic pop
#include "src/handles.h"
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-variable"
#include "src/handles-inl.h"
#pragma clang diagnostic pop
//#include "src/base/logging.h"

//#pragma clang diagnostic push
//#pragma clang diagnostic ignored "-Wmacro-redefined"
#include "core/domain/execution/execution_context.h"
//#pragma clang diagnostic pop
#include "core/domain/execution/native/native_function.h"

using v8::internal::compiler::CodeAssemblerState;
using v8::internal::compiler::Node;
using v8::internal::Address;
using v8::internal::MachineType;
using v8::internal::ExternalReference;
//using v8::internal::HandleScope;
using v8::internal::MacroAssembler;
using v8::internal::CanonicalHandleScope;
using v8::internal::Builtins;
using v8::internal::Code;
using v8::internal::Isolate;
using v8::internal::BuiltinDescriptor;
using v8::internal::CodeStubArguments;

namespace domain {

typedef void (*fn_ptr)(void);

namespace {
void PostBuildProfileAndTracing(Isolate* isolate, Code* code,
                                const char* name) {
  printf("PostBuildProfileAndTracing\n");
  
  //PROFILE(isolate, CodeCreateEvent(v8::internal::CodeEventListener::BUILTIN_TAG,
  //                                 v8::internal::AbstractCode::cast(code), name));
#ifdef ENABLE_DISASSEMBLER
  //if (FLAG_print_builtin_code) {
    //v8::internal::CodeTracer::Scope trace_scope(isolate->GetCodeTracer());
    v8::internal::OFStream os(stdout);//trace_scope.file());
    os << "Builtin: " << name << "\n";
    code->Disassemble(name, os);
    os << "\n";
  //}
#endif
  printf("PostBuildProfileAndTracing end\n");
}

}  

//void Hello(int32_t number) {
//  printf("hello number %d\n", number);
//}

void Hello() {
  printf("hello dude!\n");
}

TFCodeBuilder::TFCodeBuilder(CodeAssemblerState* state):
 v8::internal::CodeStubAssembler(state) {

}

TFCodeBuilder::~TFCodeBuilder() {

}

v8::internal::Code* TFCodeBuilder::BuildHelloCall(ExecutionContext* execution_context) {
  //printf("TFCodeBuilder::BuildHelloCall\n");
  v8::Isolate* isolate = execution_context->isolate();
  v8::Isolate::Scope scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::internal::Isolate* i_isolate = reinterpret_cast<v8::internal::Isolate*>(isolate);
  GenerateHello(i_isolate);
  v8::internal::Handle<Code> code = CodeAssembler::GenerateCode(state());
  CanonicalHandleScope canonical(i_isolate);
  PostBuildProfileAndTracing(i_isolate, *code, "hello");
  
  return *code;
}

void TFCodeBuilder::GenerateHello(v8::internal::Isolate* isolate) {
  v8::internal::HandleScope handle_scope(isolate);

  Label native(this);
  //Label out(this);
  Goto(&native);

  // TODO(ishell): use constants from Descriptor once the JSFunction linkage
  // arguments are reordered.
  //Node* argc = Parameter(BuiltinDescriptor::kArgumentsCount);
  //Node* context = Parameter(BuiltinDescriptor::kContext);
  //Node* new_target = Parameter(BuiltinDescriptor::kNewTarget);
  
  //CodeStubArguments args(this, ChangeInt32ToIntPtr(argc));
  //BranchIfToBooleanIsTrue(args.AtIndex(0), &out, &native);

  BIND(&native);
  {
    Node* hello = ExternalConstant(ExternalReference::Create(FUNCTION_ADDR(Hello)));
    Node* arg0 = Int32Constant(42);
    CallCFunction1(MachineType::AnyTagged(), MachineType::Int32(), hello, arg0);
  }
}

template <typename Functor>
v8::internal::Code* TFCodeBuilder::BuildCCall(ExecutionContext* execution_context, NativeFunction<Functor>* function) {
 //  Label call_native(this);
  
 //  result.Bind(AllocateHeapNumberWithValue(LoadFixedDoubleArrayElement(
 //          elements, IntPtrConstant(0), MachineType::Float64(), 0,
 //          INTPTR_PARAMETERS, &call_native)));

 //  Goto(&call_native);
 //  BIND(&call_native);

 //  int32_t header_size = FixedDoubleArray::kHeaderSize - kHeapObjectTag;
 //  Node* native = //ExternalConstant(ExternalReference::Create(function->function_ptr(), context->isolate()));
 // // ExternalConstant(ExternalReference(Redirect(FUNCTION_ADDR(function->function_ptr()))));
 //   ExternalConstant(ExternalReference(function->function_ptr()));
  
 //  Node* start = IntPtrAdd(
 //          BitcastTaggedToWord(elements),
 //          ElementOffsetFromIndex(IntPtrConstant(0), HOLEY_DOUBLE_ELEMENTS,
 //                                 INTPTR_PARAMETERS, header_size));
 //  CallCFunction3(MachineType::AnyTagged(), MachineType::Pointer(),
 //                 MachineType::Pointer(), MachineType::UintPtr(), native,
 //                 start, IntPtrAdd(start, IntPtrConstant(kDoubleSize)),
 //                 IntPtrMul(new_length, IntPtrConstant(kDoubleSize)));

 //  Node* offset = ElementOffsetFromIndex(new_length, HOLEY_DOUBLE_ELEMENTS,
 //                                        INTPTR_PARAMETERS, header_size); 
 return nullptr;
}

MASMCodeBuilder::MASMCodeBuilder() {}
MASMCodeBuilder::~MASMCodeBuilder() {}

//Code* BuildAdaptor(Isolate* isolate, int32_t builtin_index,
//                   Address builtin_address,
//                   Builtins::ExitFrameType exit_frame_type, const char* name)

template <typename Functor>
v8::internal::Code* MASMCodeBuilder::BuildCCall(ExecutionContext* execution_context, NativeFunction<Functor>* function) {
  // HandleScope scope(isolate);
  // // Canonicalize handles, so that we can share constant namespace entries pointing
  // // to code targets without dereferencing their handles.
  // CanonicalHandleScope canonical(isolate);
  // const size_t buffer_size = 32 * KB;
  // byte buffer[buffer_size];  // NOLINT(runtime/arrays)
  // MacroAssembler masm(isolate, buffer, buffer_size, CodeObjectRequired::kYes);
  // DCHECK(!masm.has_frame());
  // Builtins::Generate_Adaptor(&masm, builtin_address, exit_frame_type);
  // CodeDesc desc;
  // masm.GetCode(isolate, &desc);
  // Handle<Code> code = isolate->factory()->NewCode(
  //     desc, Code::BUILTIN, masm.CodeObject(), builtin_index);
  // PostBuildProfileAndTracing(isolate, *code, name);
  // return *code;
  return nullptr;
}

//Code* BuildAdaptor(Isolate* isolate, int32_t builtin_index,
//                   Address builtin_address,
//                   Builtins::ExitFrameType exit_frame_type, const char* name)

v8::internal::Code* MASMCodeBuilder::BuildHelloCall(ExecutionContext* execution_context) {
  printf("MASMCodeBuilder::BuildHelloCall\n");
  //int builtin_index = 99999;
  v8::Isolate* isolate = execution_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope scope(isolate);
 
  v8::internal::Isolate* i_isolate = reinterpret_cast<v8::internal::Isolate*>(isolate);
  
  printf("isolate ? %d\n", (i_isolate != nullptr));
  printf("after HandleScope\n");
  // Canonicalize handles, so that we can share constant namespace entries pointing
  // to code targets without dereferencing their handles.
  CanonicalHandleScope canonical(i_isolate);
  //printf("after CanonicalHandleScope\n");
  const size_t buffer_size = 32 * v8::internal::KB;
  uint8_t buffer[buffer_size];  // NOLINT(runtime/arrays)
  MacroAssembler masm(i_isolate, buffer, buffer_size, v8::internal::CodeObjectRequired::kYes);
  printf("after masm constructor\n");
  DCHECK(!masm.has_frame());
  Address address = FUNCTION_ADDR(Hello); 
  //Builtins::Generate_Adaptor(&masm, real_address, Builtins::EXIT);
  //printf("after Builtins::Generate_Adaptor\n");
 // v8::internal::Smi* number = v8::internal::Smi::FromInt(42);
  masm.set_has_frame(true);
  masm.EnterFrame(v8::internal::StackFrame::NATIVE);
  masm.PrepareCallCFunction(0);
  //masm.Move(v8::internal::arg_reg_1, number);
  //masm.Push(number);
  masm.CallCFunction(ExternalReference::Create(address), 0);
  masm.LeaveFrame(v8::internal::StackFrame::NATIVE);
  masm.set_has_frame(false);
  
  v8::internal::CodeDesc desc;
  masm.GetCode(i_isolate, &desc);
  v8::internal::Handle<Code> code = i_isolate->factory()->NewCode(
      desc, Code::BUILTIN, masm.CodeObject(), Builtins::kNoBuiltinId);
  PostBuildProfileAndTracing(i_isolate, *code, "hello");
 
  fn_ptr func = reinterpret_cast<fn_ptr>(code->InstructionStart());
  func();

  return *code;
  //return nullptr;
}

}