// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "runtime/MumbaShims/v8/v8_context.h"

#include "base/logging.h"
#include "base/bind.h"
#include "runtime/MumbaShims/v8/v8_script.h"
#include "runtime/MumbaShims/v8/v8_value.h"
#include "runtime/MumbaShims/v8/v8_exception.h"
#include "gin/public/context_holder.h"
#include "gin/public/v8_platform.h"
#include "v8/include/v8.h"
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmacro-redefined"
#include "v8/src/v8.h"
#pragma clang diagnostic pop

namespace mumba {

V8Context::V8Context(v8::Isolate* isolate):
  context_holder_(new gin::ContextHolder(isolate)),
  owned_(true) {
  v8::HandleScope scope(isolate);  
  context_holder_->SetContext(v8::Context::New(isolate));
}

V8Context::V8Context(v8::Isolate* isolate, v8::Local<v8::Context> context, bool owned): 
  context_holder_(new gin::ContextHolder(isolate)),
  owned_(owned) {
  v8::HandleScope handle_scope(isolate);
  if (owned) {
    context_holder_.reset(new gin::ContextHolder(isolate));
    context_holder_->SetContext(context);
  } else {
    context_.Reset(isolate, context);
  }
}

V8Context::V8Context(v8::Isolate* isolate, v8::Local<v8::ObjectTemplate> global):
  context_holder_(new gin::ContextHolder(isolate)),
  owned_(true) {
  v8::HandleScope handle_scope(isolate);
  context_holder_->SetContext(v8::Context::New(isolate, nullptr, global));
}

// V8Context::V8Context(domain::ModuleContext* module_context) {
//   isolate_ = module_context->execution()->isolate();
//   module_context_ = module_context;
//   // trying to fix a bug, where we dont have access to the global
//   // platform inside the loaded module
//   v8::internal::V8::SetPlatformForTesting(gin::V8Platform::Get());
// }

V8Context::~V8Context() {

}

v8::Isolate* V8Context::isolate() const {
  return context_holder_->isolate();
}

v8::Local<v8::Context> V8Context::GetLocal() const {
  return owned_ ? context_holder_->context() : context_.Get(isolate());
}

V8Value* V8Context::ParseAndRun(const char* source, int len) {
  // base::WaitableEvent wait(
  //   base::WaitableEvent::ResetPolicy::AUTOMATIC,
  //   base::WaitableEvent::InitialState::NOT_SIGNALED);

  V8Value* result = nullptr;

  // vm_task_runner_->PostTask(
  //   FROM_HERE, 
  //   base::BindOnce(&V8Context::EvalSourceImpl, 
  //     base::Unretained(this),
  //     source,
  //     base::Unretained(&wait),
  //     base::Unretained(&result)));

  // wait.Wait();
  ParseAndRunImpl(source, len, nullptr, &result);
  return result;
}

// void V8Context::ParseAndRunImpl(const char* source, int len, base::WaitableEvent* wait_event, V8Value** result) {
//   v8::Isolate* isolate = context_holder_->isolate();
//   v8::Isolate::Scope isolate_scope(isolate);
//   v8::HandleScope handle_scope(isolate);

//   v8::Local<v8::String> v8string = v8::String::NewFromUtf8(isolate, source, v8::String::kNormalString, len).ToLocalChecked();

//   // Compile the source code.
//   v8::TryCatch trycatch(isolate);
//   v8::Local<v8::Context> context = owned_ ? context_holder_->context() : context_.Get(isolate);
//   v8::Context::Scope context_scope(context);

//   auto maybe_script = v8::Script::Compile(context, v8string);

//   if (maybe_script.IsEmpty()) {
//     //DLOG(INFO) << "compilation failed. sintax error";
//     //exc.set(isolate, trycatch.Exception());
//     //exc.SetSintaxException(true);
//     if (wait_event) {
//       wait_event->Signal();
//     }
//     return;
//   }

//   v8::Local<v8::Script> script = maybe_script.ToLocalChecked();
//   // Run the script to get the result.
//   auto maybe_result = script->Run(context);

//   // run error
//   if (maybe_result.IsEmpty()) {
//     //DLOG(INFO) << "compilation failed. execute error";
//     //exc.set(isolate, trycatch.Exception());
//     //exc.SetRunException(true);
//     if (wait_event) {
//       wait_event->Signal();
//     }
//     return;
//   }

//   *result = new V8Value(isolate, maybe_result.ToLocalChecked());

//   if (wait_event) {
//     wait_event->Signal();
//   }
// }

void V8Context::ParseAndRunImpl(const char* source, int len, base::WaitableEvent* wait_event, V8Value** result) {
  v8::Isolate* isolate = context_holder_->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);
  
  v8::Local<v8::String> v8string = v8::String::NewFromUtf8(isolate, source, v8::String::kNormalString, len);

  // Compile the source code.
  v8::TryCatch trycatch(isolate);
  v8::Local<v8::Context> context = owned_ ? context_holder_->context() : context_.Get(isolate);
  v8::Context::Scope context_scope(context);
  
  std::string script_name("unnamed");
  v8::Local<v8::String> v8_script_name = v8::String::NewFromUtf8(isolate, script_name.c_str(), v8::String::kNormalString, script_name.size());
  v8::ScriptOrigin origin(v8_script_name);
  v8::ScriptCompiler::Source src_code(v8string, origin);
  auto maybe_script = v8::ScriptCompiler::Compile(context, &src_code);

  if (maybe_script.IsEmpty()) {
    //DLOG(INFO) << "compilation failed. No Script object returned. (sintax error?)";
    //exc.set(isolate, trycatch.Exception());
    //exc.SetSintaxException(true);
    if (wait_event) {
      wait_event->Signal();
    }
    return;
  }

  v8::Local<v8::Script> script = maybe_script.ToLocalChecked();
  // Run the script to get the result.
  auto maybe_result = script->Run(context);

  // run error
  if (maybe_result.IsEmpty()) {
    v8::String::Utf8Value error_message(isolate, trycatch.Message()->Get());
    //DLOG(INFO) << "compilation failed. execute error: " << *error_message;
    //exc.set(isolate, trycatch.Exception());
    //exc.SetRunException(true);
    if (wait_event) {
      wait_event->Signal();
    }
    return;
  }

  *result = new V8Value(isolate, maybe_result.ToLocalChecked());

  if (wait_event) {
    wait_event->Signal();
  }
}

// V8Script* V8Context::CompileFromString(v8::Isolate* isolate, const V8Value* str, V8Exception& exc) {
//  //v8::Isolate::Scope isolate_scope(isolate);
//  //DLOG(INFO) << "V8Context::CompileFromString";
//  v8::HandleScope handle_scope(isolate);

//  //DLOG(INFO) << "v8::String::NewFromOneByte";
//  auto source = v8::String::NewFromOneByte(isolate, reinterpret_cast<const uint8_t *>(str), v8::NewStringType::kNormal).ToLocalChecked();

//  // Compile the source code.
//  v8::TryCatch trycatch(isolate);

//  //DLOG(INFO) << "context_.Get";
//  v8::Local<v8::Context> context = context_holder_->context();
//  //DLOG(INFO) << "v8::Context::Scope context_scope";
//  v8::Context::Scope context_scope(context);
//  //DLOG(INFO) << "compilation = v8::Script::Compile";
 
//  auto compilation = v8::Script::Compile(context, source);

//  // syntax error
//  if (compilation.IsEmpty()) {
//   //DLOG(INFO) << "compilation.IsEmpty = true";
//   exc.set(isolate, trycatch.Exception());
//   exc.SetSintaxException(true);
//   return nullptr;
//  }

//  //DLOG(INFO) << "return new V8Script .. compilation.ToLocalChecked()";
//  return new V8Script(isolate, compilation.ToLocalChecked());
// }

// V8Value* V8Context::ExecuteScript(v8::Isolate* isolate, const V8Script* script, V8Exception& exc) {
//  v8::Isolate::Scope isolate_scope(isolate);
//  v8::HandleScope handle_scope(isolate);
//  v8::Local<v8::Context> context = context_holder_->context();//context_.Get(isolate);

//  v8::Context::Scope context_scope(context);

//  v8::Local<v8::Script> v8script = script->GetLocal(isolate);

//  v8::TryCatch trycatch(isolate);

//  // Run the script to get the result.
//  auto result = v8script->Run(context);

//  // run error
//  if (result.IsEmpty()) {
//   exc.set(isolate, trycatch.Exception());
//   exc.SetRunException(true);
//   return nullptr;
//  }

//  return new V8Value(isolate, result.ToLocalChecked());
// }

}