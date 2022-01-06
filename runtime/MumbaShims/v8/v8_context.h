// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_V8_ONTEXT_H__
#define MUMBA_RUNTIME_MUMBA_SHIMS_V8_ONTEXT_H__

#include "base/macros.h"
#include "base/single_thread_task_runner.h"
#include "base/synchronization/waitable_event.h"
#include "v8/include/v8.h"

namespace domain {
class ModuleContext;  
}

namespace gin {
class ContextHolder;
}

namespace mumba {

class V8Value;
class V8Script;
class V8Exception;

class V8Context {
public:
 V8Context(v8::Isolate* isolate);
 V8Context(v8::Isolate* isolate, v8::Local<v8::Context> context, bool owned = false);
 V8Context(v8::Isolate* isolate, v8::Local<v8::ObjectTemplate> global);
 //V8Context(domain::ModuleContext* module_context);
 ~V8Context();

 v8::Isolate* isolate() const;// { return isolate_; }

 // domain::ModuleContext* module_context() const {
 //    return module_context_;
 // }

 v8::Local<v8::Context> GetLocal() const;// { return context_.Get(isolate); }

 // warning: the return values are heap allocated and are
 // the responsability of the caller to be cleaned up
 //V8Script* CompileFromString(v8::Isolate* isolate, const V8Value* string, V8Exception& exc);
 //V8Value* ExecuteScript(v8::Isolate* isolate, const V8Script* script, V8Exception& exc);

 // synchronous version
 V8Value* ParseAndRun(const char* source, int len);

private:
 
 void ParseAndRunImpl(const char* source, int len, base::WaitableEvent* wait_event, V8Value** result);

 //v8::Isolate* isolate_;
 //domain::ModuleContext* module_context_;
 std::unique_ptr<gin::ContextHolder> context_holder_;
 //scoped_refptr<base::SingleThreadTaskRunner> vm_task_runner_;
 v8::Global<v8::Context> context_;

 bool owned_;

 DISALLOW_COPY_AND_ASSIGN(V8Context);
};

}

#endif