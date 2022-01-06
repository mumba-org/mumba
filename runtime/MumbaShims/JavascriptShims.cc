// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "JavascriptShims.h"

#include "base/command_line.h"
#include "runtime/MumbaShims/v8/v8_engine.h"
#include "runtime/MumbaShims/v8/v8_context.h"
#include "runtime/MumbaShims/v8/v8_value.h"
#include "runtime/MumbaShims/v8/v8_exception.h"
#include "runtime/MumbaShims/v8/v8_script.h"
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-variable"
#include "src/api.h"
#include "src/objects-inl.h"
#include "src/snapshot/code-serializer.h"
#include "src/version.h"
#include "src/wasm/module-decoder.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-memory.h"
#include "src/wasm/wasm-module-builder.h"
#include "src/wasm/wasm-module.h"
#include "src/wasm/wasm-objects-inl.h"
#include "src/wasm/wasm-opcodes.h"
#include "src/property-descriptor.h"
#pragma clang diagnostic pop

class V8FunctionHandler {
public:
  v8::Isolate* isolate_; 
  void* state_;
  void(*callback_)(void*, JavascriptFunctionCallbackInfoRef);
  v8::Global<v8::External> wrapper_;
  
  V8FunctionHandler(v8::Isolate* isolate, void* state, void(*callback)(void*, JavascriptFunctionCallbackInfoRef)):
    isolate_(isolate),
    state_(state),
    callback_(callback),
    wrapper_(isolate,
            v8::External::New(isolate, this)) {
    wrapper_.SetWeak(this, Cleanup, v8::WeakCallbackType::kParameter);
  }

  static void Cleanup(
      const v8::WeakCallbackInfo<V8FunctionHandler>& data) {
    //DLOG(INFO) << "V8FunctionHandler::Cleanup";
    if (!data.GetParameter()->wrapper_.IsEmpty()) {
      data.GetParameter()->wrapper_.Reset();
      data.SetSecondPassCallback(Cleanup);
    } else {
      delete data.GetParameter();
    }
  }
  
};

static void V8FunctionCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
  //DLOG(INFO) << "V8FunctionCallback called";
  V8FunctionHandler* handler = static_cast<V8FunctionHandler*>(
    info.Data().As<v8::External>()->Value());
  DCHECK(handler);
  DCHECK(handler->callback_);
  
  //DLOG(INFO) << "V8FunctionCallback: handler = " << handler;

  // call function
  handler->callback_(handler->state_, const_cast<v8::FunctionCallbackInfo<v8::Value> *>(&info));
  // we dont need the wrapper anymore
  //delete handler;
}
// JsRuntime
// JsEngineRef _JavascriptEngineCreate() {
//   if (!base::CommandLine::InitializedForCurrentProcess()) {
//     base::CommandLine::Init(0, nullptr);
//   }
//   return new mumba::V8Engine();//::GetInstance();
// }

// int _JavascriptEngineInit(JsEngineRef engine) {
//  return reinterpret_cast<mumba::V8Engine *>(engine)->Init() ? 1 : 0; 
// }

// void _JavascriptEngineShutdown(JsEngineRef engine) {
//  reinterpret_cast<mumba::V8Engine *>(engine)->Shutdown();
// }

// JavascriptContextRef _JavascriptEngineCreateContext(JsEngineRef engine) {
//   return reinterpret_cast<mumba::V8Engine *>(engine)->CreateContext();
// }

// JsEngineRef _JavascriptEngineGetCurrent() {
//   mumba::V8Engine* engine = mumba::V8Engine::GetInstance();
//   return engine;
// }

 // JsContext
JavascriptContextRef _JavascriptContextGetCurrent() {
//   mumba::V8Engine* engine = mumba::V8Engine::GetInstance();
//   v8::Isolate* isolate = engine->isolate();
//   if (!isolate->InContext()) {
//     return engine->CreateContext();
//   }
   v8::Isolate* isolate = v8::Isolate::GetCurrent();
   v8::Isolate::Scope isolate_scope(isolate);
   v8::HandleScope handle_scope(isolate);
   return new mumba::V8Context(isolate, isolate->GetCurrentContext());
}

JavascriptDataRef _JavascriptContextGetGlobal(JavascriptContextRef context) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);
  v8::Local<v8::Context> v8_context = i_context->GetLocal();
  return new mumba::V8Value(isolate, v8_context->Global());
}

//JavascriptContextRef _JavascriptContextCreateFromModuleContext(ModuleContextRef module) {
  //DLOG(INFO) << "_JavascriptContextCreateFromModuleContext";
 // domain::ModuleContext* module_context = reinterpret_cast<domain::ModuleContext*>(module);
  //return new mumba::V8Context(module_context);
//}

void _JavascriptContextDestroy(JavascriptContextRef context) {
  //delete reinterpret_cast<mumba::V8Context *>(context);
}

// JavascriptScriptRef _JavascriptContextParseScriptUTF8(JavascriptContextRef context, const char* source) {
//   return nullptr;
// }

// JavascriptDataRef _JavascriptContextExecuteScript(JavascriptContextRef context, JavascriptScriptRef source) {
//   return nullptr;
// }

JavascriptDataRef _JavascriptContextParseAndRunUTF8(JavascriptContextRef context, const char* source, int len) {
  mumba::V8Context* v8_context = reinterpret_cast<mumba::V8Context *>(context);
  return v8_context->ParseAndRun(source, len);
}

void _JavascriptDataDestroy(JavascriptDataRef handle) {
  // for now we should not do this
  // until we solve the problem of v8::Persistent<> destructor

  //delete reinterpret_cast<mumba::V8Data *>(handle); 
}

// JsValue
int _JavascriptValueIsUndefined(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent(); 
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsUndefined() ?  1 : 0;
}

int _JavascriptValueIsNull(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent(); 
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate); 
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsNull() ? 1 : 0;
}

int _JavascriptValueIsTrue(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent(); 
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);  
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsTrue() ? 1 : 0;
}

int _JavascriptValueIsFalse(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent(); 
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);  
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsFalse() ? 1 : 0;
}

int _JavascriptValueIsName(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent(); 
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);  
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsName() ? 1 : 0;
}

int _JavascriptValueIsSymbol(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);  
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsSymbol() ? 1 : 0;
}

int _JavascriptValueIsString(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent(); 
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);  
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsString() ? 1 : 0;
}

int _JavascriptValueIsFunction(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);  
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsFunction() ? 1 : 0;
}

int _JavascriptValueIsArray(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);  
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsArray() ? 1 : 0;
}

int _JavascriptValueIsObject(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);  
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsObject() ? 1 : 0;
}

int _JavascriptValueIsBool(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);  
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsBoolean() ? 1 : 0;
}

int _JavascriptValueIsNumber(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate(); 
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);  
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsNumber() ? 1 : 0;
}

int _JavascriptValueIsInt32(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate(); 
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);  
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsInt32() ? 1 : 0;
}

int _JavascriptValueIsUInt32(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate(); 
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);  
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsUint32() ? 1 : 0;
}

int _JavascriptValueIsDate(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);  
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsDate() ? 1 : 0;
}

int _JavascriptValueIsMap(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);  
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsMap() ? 1 : 0;
} 

int _JavascriptValueIsSet(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate(); 
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);  
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsSet() ? 1 : 0;
}

int _JavascriptValueIsArgumentsObject(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate(); 
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);  
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsArgumentsObject() ? 1 : 0;
}

int _JavascriptValueIsBooleanObject(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate(); 
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);  
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsBooleanObject() ? 1 : 0;
}

int _JavascriptValueIsNumberObject(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate(); 
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);  
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsNumberObject() ? 1 : 0;
}

int _JavascriptValueIsStringObject(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);  
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsStringObject() ? 1 : 0;
}

int _JavascriptValueIsSymbolObject(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate(); 
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);  
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsSymbolObject() ? 1 : 0;
}

int _JavascriptValueIsNativeError(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate(); 
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate); 

 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsNativeError() ? 1 : 0;
}

int _JavascriptValueIsRegExp(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate(); 
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);  
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsRegExp() ? 1 : 0;
}

int _JavascriptValueIsGeneratorFunction(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate(); 
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate); 
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsGeneratorFunction() ? 1 : 0;
}

int _JavascriptValueIsGeneratorObject(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate(); 
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsGeneratorObject() ? 1 : 0;
}

int _JavascriptValueIsPromise(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate(); 
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsPromise() ? 1 : 0;
}

int _JavascriptValueIsMapIterator(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate(); 
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsMapIterator() ? 1 : 0;
}

int _JavascriptValueIsSetIterator(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate(); 
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsSetIterator() ? 1 : 0;
}

int _JavascriptValueIsWeakMap(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsWeakMap() ? 1 : 0;
}

int _JavascriptValueIsWeakSet(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate(); 
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsWeakSet() ? 1 : 0;
}

int _JavascriptValueIsArrayBuffer(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate(); 
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsArrayBuffer() ? 1 : 0;
}

int _JavascriptValueIsArrayBufferView(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate(); 
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsArrayBufferView() ? 1 : 0;
}

int _JavascriptValueIsTypedArray(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate(); 
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsTypedArray() ? 1 : 0;
}

int _JavascriptValueIsUInt8Array(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate(); 
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsUint8Array() ? 1 : 0;
}

int _JavascriptValueIsUInt8ClampedArray(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate(); 
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsUint8ClampedArray() ? 1 : 0;
}

int _JavascriptValueIsInt8Array(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate(); 
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsInt8Array() ? 1 : 0;
}

int _JavascriptValueIsUInt16Array(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate(); 
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsUint16Array() ? 1 : 0;
}

int _JavascriptValueIsInt16Array(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate(); 
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsInt16Array() ? 1 : 0;
}

int _JavascriptValueIsUInt32Array(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate(); 
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);
 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsUint32Array() ? 1 : 0;
}

int _JavascriptValueIsInt32Array(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate(); 
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsInt32Array() ? 1 : 0;
}

int _JavascriptValueIsFloat32Array(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate(); 
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsFloat32Array() ? 1 : 0;
}

int _JavascriptValueIsFloat64Array(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate(); 
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsFloat64Array() ? 1 : 0;
}

int _JavascriptValueIsDataView(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent(); 
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsDataView() ? 1 : 0;
}

int _JavascriptValueIsSharedArrayBuffer(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent(); 
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return value->IsSharedArrayBuffer() ? 1 : 0;
}

int _JavascriptValueIsEqual(JavascriptContextRef context, JavascriptDataRef left, JavascriptDataRef right) {
  //v8::Isolate* isolate = v8::Isolate::GetCurrent();
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate(); 
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);
  
  v8::Local<v8::Value> lhs = reinterpret_cast<mumba::V8Value *>(left)->GetLocal(isolate);
  v8::Local<v8::Value> rhs = reinterpret_cast<mumba::V8Value *>(right)->GetLocal(isolate);

  return lhs->Equals(rhs) ? 1 : 0;
}

JavascriptDataRef _JavascriptValueCreateNull(JavascriptContextRef context) {
  //v8::Isolate* isolate = v8::Isolate::GetCurrent();
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);
  
  v8::Local<v8::Primitive> v8value = v8::Null(isolate);
  return new mumba::V8Value(isolate, v8value);
}

JavascriptDataRef _JavascriptValueCreateUndefined(JavascriptContextRef context) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  //v8::Isolate* isolate = v8::Isolate::GetCurrent(); 
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);
  
  v8::Local<v8::Primitive> v8value = v8::Undefined(isolate);
  return new mumba::V8Value(isolate, v8value);
}

char* _JavascriptValueToString(JavascriptContextRef context, JavascriptDataRef handle, int* out_len) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);
  
  v8::Local<v8::Context> v8context = i_context->GetLocal();
  v8::Context::Scope context_scope(v8context);

  v8::Local<v8::Value> value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  v8::Local<v8::String> str = value->ToString(v8context).ToLocalChecked();

  v8::String::Utf8Value str_value(isolate, str);
  char* result = reinterpret_cast<char *>(malloc(str_value.length()));
  memcpy(result, *str_value, str_value.length());
  
  *out_len = str_value.length();
  
  return result;
}

// JsBoolean
int _JavascriptBooleanCanCast(JavascriptContextRef context, JavascriptDataRef handle) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 //v8::Isolate* isolate = v8::Isolate::GetCurrent(); 
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate); 

 v8::Local<v8::Value> v8value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 
 return v8value->IsBoolean() || v8value->IsTrue() || v8value->IsFalse() ? 1 : 0;
}

int _JavascriptBooleanGetValue(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);
 
 v8::Local<v8::Value> v8value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 v8::Local<v8::Context> v8context = i_context->GetLocal();
 
 v8::Context::Scope context_scope(v8context);

 auto result = v8value->BooleanValue(v8context);
 return result.FromJust() ? 1 : 0;
}

JavascriptDataRef _JavascriptBooleanNew(JavascriptContextRef context, int value) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);
 
 v8::Local<v8::Boolean> v8bool = v8::Boolean::New(isolate, value == 0 ? false : true);
 
 return new mumba::V8Value(isolate, v8bool);
}

// JsName
int _JavascriptNameGetIdentityHash(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate(); 
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::Local<v8::Value> v8value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return v8value.As<v8::Name>()->GetIdentityHash();
}

int _JavascriptNameCanCast(JavascriptContextRef context, JavascriptDataRef handle) {
 return _JavascriptValueIsName(context, handle);
}

// JsString
const char* _JavascriptStringGetValue(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);
 v8::Local<v8::Value> v8value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 v8::String::Utf8Value result(isolate, v8value);
 return *result;
}

int _JavascriptStringGetLenght(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::Local<v8::Value> v8value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return v8value.As<v8::String>()->Length();
}

int _JavascriptStringUTF8Length(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::Local<v8::Value> v8value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return v8value.As<v8::String>()->Utf8Length();
}

int _JavascriptStringIsOneByte(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate(); 
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::Local<v8::Value> v8value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate); 
 return v8value.As<v8::String>()->IsOneByte();
}

int _JavascriptStringContainsOnlyOneByte(JavascriptContextRef context, JavascriptDataRef handle) {
  //v8::Isolate* isolate = v8::Isolate::GetCurrent();
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Value> v8value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  return v8value.As<v8::String>()->ContainsOnlyOneByte();
}

int _JavascriptStringCanCast(JavascriptContextRef context, JavascriptDataRef handle) {
 return _JavascriptValueIsString(context, handle);
}

JavascriptDataRef _JavascriptStringCreateFromCString(JavascriptContextRef context, const char* string, int lenght) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate(); 
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::MaybeLocal<v8::String> v8string = v8::String::NewFromUtf8(isolate, string, v8::String::kNormalString, lenght);
 
 if (v8string.IsEmpty()) {
   //DLOG(INFO) << " maybe string is empty. returning null";
   return nullptr;
 }

 return new mumba::V8Value(isolate, v8string.ToLocalChecked());
}

int _JavascriptStringWrite(JavascriptContextRef context, JavascriptDataRef handle, uint16_t* buffer, int start, int length) {
  //v8::Isolate* isolate = v8::Isolate::GetCurrent();
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate(); 
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Value> v8value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  return v8value.As<v8::String>()->Write(buffer, start, length);
}

int _JavascriptStringWriteOneByte(JavascriptContextRef context, JavascriptDataRef handle, uint8_t* buffer, int start, int length) {
  //v8::Isolate* isolate = v8::Isolate::GetCurrent();
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate(); 
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Value> v8value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  return v8value.As<v8::String>()->WriteOneByte(buffer, start, length);
}

int _JavascriptStringWriteUTF8(JavascriptContextRef context, JavascriptDataRef handle, char* buffer, int length) {
  //v8::Isolate* isolate = v8::Isolate::GetCurrent();
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate(); 
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Value> v8value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  
  return v8value.As<v8::String>()->WriteUtf8(buffer, length);
}
     
// JsNumber
double _JavascriptNumberGetValue(JavascriptContextRef context, JavascriptDataRef handle) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context); 
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);
 
 v8::Local<v8::Value> v8value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 v8::Local<v8::Context> v8context = i_context->GetLocal();
 
 v8::Context::Scope context_scope(v8context);
 
 auto result = v8value->NumberValue(v8context);
 
 return result.FromJust();
}

int _JavascriptNumberCanCast(JavascriptContextRef context, JavascriptDataRef handle) {
  return _JavascriptValueIsNumber(context, handle);
}

JavascriptDataRef _JavascriptNumberNew(JavascriptContextRef context, double value) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);
 
  v8::Local<v8::Number> v8num = v8::Number::New(isolate, value);
 
  return new mumba::V8Value(isolate, v8num);
}

// JsInteger

JavascriptDataRef _JavascriptIntegerNew(JavascriptContextRef context, int64_t value) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);
 
  v8::Local<v8::Integer> v8integer = v8::Integer::New(isolate, value);
 
  return new mumba::V8Value(isolate, v8integer);
}

int64_t _JavascriptIntegerGetValue(JavascriptContextRef context, JavascriptDataRef handle) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);
 
 v8::Local<v8::Value> v8value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 v8::Local<v8::Context> v8context = i_context->GetLocal();
 
 v8::Context::Scope context_scope(v8context);
 
 auto result = v8value->IntegerValue(v8context);
 return result.FromJust();
}

int _JavascriptIntegerCanCast(JavascriptContextRef context, JavascriptDataRef handle) {
 return _JavascriptValueIsNumber(context, handle);
}

// JsInt32
int _JavascriptInt32GetValue(JavascriptContextRef context, JavascriptDataRef handle) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);
 
 v8::Local<v8::Value> v8value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 v8::Local<v8::Context> v8context = i_context->GetLocal();
 
 v8::Context::Scope context_scope(v8context);

 auto result = v8value->Int32Value(v8context);
 return result.FromJust();
}

int _JavascriptInt32CanCast(JavascriptContextRef context, JavascriptDataRef handle) {
 return _JavascriptValueIsInt32(context, handle);
}

// JsUInt32
uint32_t _JavascriptUInt32GetValue(JavascriptContextRef context, JavascriptDataRef handle) { 
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);
 
 v8::Local<v8::Value> v8value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 v8::Local<v8::Context> v8context = i_context->GetLocal();
 
 v8::Context::Scope context_scope(v8context);
 
 auto result = v8value->Uint32Value(v8context);
 return result.FromJust();
}

int _JavascriptUInt32CanCast(JavascriptContextRef context, JavascriptDataRef handle) {
 return _JavascriptValueIsUInt32(context, handle);
}

// JsObject
int _JavascriptObjectGetIdentityHash(JavascriptContextRef context, JavascriptDataRef handle) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate(); 
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Value> v8value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  return v8value.As<v8::Object>()->GetIdentityHash();
}

int _JavascriptObjectIsCallable(JavascriptContextRef context, JavascriptDataRef handle) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate(); 
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Value> v8value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  return v8value.As<v8::Object>()->IsCallable() ? 1 : 0;
}

JavascriptDataRef _JavascriptObjectGetPropertyNames(JavascriptDataRef context, JavascriptDataRef handle) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Value> v8value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  v8::Local<v8::Context> v8context = reinterpret_cast<mumba::V8Context *>(context)->GetLocal();
  
  v8::Context::Scope context_scope(v8context);

  v8::MaybeLocal<v8::Array> array = v8value.As<v8::Object>()->GetPropertyNames(v8context);
  
  if (array.IsEmpty()) {
    return nullptr;
  }

  return new mumba::V8Value(isolate, array.ToLocalChecked());
}

JavascriptDataRef _JavascriptObjectGetPrototype(JavascriptContextRef context, JavascriptDataRef handle) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate(); 
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Value> v8value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  v8::Local<v8::Value> prototype = v8value.As<v8::Object>()->GetPrototype();
  return new mumba::V8Value(isolate, prototype);
}

JavascriptDataRef  _JavascriptObjectGetObjectProtoString(JavascriptContextRef context, JavascriptDataRef handle) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate(); 
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Context> v8context = i_context->GetLocal();
  v8::Local<v8::Value> v8value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  
  v8::Context::Scope context_scope(v8context);
  v8::MaybeLocal<v8::String> proto_string = v8value.As<v8::Object>()->ObjectProtoToString(v8context);
  
  if (proto_string.IsEmpty()) {
    return nullptr;
  }

  return new mumba::V8Value(isolate, proto_string.ToLocalChecked());
}

JavascriptDataRef _JavascriptObjectGetConstructorName(JavascriptContextRef context, JavascriptDataRef handle) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate(); 
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Value> v8value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  v8::Local<v8::String> constructor = v8value.As<v8::Object>()->GetConstructorName();
  
  return new mumba::V8Value(isolate, constructor);
}

int _JavascriptObjectGetInternalFieldCount(JavascriptContextRef context, JavascriptDataRef handle) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate(); 
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Value> v8value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  return v8value.As<v8::Object>()->InternalFieldCount();
}

JavascriptDataRef _JavascriptObjectGetInternalField(JavascriptContextRef context, JavascriptDataRef handle, int index) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);
  
  v8::Local<v8::Value> v8value = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  v8::Local<v8::Value> field = v8value.As<v8::Object>()->GetInternalField(index);

  if (field->IsNull() || field->IsUndefined()){
    return nullptr;
  }

  return new mumba::V8Value(isolate, field);
}

void _JavascriptObjectSetInternalField(JavascriptContextRef context, JavascriptDataRef handle, int index, JavascriptDataRef value) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate(); 
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);
  
  v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  v8::Local<v8::Value> v8field = reinterpret_cast<mumba::V8Value *>(value)->GetLocal(isolate);
  
  v8handle.As<v8::Object>()->SetInternalField(index, v8field);
}

int _JavascriptObjectCanCast(JavascriptContextRef context, JavascriptDataRef handle) {
  return _JavascriptValueIsObject(context, handle);
}

int _JavascriptObjectCreateDataProperty(JavascriptContextRef context, JavascriptDataRef handle, JavascriptDataRef key, JavascriptDataRef value) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate(); 
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Context> v8context = reinterpret_cast<mumba::V8Context *>(context)->GetLocal();
  v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  v8::Local<v8::Value> v8key = reinterpret_cast<mumba::V8Value *>(key)->GetLocal(isolate);
  v8::Local<v8::Value> v8value = reinterpret_cast<mumba::V8Value *>(value)->GetLocal(isolate);

  v8::Context::Scope context_scope(v8context);
  v8::Maybe<bool> result = v8handle.As<v8::Object>()->CreateDataProperty(v8context, v8key.As<v8::Name>(), v8value);
  
  if (result.IsNothing()) {
    return -1;
  }

  return result.FromJust() ? 1 : 0;
}

int _JavascriptObjectCreateDataPropertyByIndex(JavascriptContextRef context, JavascriptDataRef handle, int index, JavascriptDataRef value) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate(); 
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Context> v8context = reinterpret_cast<mumba::V8Context *>(context)->GetLocal();
  v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  v8::Local<v8::Value> v8value = reinterpret_cast<mumba::V8Value *>(value)->GetLocal(isolate);
  
  v8::Context::Scope context_scope(v8context); 
  v8::Maybe<bool> result = v8handle.As<v8::Object>()->CreateDataProperty(v8context, index, v8value);

  if (result.IsNothing()) {
    return -1;
  }

  return result.FromJust() ? 1 : 0;
}

JavascriptDataRef _JavascriptObjectGetProperty(JavascriptContextRef context, JavascriptDataRef handle, JavascriptDataRef key) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate(); 
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);
  
  v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  v8::Local<v8::Context> v8context = reinterpret_cast<mumba::V8Context *>(context)->GetLocal();
  v8::Local<v8::Value> v8key = reinterpret_cast<mumba::V8Value *>(key)->GetLocal(isolate);
  
  v8::Context::Scope context_scope(v8context);
  v8::MaybeLocal<v8::Value> result = v8handle.As<v8::Object>()->Get(v8context, v8key);
  
  if(result.IsEmpty()) {
    return nullptr;
  }

  return new mumba::V8Value(isolate, result.ToLocalChecked());
}

JavascriptDataRef _JavascriptObjectGetPropertyByIndex(JavascriptContextRef context, JavascriptDataRef handle, int index) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate(); 
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);
  
  v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  v8::Local<v8::Context> v8context = reinterpret_cast<mumba::V8Context *>(context)->GetLocal();
  
  v8::Context::Scope context_scope(v8context);
  v8::MaybeLocal<v8::Value> result = v8handle.As<v8::Object>()->Get(v8context, index);
  
  if(result.IsEmpty()) {
    return nullptr;
  }

  return new mumba::V8Value(isolate, result.ToLocalChecked());
}

int _JavascriptObjectSetProperty(JavascriptContextRef context, JavascriptDataRef handle, JavascriptDataRef key, JavascriptDataRef value) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate(); 
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Context> v8context = i_context->GetLocal();
  v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  v8::Local<v8::Value> v8key = reinterpret_cast<mumba::V8Value *>(key)->GetLocal(isolate);
  v8::Local<v8::Value> v8value = reinterpret_cast<mumba::V8Value *>(value)->GetLocal(isolate);

  v8::Context::Scope context_scope(v8context);

  v8::Maybe<bool> result = v8handle.As<v8::Object>()->Set(v8context, v8key, v8value);

  if(result.IsNothing()) {
    return -1;
  }
  return result.FromJust() ? 1 : 0;
}

int _JavascriptObjectSetPropertyByIndex(JavascriptContextRef context, JavascriptDataRef handle, int index, JavascriptDataRef value) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate(); 
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Context> v8context = i_context->GetLocal();
  v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  v8::Local<v8::Value> v8value = reinterpret_cast<mumba::V8Value *>(value)->GetLocal(isolate);

  v8::Context::Scope context_scope(v8context);

  v8::Maybe<bool> result = v8handle.As<v8::Object>()->Set(v8context, index, v8value);

  if(result.IsNothing()) {
    return -1;
  }
  return result.FromJust() ? 1 : 0;
}

int _JavascriptObjectHasProperty(JavascriptContextRef context, JavascriptDataRef handle, JavascriptDataRef key) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Context> v8context = i_context->GetLocal();
  v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  v8::Local<v8::Value> v8key = reinterpret_cast<mumba::V8Value *>(key)->GetLocal(isolate);

  v8::Context::Scope context_scope(v8context);

  v8::Maybe<bool> result = v8handle.As<v8::Object>()->Has(v8context, v8key);
  
  if(result.IsNothing()) {
    return -1;
  }

  return result.FromJust() ? 1 : 0;
}

int _JavascriptObjectHasPropertyByIndex(JavascriptContextRef context, JavascriptDataRef handle, int index) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Context> v8context = i_context->GetLocal();
  v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);

  v8::Context::Scope context_scope(v8context);

  v8::Maybe<bool> result = v8handle.As<v8::Object>()->Has(v8context, index);
  
  if(result.IsNothing()) {
    return -1;
  }

  return result.FromJust() ? 1 : 0;
}

int _JavascriptObjectDeleteProperty(JavascriptContextRef context, JavascriptDataRef handle, JavascriptDataRef key) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Context> v8context = i_context->GetLocal();
  v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  v8::Local<v8::Value> v8key = reinterpret_cast<mumba::V8Value *>(key)->GetLocal(isolate);

  v8::Context::Scope context_scope(v8context);

  v8::Maybe<bool> result = v8handle.As<v8::Object>()->Delete(v8context, v8key);
  
  if(result.IsNothing()) {
    return -1;
  }

  return result.FromJust() ? 1 : 0;
}

int _JavascriptObjectDeletePropertyByIndex(JavascriptContextRef context, JavascriptDataRef handle, int index) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Context> v8context = i_context->GetLocal();
  v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);

  v8::Context::Scope context_scope(v8context);

  v8::Maybe<bool> result = v8handle.As<v8::Object>()->Delete(v8context, index);
  
  if(result.IsNothing()) {
    return -1;
  }

  return result.FromJust() ? 1 : 0;
}

JavascriptDataRef _JavascriptObjectFindInstanceInPrototypeChain(JavascriptContextRef context, JavascriptDataRef handle, JavascriptFunctionTemplateRef templ) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  v8::Local<v8::FunctionTemplate> v8templ = reinterpret_cast<mumba::V8FunctionTemplate *>(templ)->GetLocal(isolate);
  v8::Local<v8::Object> object = v8handle.As<v8::Object>()->FindInstanceInPrototypeChain(v8templ);
  
  return new mumba::V8Value(isolate, object);
}

int _JavascriptObjectHasOwnProperty(JavascriptContextRef context, JavascriptDataRef handle, JavascriptDataRef key) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Context> v8context = i_context->GetLocal();
  v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  v8::Local<v8::Value> v8key = reinterpret_cast<mumba::V8Value *>(key)->GetLocal(isolate);

  v8::Context::Scope context_scope(v8context);

  v8::Maybe<bool> result = v8handle.As<v8::Object>()->HasOwnProperty(v8context, v8key.As<v8::Name>());
  
  if(result.IsNothing()) {
    return -1;
  }

  return result.FromJust() ? 1 : 0;  
}

int _JavascriptObjectHasRealNamedProperty(JavascriptContextRef context, JavascriptDataRef handle, JavascriptDataRef key) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Context> v8context = i_context->GetLocal();
  v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  v8::Local<v8::Value> v8key = reinterpret_cast<mumba::V8Value *>(key)->GetLocal(isolate);

  v8::Context::Scope context_scope(v8context);

  v8::Maybe<bool> result = v8handle.As<v8::Object>()->HasRealNamedProperty(v8context, v8key.As<v8::Name>());
  
  if(result.IsNothing()) {
    return -1;
  }

  return result.FromJust() ? 1 : 0;
}

int _JavascriptObjectHasRealIndexedProperty(JavascriptContextRef context, JavascriptDataRef handle, int index) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Context> v8context = i_context->GetLocal();
  v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);

  v8::Context::Scope context_scope(v8context);

  v8::Maybe<bool> result = v8handle.As<v8::Object>()->HasRealIndexedProperty(v8context, index);
  
  if(result.IsNothing()) {
    return -1;
  }

  return result.FromJust() ? 1 : 0;
}

int _JavascriptObjectHasRealNamedCallbackProperty(JavascriptContextRef context, JavascriptDataRef handle, JavascriptDataRef key) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Context> v8context = i_context->GetLocal();
  v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  v8::Local<v8::Value> v8key = reinterpret_cast<mumba::V8Value *>(key)->GetLocal(isolate);

  v8::Context::Scope context_scope(v8context);

  v8::Maybe<bool> result = v8handle.As<v8::Object>()->HasRealNamedCallbackProperty(v8context, v8key.As<v8::Name>());
  
  if(result.IsNothing()) {
    return -1;
  }

  return result.FromJust() ? 1 : 0;
}

JavascriptDataRef _JavascriptObjectGetRealNamedPropertyInPrototypeChain(JavascriptContextRef context, JavascriptDataRef handle, JavascriptDataRef key) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Context> v8context = i_context->GetLocal();
  v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  v8::Local<v8::Value> v8key = reinterpret_cast<mumba::V8Value *>(key)->GetLocal(isolate);

  v8::Context::Scope context_scope(v8context);

  v8::MaybeLocal<v8::Value> result = v8handle.As<v8::Object>()->GetRealNamedPropertyInPrototypeChain(v8context, v8key.As<v8::Name>());
  
  if(result.IsEmpty()) {
    return nullptr;
  }

  return new mumba::V8Value(isolate, result.ToLocalChecked()); 
}

JavascriptDataRef _JavascriptObjectGetRealNamedProperty(JavascriptContextRef context, JavascriptDataRef handle, JavascriptDataRef key) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Context> v8context = i_context->GetLocal();
  v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  v8::Local<v8::Value> v8key = reinterpret_cast<mumba::V8Value *>(key)->GetLocal(isolate);

  v8::Context::Scope context_scope(v8context);

  v8::MaybeLocal<v8::Value> result = v8handle.As<v8::Object>()->GetRealNamedProperty(v8context, v8key.As<v8::Name>());
  
  if(result.IsEmpty()) {
    return nullptr;
  }

  return new mumba::V8Value(isolate, result.ToLocalChecked());
}

int _JavascriptObjectHasNamedLookupInterceptor(JavascriptContextRef context, JavascriptDataRef handle) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  return v8handle.As<v8::Object>()->HasNamedLookupInterceptor() ? 1 : 0;
}

int _JavascriptObjectHasIndexedLookupInterceptor(JavascriptContextRef context, JavascriptDataRef handle) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  return v8handle.As<v8::Object>()->HasIndexedLookupInterceptor() ? 1 : 0;
}

JavascriptDataRef _JavascriptObjectCallAsFunction(JavascriptContextRef context, JavascriptDataRef handle, JavascriptDataRef recv, int argc, JavascriptDataRef* argv) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);
 std::unique_ptr<v8::Local<v8::Value>[]> v8argv(new v8::Local<v8::Value>[argc]);

 for(int i = 0; i < argc; i++) {
   v8argv[i] = reinterpret_cast<mumba::V8Value *>(argv[i])->GetLocal(isolate);
 }

 v8::Local<v8::Context> v8context = i_context->GetLocal();
 v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 v8::Local<v8::Value> v8recv = reinterpret_cast<mumba::V8Value *>(recv)->GetLocal(isolate);
  
 v8::Context::Scope context_scope(v8context);
 
 v8::MaybeLocal<v8::Value> result = v8handle.As<v8::Object>()->CallAsFunction(v8context, v8recv, argc, v8argv.get());
 
 if (result.IsEmpty()) {
   return nullptr;
 }

 return new mumba::V8Value(isolate, result.ToLocalChecked());
}

EXPORT JavascriptDataRef _JavascriptObjectCallAsConstructor(JavascriptContextRef context, JavascriptDataRef handle, int argc, JavascriptDataRef* argv){
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 std::unique_ptr<v8::Local<v8::Value>[]> v8argv(new v8::Local<v8::Value>[argc]);

 for(int i = 0; i < argc; i++) {
   v8argv[i] = reinterpret_cast<mumba::V8Value *>(argv[i])->GetLocal(isolate);
 }

 v8::Local<v8::Context> v8context = i_context->GetLocal();
 v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  
 v8::Context::Scope context_scope(v8context);
 
 v8::MaybeLocal<v8::Value> result = v8handle.As<v8::Object>()->CallAsConstructor(v8context, argc, v8argv.get());
 
 if (result.IsEmpty()) {
   return nullptr;
 }

 return new mumba::V8Value(isolate, result.ToLocalChecked()); 
}

JavascriptDataRef _JavascriptObjectClone(JavascriptContextRef context, JavascriptDataRef handle) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 v8::Local<v8::Object> object = v8handle.As<v8::Object>()->Clone();
 
 return new mumba::V8Value(isolate, object);
}

// JsMap
int _JavascriptArrayCount(JavascriptContextRef context, JavascriptDataRef handle) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return v8handle.As<v8::Array>()->Length();
}

int _JavascriptArrayCanCast(JavascriptContextRef context, JavascriptDataRef handle) {
  return _JavascriptValueIsArray(context, handle);
}

// JavascriptDataRef _JavascriptArrayCloneElementAt(JavascriptDataRef context, JavascriptDataRef handle, int index) {
//  v8::Isolate* isolate = v8::Isolate::GetCurrent();
//  v8::Isolate::Scope isolate_scope(isolate);
//  v8::HandleScope handle_scope(isolate);

//  v8::Local<v8::Context> v8context = reinterpret_cast<mumba::V8Context *>(context)->GetLocal();
//  v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);

//  v8::Context::Scope context_scope(v8context);

//  v8::MaybeLocal<v8::Object> result = v8handle.As<v8::Array>()->CloneElementAt(v8context, index);

//  if (result.IsEmpty()) {
//    return nullptr;
//  }

//  return new mumba::V8Value(isolate, result.ToLocalChecked()); 
// }

// JsMap
int _JavascriptMapCount(JavascriptContextRef context, JavascriptDataRef handle) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return v8handle.As<v8::Map>()->Size(); 
}

int _JavascriptMapCanCast(JavascriptContextRef context, JavascriptDataRef handle) {
  return _JavascriptValueIsMap(context, handle); 
}

JavascriptDataRef _JavascriptMapGetProperty(JavascriptContextRef context, JavascriptDataRef handle, JavascriptDataRef key) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);
  
  v8::Local<v8::Context> v8context = i_context->GetLocal();
  v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  v8::Local<v8::Value> v8key = reinterpret_cast<mumba::V8Value *>(key)->GetLocal(isolate);
  
  v8::Context::Scope context_scope(v8context);

  v8::MaybeLocal<v8::Value> result = v8handle.As<v8::Map>()->Get(v8context, v8key);

  if (result.IsEmpty()) {
    return nullptr;
  }

  return new mumba::V8Value(isolate, result.ToLocalChecked());  
}

JavascriptDataRef _JavascriptMapSetProperty(JavascriptContextRef context, JavascriptDataRef handle, JavascriptDataRef key, JavascriptDataRef value) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);
  
  v8::Local<v8::Context> v8context = i_context->GetLocal();
  v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  v8::Local<v8::Value> v8key = reinterpret_cast<mumba::V8Value *>(key)->GetLocal(isolate);
  v8::Local<v8::Value> v8value = reinterpret_cast<mumba::V8Value *>(value)->GetLocal(isolate); 
 
  v8::Context::Scope context_scope(v8context);
  v8::MaybeLocal<v8::Map> map = v8handle.As<v8::Map>()->Set(v8context, v8key, v8value);
  
  if (map.IsEmpty()) {
    return nullptr;
  }

  return new mumba::V8Value(isolate, map.ToLocalChecked());
}

int _JavascriptMapHasProperty(JavascriptDataRef context, JavascriptDataRef handle, JavascriptDataRef key) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Context> v8context = i_context->GetLocal();
  v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  v8::Local<v8::Value> v8key = reinterpret_cast<mumba::V8Value *>(key)->GetLocal(isolate);
 
  v8::Context::Scope context_scope(v8context);
  v8::Maybe<bool> result = v8handle.As<v8::Map>()->Has(v8context, v8key);
  
  if (result.IsNothing()) {
    return -1;
  }
  
  return result.FromJust() ? 1 : 0;
}

int _JavascriptMapDeleteProperty(JavascriptDataRef context, JavascriptDataRef handle, JavascriptDataRef key) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);
 
  v8::Local<v8::Context> v8context = i_context->GetLocal();
  v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  v8::Local<v8::Value> v8key = reinterpret_cast<mumba::V8Value *>(key)->GetLocal(isolate);
  
  v8::Context::Scope context_scope(v8context);
  v8::Maybe<bool> result = v8handle.As<v8::Map>()->Delete(v8context, v8key);
  if (result.IsNothing()) {
    return -1;
  }
  
  return result.FromJust() ? 1 : 0;
}

void _JavascriptMapClear(JavascriptContextRef context, JavascriptDataRef handle) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 
 return v8handle.As<v8::Map>()->Clear();
}

JavascriptDataRef _JavascriptMapAsArray(JavascriptContextRef context, JavascriptDataRef handle) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 v8::Local<v8::Array> array = v8handle.As<v8::Map>()->AsArray();
 
 return new mumba::V8Value(isolate, array);
}

// JsSet
int _JavascriptSetCount(JavascriptContextRef context, JavascriptDataRef handle) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return v8handle.As<v8::Set>()->Size();
}

int _JavascriptSetCanCast(JavascriptContextRef context, JavascriptDataRef handle) {
  return _JavascriptValueIsSet(context, handle);
}

JavascriptDataRef _JavascriptSetAdd(JavascriptDataRef context, JavascriptDataRef handle, JavascriptDataRef key) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate); 

  v8::Local<v8::Context> v8context = i_context->GetLocal();
  v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  v8::Local<v8::Value> v8key = reinterpret_cast<mumba::V8Value *>(key)->GetLocal(isolate);
 
  v8::Context::Scope context_scope(v8context);
  v8::MaybeLocal<v8::Set> result = v8handle.As<v8::Set>()->Add(v8context, v8key);
  
  if (result.IsEmpty()) {
    return nullptr;
  }
  
  return new mumba::V8Value(isolate, result.ToLocalChecked());
}

int _JavascriptSetHasProperty(JavascriptDataRef context, JavascriptDataRef handle, JavascriptDataRef key) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);
 
 v8::Local<v8::Context> v8context = i_context->GetLocal();
 v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 v8::Local<v8::Value> v8key = reinterpret_cast<mumba::V8Value *>(key)->GetLocal(isolate); 
 
 v8::Context::Scope context_scope(v8context);
 
 v8::Maybe<bool> result = v8handle.As<v8::Set>()->Has(v8context, v8key);
  
 if (result.IsNothing()) {
  return -1;
 }
  
 return result.FromJust() ? 1 : 0;
}

int _JavascriptSetDeleteProperty(JavascriptDataRef context, JavascriptDataRef handle, JavascriptDataRef key) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);
 
 v8::Local<v8::Context> v8context = i_context->GetLocal();
 v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 v8::Local<v8::Value> v8key = reinterpret_cast<mumba::V8Value *>(key)->GetLocal(isolate); 
 
 v8::Context::Scope context_scope(v8context);
 
 v8::Maybe<bool> result = v8handle.As<v8::Set>()->Delete(v8context, v8key);
  
 if (result.IsNothing()) {
  return -1;
 }
  
 return result.FromJust() ? 1 : 0;
}

void _JavascriptSetClear(JavascriptContextRef context, JavascriptDataRef handle) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  v8handle.As<v8::Set>()->Clear();
}

JavascriptDataRef _JavascriptSetAsArray(JavascriptContextRef context, JavascriptDataRef handle) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 
  return new mumba::V8Value(isolate, v8handle.As<v8::Set>()->AsArray());
}

// JsFunctionCallbackInfo

int _JavascriptFunctionCallbackInfoGetLength(JavascriptContextRef context, JavascriptFunctionCallbackInfoRef handle) {
  return reinterpret_cast<v8::FunctionCallbackInfo<v8::Value>*>(handle)->Length();
}

JavascriptDataRef _JavascriptFunctionCallbackInfoGetThis(JavascriptContextRef context, JavascriptFunctionCallbackInfoRef handle) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);
  return new mumba::V8Value(isolate, reinterpret_cast<v8::FunctionCallbackInfo<v8::Value>*>(handle)->This());
}

JavascriptDataRef _JavascriptFunctionCallbackInfoGetHolder(JavascriptContextRef context, JavascriptFunctionCallbackInfoRef handle) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);
  return new mumba::V8Value(isolate, reinterpret_cast<v8::FunctionCallbackInfo<v8::Value>*>(handle)->Holder());
}

int _JavascriptFunctionCallbackInfoIsConstructorCall(JavascriptContextRef context, JavascriptFunctionCallbackInfoRef handle) {
  return reinterpret_cast<v8::FunctionCallbackInfo<v8::Value>*>(handle)->IsConstructCall();
}

JavascriptDataRef _JavascriptFunctionCallbackInfoGetData(JavascriptContextRef context, JavascriptFunctionCallbackInfoRef handle) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);
  return new mumba::V8Value(isolate, reinterpret_cast<v8::FunctionCallbackInfo<v8::Value>*>(handle)->Data());
}

JavascriptDataRef _JavascriptFunctionCallbackInfoGetReturnValue(JavascriptContextRef context, JavascriptFunctionCallbackInfoRef handle) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);
  return new mumba::V8Value(isolate, reinterpret_cast<v8::FunctionCallbackInfo<v8::Value>*>(handle)->GetReturnValue().Get());
}

JavascriptDataRef _JavascriptFunctionCallbackInfoGetValueAt(JavascriptContextRef context, JavascriptFunctionCallbackInfoRef handle, int index) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);
  v8::FunctionCallbackInfo<v8::Value>* handle_ptr = reinterpret_cast<v8::FunctionCallbackInfo<v8::Value>*>(handle);
  DCHECK(index < handle_ptr->Length());
  return new mumba::V8Value(isolate, (*handle_ptr)[index]);
}

// JsFunction
JavascriptDataRef _JavascriptFunctionCreate(JavascriptContextRef context, const char* name, int name_len, void* state, void(*callback)(void*, JavascriptFunctionCallbackInfoRef)) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);
 
  v8::Local<v8::Context> v8context = i_context->GetLocal();
 
  V8FunctionHandler* handler = new V8FunctionHandler(isolate, state, callback);
  v8::Local<v8::Value> wrapper = handler->wrapper_.Get(isolate);
  v8::Local<v8::Function> v8handle;
  
  if (!v8::Function::New(v8context, 
                         V8FunctionCallback, 
                         wrapper, 
                         0,
                         v8::ConstructorBehavior::kThrow, 
                         v8::SideEffectType::kHasSideEffect).ToLocal(&v8handle)) {
    return nullptr;
  }

  v8::Local<v8::String> v8_function_name = v8::String::NewFromUtf8(isolate, name, v8::String::kNormalString, name_len);
  //DLOG(INFO) << "setting function name to '" << name << "' [" << name_len << "]";
  v8handle->SetName(v8_function_name);

  return new mumba::V8Value(isolate, v8handle);
}

JavascriptDataRef _JavascriptFunctionCreateInstance(JavascriptContextRef context, JavascriptDataRef handle, int argc, JavascriptDataRef* argv) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);
 
 std::unique_ptr<v8::Local<v8::Value>[]> v8argv(new v8::Local<v8::Value>[argc]);

 for(int i = 0; i < argc; i++) {
   v8argv[i] = reinterpret_cast<mumba::V8Value *>(argv[i])->GetLocal(isolate);
 }

 v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 v8::Local<v8::Context> v8context = i_context->GetLocal();

 v8::MaybeLocal<v8::Object> v8instance = v8handle.As<v8::Function>()->NewInstance(v8context, argc, v8argv.get());

 if (v8instance.IsEmpty()) {
 	return nullptr;
 }

 return new mumba::V8Value(isolate, v8instance.ToLocalChecked());
}

JavascriptDataRef _JavascriptFunctionGetName(JavascriptContextRef context, JavascriptDataRef handle) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return new mumba::V8Value(isolate, v8handle.As<v8::Function>()->GetName());
}

JavascriptDataRef _JavascriptFunctionGetInferredName(JavascriptContextRef context, JavascriptDataRef handle) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return new mumba::V8Value(isolate, v8handle.As<v8::Function>()->GetInferredName()); 
}

int _JavascriptFunctionGetScriptLineNumber(JavascriptContextRef context, JavascriptDataRef handle) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return v8handle.As<v8::Function>()->GetScriptLineNumber();
}

int _JavascriptFunctionGetScriptColumnNumber(JavascriptContextRef context, JavascriptDataRef handle) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  return v8handle.As<v8::Function>()->GetScriptColumnNumber();
}

// int _JavascriptFunctionIsBuiltin(JavascriptDataRef handle) {
//   v8::Isolate* isolate = v8::Isolate::GetCurrent();
//   v8::Isolate::Scope isolate_scope(isolate);
//   v8::HandleScope handle_scope(isolate);

//   v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
//   return v8handle.As<v8::Function>()->IsBuiltin() ? 1 : 0;
// }

int _JavascriptFunctionGetScriptId(JavascriptContextRef context, JavascriptDataRef handle) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
  return v8handle.As<v8::Function>()->ScriptId();
}

JavascriptDataRef _JavascriptFunctionGetDisplayName(JavascriptContextRef context, JavascriptDataRef handle) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return new mumba::V8Value(isolate, v8handle.As<v8::Function>()->GetDisplayName());
}

JavascriptDataRef _JavascriptFunctionGetBoundFunction(JavascriptContextRef context, JavascriptDataRef handle) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return new mumba::V8Value(isolate, v8handle.As<v8::Function>()->GetBoundFunction());
}

int _JavascriptFunctionCanCast(JavascriptContextRef context, JavascriptDataRef handle) {
  return _JavascriptValueIsFunction(context, handle);
}

JavascriptDataRef _JavascriptFunctionCall(JavascriptContextRef context, JavascriptDataRef handle, JavascriptDataRef recv, int argc, JavascriptDataRef* argv) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);
 
 std::unique_ptr<v8::Local<v8::Value>[]> v8argv(new v8::Local<v8::Value>[argc]);

 for(int i = 0; i < argc; i++) {
   v8argv[i] = reinterpret_cast<mumba::V8Value *>(argv[i])->GetLocal(isolate);
 }

 v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 v8::Local<v8::Context> v8context = i_context->GetLocal();
 v8::Local<v8::Value> v8recv = reinterpret_cast<mumba::V8Value *>(recv)->GetLocal(isolate);
 
 v8::MaybeLocal<v8::Value> result = v8handle.As<v8::Function>()->Call(v8context, v8recv, argc, v8argv.get());
 if (result.IsEmpty()) {
  return nullptr;
 }
  
 return new mumba::V8Value(isolate, result.ToLocalChecked());
}

void _JavascriptFunctionSetName(JavascriptContextRef context, JavascriptDataRef handle, JavascriptDataRef name) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 v8::Local<v8::Value> v8name = reinterpret_cast<mumba::V8Value *>(name)->GetLocal(isolate);
 
 v8handle.As<v8::Function>()->SetName(v8name.As<v8::String>());
}

JavascriptScriptOriginRef _JavascriptFunctionGetScriptOrigin(JavascriptContextRef context, JavascriptDataRef handle) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 //v8::Isolate::Scope isolate_scope(isolate);
 //v8::HandleScope handle_scope(isolate);

 //v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return nullptr;
}

// JsPromisse
int _JavascriptPromiseCanCast(JavascriptContextRef context, JavascriptDataRef handle) {
  return _JavascriptValueIsPromise(context, handle);
}

// JsArrayBuffer
int _JavascriptArrayBufferCanCast(JavascriptContextRef context, JavascriptDataRef handle) {
 return _JavascriptValueIsArrayBuffer(context, handle);  
}

// JsArrayBufferView
int _JavascriptArrayBufferViewCanCast(JavascriptContextRef context, JavascriptDataRef handle) {
  return _JavascriptValueIsArrayBufferView(context, handle);
}

// JsTypedArray
int _JavascriptTypedArrayCanCast(JavascriptContextRef context, JavascriptDataRef handle) {
  return _JavascriptValueIsTypedArray(context, handle);
}

// JsUInt8Array
int _JavascriptUInt8ArrayCanCast(JavascriptContextRef context, JavascriptDataRef handle) {
  return _JavascriptValueIsUInt8Array(context, handle);
}

// JsUInt8ClampedArray
int _JavascriptUInt8ClampedArrayCanCast(JavascriptContextRef context, JavascriptDataRef handle) {
  return _JavascriptValueIsUInt8ClampedArray(context, handle);
}

// JsInt8Array
int _JavascriptInt8ArrayCanCast(JavascriptContextRef context, JavascriptDataRef handle) {
  return _JavascriptValueIsInt8Array(context, handle);
}

// JsUInt64Array
int _JavascriptUInt16ArrayCanCast(JavascriptContextRef context, JavascriptDataRef handle) {
  return _JavascriptValueIsUInt16Array(context, handle);
}

// JsInt64Array
int _JavascriptInt16ArrayCanCast(JavascriptContextRef context, JavascriptDataRef handle) {
  return _JavascriptValueIsInt16Array(context, handle);
}

// JsUInt32Array
int _JavascriptUInt32ArrayCanCast(JavascriptContextRef context, JavascriptDataRef handle) {
  return _JavascriptValueIsUInt32Array(context, handle);
}

// JsInt32
int _JavascriptInt32ArrayCanCast(JavascriptContextRef context, JavascriptDataRef handle) {
  return _JavascriptValueIsInt32Array(context, handle);
}

// JsFloat32
int _JavascriptFloat32ArrayCanCast(JavascriptContextRef context, JavascriptDataRef handle) {
  return _JavascriptValueIsFloat32Array(context, handle);
}

// JsFloat64
int _JavascriptFloat64ArrayCanCast(JavascriptContextRef context, JavascriptDataRef handle) {
  return _JavascriptValueIsFloat64Array(context, handle);
}

// JsDataView
int _JavascriptDataViewCanCast(JavascriptContextRef context, JavascriptDataRef handle) {
  return _JavascriptValueIsDataView(context, handle);
}

// JsDate
double _JavascriptDateGetValue(JavascriptContextRef context, JavascriptDataRef handle) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return v8handle.As<v8::Date>()->ValueOf();
}

int _JavascriptDateCanCast(JavascriptContextRef context, JavascriptDataRef handle) {
  return _JavascriptValueIsDate(context, handle);
}

JavascriptDataRef _JavascriptDateCreate(JavascriptContextRef context, double value) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::Local<v8::Context> v8context = i_context->GetLocal();
 v8::MaybeLocal<v8::Value> date = v8::Date::New(v8context, value);
 
 if (date.IsEmpty()) {
   return nullptr;
 }

 return new mumba::V8Value(isolate, date.ToLocalChecked());
}

// JsNumberObject
double _JavascriptNumberObjectGetValue(JavascriptContextRef context, JavascriptDataRef handle) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return v8handle.As<v8::NumberObject>()->ValueOf();
}

int _JavascriptNumberObjectCanCast(JavascriptContextRef context, JavascriptDataRef handle) {
  return _JavascriptValueIsNumberObject(context, handle);
}

JavascriptDataRef _JavascriptNumberObjectCreate(JavascriptContextRef context, double value) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::Local<v8::Value> number = v8::NumberObject::New(isolate, value);
 
 return new mumba::V8Value(isolate, number);
}

// JsBooleanObject
int _JavascriptBooleanObjectGetValue(JavascriptContextRef context, JavascriptDataRef handle) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return v8handle.As<v8::BooleanObject>()->ValueOf() ? 1 : 0;
}

int _JavascriptBooleanObjectCanCast(JavascriptContextRef context, JavascriptDataRef handle) {
  return _JavascriptValueIsBooleanObject(context, handle);
}

JavascriptDataRef _JavascriptBooleanObjectCreate(JavascriptContextRef context, int value) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::Local<v8::Value> boolean = v8::BooleanObject::New(isolate, value);
 
 return new mumba::V8Value(isolate, boolean);
}

// JsStringObject
JavascriptDataRef _JavascriptStringObjectGetValue(JavascriptContextRef context, JavascriptDataRef handle) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 return new mumba::V8Value(isolate, v8handle.As<v8::StringObject>()->ValueOf());
}

int _JavascriptStringObjectCanCast(JavascriptContextRef context, JavascriptDataRef handle) {
  return _JavascriptValueIsStringObject(context, handle);
}

JavascriptDataRef _JavascriptStringObjectCreate(JavascriptContextRef context, JavascriptDataRef string) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::Local<v8::Value> v8string = reinterpret_cast<mumba::V8Value *>(string)->GetLocal(isolate);
 v8::Local<v8::Value> result = v8::StringObject::New(v8string.As<v8::String>());
 return new mumba::V8Value(isolate, result);
}

JavascriptDataRef _JavascriptStringObjectCreateFromString(JavascriptContextRef context, const char* value, int len) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::Local<v8::String> v8string = v8::String::NewFromUtf8(isolate, value, v8::String::kNormalString, len);
 v8::Local<v8::Value> result = v8::StringObject::New(v8string);
 return new mumba::V8Value(isolate, result);
}

// JsRegexp
JavascriptDataRef _JavascriptRegExpGetSource(JavascriptContextRef context, JavascriptDataRef handle) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);

 return new mumba::V8Value(isolate, v8handle.As<v8::RegExp>()->GetSource());
}

int _JavascriptRegExpCanCast(JavascriptContextRef context, JavascriptDataRef handle) {
  return _JavascriptValueIsRegExp(context, handle);
}

JavascriptDataRef _JavascriptRegExpCreate(JavascriptContextRef context, JavascriptDataRef pattern) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::RegExp::Flags v8flags = v8::RegExp::kNone;
 
 v8::Local<v8::Context> v8context = reinterpret_cast<mumba::V8Context *>(context)->GetLocal();
 v8::Local<v8::Value> v8pattern = reinterpret_cast<mumba::V8Value *>(pattern)->GetLocal(isolate);  
 v8::MaybeLocal<v8::RegExp> result = v8::RegExp::New(v8context, v8pattern.As<v8::String>(), v8flags);
 
 if (result.IsEmpty()) {
   return nullptr;
 }

 return new mumba::V8Value(isolate, result.ToLocalChecked());
}

JavascriptDataRef _JavascriptRegExpCreateFromString(JavascriptContextRef context, const char* pattern, int len) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::RegExp::Flags v8flags = v8::RegExp::kNone;
 
 v8::Local<v8::Context> v8context = i_context->GetLocal();
 v8::Local<v8::String> v8pattern = v8::String::NewFromUtf8(isolate, pattern, v8::String::kNormalString, len);
 v8::MaybeLocal<v8::RegExp> result = v8::RegExp::New(v8context, v8pattern, v8flags);
 
 if (result.IsEmpty()) {
   return nullptr;
 }

 return new mumba::V8Value(isolate, result.ToLocalChecked());
}

JavascriptFunctionTemplateRef _JavascriptFunctionTemplateCreate(JavascriptContextRef context) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);
 
 return new mumba::V8FunctionTemplate(isolate, v8::FunctionTemplate::New(isolate));
}

void _JavascriptFunctionTemplateDestroy(JavascriptFunctionTemplateRef handle) {
 delete reinterpret_cast<mumba::V8FunctionTemplate *>(handle);
}

void _JavascriptFunctionTemplateSet(JavascriptContextRef context, JavascriptFunctionTemplateRef handle, const char* name, JavascriptDataRef value) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::Local<v8::FunctionTemplate> v8handle = reinterpret_cast<mumba::V8FunctionTemplate *>(handle)->GetLocal(isolate);
 v8::Local<v8::Data> v8value = reinterpret_cast<mumba::V8Data *>(value)->GetLocal(isolate);
 v8handle->Set(isolate, name, v8value);
}

void _JavascriptFunctionTemplateSetNativeDataProperty(JavascriptContextRef context, JavascriptFunctionTemplateRef handle, JavascriptDataRef name, CJsAccessorGetterCallback getter, CJsAccessorSetterCallback setter) {
 
}

// JsFunctionTemplate
JavascriptDataRef _JavascriptFunctionTemplateGetFunction(JavascriptContextRef context, JavascriptFunctionTemplateRef handle) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::FunctionTemplate> v8handle = reinterpret_cast<mumba::V8FunctionTemplate *>(handle)->GetLocal(isolate);
  //v8::Local<v8::Context> v8context = reinterpret_cast<mumba::V8Context *>(context)->GetLocal();

  v8::MaybeLocal<v8::Function> function = v8handle->GetFunction();
  if (function.IsEmpty()) {
    return nullptr;
  }
  return new mumba::V8Value(isolate, function.ToLocalChecked());
}

JavascriptObjectTemplateRef _JavascriptFunctionTemplateGetPrototypeTemplate(JavascriptContextRef context, JavascriptFunctionTemplateRef handle) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::FunctionTemplate> v8handle = reinterpret_cast<mumba::V8FunctionTemplate *>(handle)->GetLocal(isolate);
 
  v8::Local<v8::ObjectTemplate> prototype = v8handle->PrototypeTemplate();
  return new mumba::V8ObjectTemplate(isolate, prototype);
}

JavascriptObjectTemplateRef _JavascriptFunctionTemplateGetInstanceTemplate(JavascriptContextRef context, JavascriptFunctionTemplateRef handle) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::FunctionTemplate> v8handle = reinterpret_cast<mumba::V8FunctionTemplate *>(handle)->GetLocal(isolate);
 
  v8::Local<v8::ObjectTemplate> instance = v8handle->InstanceTemplate();
  return new mumba::V8ObjectTemplate(isolate, instance);
}

void _JavascriptFunctionTemplateSetCallHandler(JavascriptContextRef context, JavascriptFunctionTemplateRef handle, CJsFunctionCallback callback, JavascriptDataRef data) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Value> v8data;
  v8::Local<v8::FunctionTemplate> v8handle = reinterpret_cast<mumba::V8FunctionTemplate *>(handle)->GetLocal(isolate);
  v8::FunctionCallback cb = &reinterpret_cast<mumba::V8Value *>(handle)->functionCallbackHandler;
  
  if (data != nullptr) {
    v8data = reinterpret_cast<mumba::V8Value *>(data)->GetLocal(isolate);
  }

  v8handle->SetCallHandler(cb, v8data);
}

void _JavascriptFunctionTemplateSetLength(JavascriptContextRef context, JavascriptFunctionTemplateRef handle, int length) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::FunctionTemplate> v8handle = reinterpret_cast<mumba::V8FunctionTemplate *>(handle)->GetLocal(isolate);

  v8handle->SetLength(length);
}

void _JavascriptFunctionTemplateInherit(JavascriptContextRef context, JavascriptFunctionTemplateRef handle, JavascriptFunctionTemplateRef parent) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::FunctionTemplate> v8handle = reinterpret_cast<mumba::V8FunctionTemplate *>(handle)->GetLocal(isolate);
  v8::Local<v8::FunctionTemplate> v8parent = reinterpret_cast<mumba::V8FunctionTemplate *>(parent)->GetLocal(isolate);
  v8handle->Inherit(v8parent);
}

void _JavascriptFunctionTemplateSetClassName(JavascriptContextRef context, JavascriptFunctionTemplateRef handle, JavascriptDataRef name) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::FunctionTemplate> v8handle = reinterpret_cast<mumba::V8FunctionTemplate *>(handle)->GetLocal(isolate);
  v8::Local<v8::Value> v8name = reinterpret_cast<mumba::V8Value *>(name)->GetLocal(isolate);
  v8handle->SetClassName(v8name.As<v8::String>());
}

void _JavascriptFunctionTemplateSetAcceptAnyReceiver(JavascriptContextRef context, JavascriptFunctionTemplateRef handle, int value) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::FunctionTemplate> v8handle = reinterpret_cast<mumba::V8FunctionTemplate *>(handle)->GetLocal(isolate);
  v8handle->SetAcceptAnyReceiver(value == 0 ? false : true);
}

void _JavascriptFunctionTemplateSetHiddenPrototype(JavascriptContextRef context, JavascriptFunctionTemplateRef handle, int value) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::FunctionTemplate> v8handle = reinterpret_cast<mumba::V8FunctionTemplate *>(handle)->GetLocal(isolate);
  v8handle->SetHiddenPrototype(value == 0 ? false : true);
}

void _JavascriptFunctionTemplateSetReadOnlyPrototype(JavascriptContextRef context, JavascriptFunctionTemplateRef handle) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::FunctionTemplate> v8handle = reinterpret_cast<mumba::V8FunctionTemplate *>(handle)->GetLocal(isolate);
  v8handle->ReadOnlyPrototype();
}

void _JavascriptFunctionTemplateRemovePrototype(JavascriptContextRef context, JavascriptFunctionTemplateRef handle) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::FunctionTemplate> v8handle = reinterpret_cast<mumba::V8FunctionTemplate *>(handle)->GetLocal(isolate);
  v8handle->RemovePrototype();
}

int _JavascriptFunctionTemplateHasInstance(JavascriptContextRef context, JavascriptFunctionTemplateRef handle, JavascriptDataRef object) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);
 
  v8::Local<v8::FunctionTemplate> v8handle = reinterpret_cast<mumba::V8FunctionTemplate *>(handle)->GetLocal(isolate);
  v8::Local<v8::Value> v8value = reinterpret_cast<mumba::V8Value *>(object)->GetLocal(isolate);
  
  return v8handle->HasInstance(v8value) ? 1 : 0; 
}

// JsObjectTemplate

JavascriptObjectTemplateRef _JavascriptObjectTemplateCreate(JavascriptContextRef context) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  return new mumba::V8ObjectTemplate(isolate, v8::ObjectTemplate::New(isolate));
}

void _JavascriptObjectTemplateDestroy(JavascriptObjectTemplateRef handle) {
 delete reinterpret_cast<mumba::V8ObjectTemplate *>(handle);
}

void _JavascriptObjectTemplateSet(JavascriptContextRef context, JavascriptObjectTemplateRef handle, const char* name, JavascriptDataRef value) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::Local<v8::ObjectTemplate> v8handle = reinterpret_cast<mumba::V8ObjectTemplate *>(handle)->GetLocal(isolate);
 v8::Local<v8::Value> v8value = reinterpret_cast<mumba::V8Value *>(value)->GetLocal(isolate);
 v8handle->Set(isolate, name, v8value);
}

void _JavascriptObjectTemplateSetNativeDataProperty(JavascriptContextRef context, JavascriptObjectTemplateRef handle, JavascriptDataRef name, CJsAccessorGetterCallback getter, CJsAccessorSetterCallback setter) {
 //v8::Isolate* isolate = v8::Isolate::GetCurrent();
 //v8::Isolate::Scope isolate_scope(isolate);
 //v8::HandleScope handle_scope(isolate);

 //v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(handle)->GetLocal(isolate);
 
}

int _JavascriptObjectTemplateGetInternalFieldCount(JavascriptContextRef context, JavascriptObjectTemplateRef handle) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::Local<v8::ObjectTemplate> v8handle = reinterpret_cast<mumba::V8ObjectTemplate *>(handle)->GetLocal(isolate);
 return v8handle->InternalFieldCount();
}

void _JavascriptObjectTemplateSetInternalFieldCount(JavascriptContextRef context, JavascriptObjectTemplateRef handle, int count) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::Local<v8::ObjectTemplate> v8handle = reinterpret_cast<mumba::V8ObjectTemplate *>(handle)->GetLocal(isolate);
 v8handle->SetInternalFieldCount(count);
}

void _JavascriptObjectTemplateSetAccessor(JavascriptContextRef context, JavascriptObjectTemplateRef handle) {
  
}

void _JavascriptObjectTemplateSetHandler(JavascriptContextRef context, JavascriptObjectTemplateRef handle) {
  
}

void _JavascriptObjectTemplateSetCallAsFunctionHandler(JavascriptContextRef context, JavascriptObjectTemplateRef handle) {
  
}

void _JavascriptObjectTemplateMarkAsUndetectable(JavascriptContextRef context, JavascriptObjectTemplateRef handle) {
 mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
 v8::Isolate* isolate = i_context->isolate();
 v8::Isolate::Scope isolate_scope(isolate);
 v8::HandleScope handle_scope(isolate);

 v8::Local<v8::ObjectTemplate> v8handle = reinterpret_cast<mumba::V8ObjectTemplate *>(handle)->GetLocal(isolate);
 v8handle->MarkAsUndetectable();
}

void _JavascriptObjectTemplateSetAccessCheckCallback(JavascriptContextRef context, JavascriptObjectTemplateRef handle) {
  
}

JavascriptDataRef _JavascriptModuleImport(JavascriptContextRef context, const char* name) {
  return nullptr;
}

JavascriptDataRef _WasmCompiledModuleDeserializeOrCompile(JavascriptContextRef context, const uint8_t* serialized_bytes, int serialized_bytes_size, const uint8_t* raw_bytes, int raw_bytes_size) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);
  
  v8::Local<v8::Context> v8context = i_context->GetLocal();

  v8::Local<v8::WasmCompiledModule> mod;
  v8context->Enter();
  v8::MaybeLocal<v8::WasmCompiledModule> maybe_mod = v8::WasmCompiledModule::DeserializeOrCompile(isolate, {serialized_bytes, serialized_bytes_size},
               {raw_bytes, raw_bytes_size});
 
  if (!maybe_mod.ToLocal(&mod)) {
    return nullptr;
  }
  v8context->Exit();
 
  return new mumba::V8Value(isolate, mod);
}

int _JavascriptContextExecuteWasm(JavascriptContextRef context, JavascriptDataRef module, const char* func, int argc, char** argv) {
  mumba::V8Context* i_context = reinterpret_cast<mumba::V8Context *>(context);
  v8::Isolate* isolate = i_context->isolate();
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Context> v8context = i_context->GetLocal();

  v8context->Enter();

  v8::Local<v8::Value> v8handle = reinterpret_cast<mumba::V8Value *>(module)->GetLocal(isolate);
  v8::Local<v8::WasmCompiledModule> i_mod = v8handle.As<v8::WasmCompiledModule>();

  v8::internal::Isolate* i_isolate = reinterpret_cast<v8::internal::Isolate*>(isolate);
  v8::internal::wasm::ErrorThrower thrower(i_isolate, "");
  v8::internal::Handle<v8::internal::WasmModuleObject> module_object = v8::internal::Handle<v8::internal::WasmModuleObject>::cast(
        v8::Utils::OpenHandle(*i_mod));
  
  v8::internal::Handle<v8::internal::WasmInstanceObject> instance = i_isolate->wasm_engine()
            ->SyncInstantiate(i_isolate, &thrower, module_object,
                              v8::internal::Handle<v8::internal::JSReceiver>::null(),
                              v8::internal::MaybeHandle<v8::internal::JSArrayBuffer>()).ToHandleChecked();

  // Get the "main" exported function
  // FIXME: reuse this for any exported function
  v8::internal::Handle<v8::internal::JSObject> exports_object;
  v8::internal::Handle<v8::internal::Name> exports = i_isolate->factory()->InternalizeUtf8String("exports");
  exports_object = v8::internal::Handle<v8::internal::JSObject>::cast(
      v8::internal::JSObject::GetProperty(instance, exports).ToHandleChecked());

  v8::internal::Handle<v8::internal::Name> main_name = i_isolate->factory()->NewStringFromAsciiChecked(func);
  v8::internal::PropertyDescriptor desc;
  v8::Maybe<bool> property_found = v8::internal::JSReceiver::GetOwnPropertyDescriptor(
      i_isolate, exports_object, main_name, &desc);

  if (!property_found.FromMaybe(false)) {
    v8context->Exit();
    return -1;
  }

  if (!desc.value()->IsJSFunction()) {
    v8context->Exit();
    return -1;
  }

  v8::internal::Handle<v8::internal::WasmExportedFunction> main_export = v8::internal::Handle<v8::internal::WasmExportedFunction>::cast(desc.value());
  v8::internal::Handle<v8::internal::Object> undefined = i_isolate->factory()->undefined_value();
  // FIXME
  v8::internal::Handle<v8::internal::Object> args[] = {};
  
  v8::internal::MaybeHandle<v8::internal::Object> retval =
      v8::internal::Execution::Call(i_isolate, main_export, undefined, 0, args);
  
  if (retval.is_null()) {
    DCHECK(i_isolate->has_pending_exception());
    i_isolate->clear_pending_exception();
    //thrower.RuntimeError("Calling exported wasm function failed.");
    v8context->Exit();
    return -1;
  }

  //DLOG(INFO) << "JavascriptContextExecuteWasm: retval.ToHandleChecked()";
  v8::internal::Handle<v8::internal::Object> result = retval.ToHandleChecked();
  if (result->IsSmi()) {
    v8context->Exit();
    return v8::internal::Smi::ToInt(*result);
  }
  if (result->IsHeapNumber()) {
    v8context->Exit();
    return static_cast<int32_t>(v8::internal::HeapNumber::cast(*result)->value());
  }
  //thrower.RuntimeError(
  //    "Calling exported wasm function failed: Return value should be number");
  v8context->Exit();    
  return -1;
}

int _JavascriptContextExecuteWasmMain(JavascriptContextRef context, JavascriptDataRef module) {
  return _JavascriptContextExecuteWasm(context, module, "_start", 0, nullptr);
}
