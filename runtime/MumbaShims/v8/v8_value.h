// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_V8_VALUE_H__
#define MUMBA_RUNTIME_MUMBA_SHIMS_V8_VALUE_H__

#include <string>

#include "base/macros.h"
//#include "base/memory/scoped_ptr.h"
#include "v8/include/v8.h"

namespace mumba {
	
class V8Data {
public:
 V8Data(v8::Isolate* isolate, v8::Local<v8::Data> data);
 ~V8Data();

 v8::Local<v8::Data> GetLocal(v8::Isolate* isolate) const { 
   return data_.Get(isolate); 
 }

private: 
 v8::Persistent<v8::Data> data_;

 DISALLOW_COPY_AND_ASSIGN(V8Data);
};

// abstract value implemented by the real engine, v8
class V8Value {
public: 
 
 static void functionCallbackHandler(const v8::FunctionCallbackInfo<v8::Value>& info) {}

 V8Value(v8::Isolate* isolate, v8::Local<v8::Value> value);
 ~V8Value();
 
 v8::Local<v8::Value> GetLocal(v8::Isolate* isolate) const { 
   return value_.Get(isolate); 
 } 

private: 
 v8::Persistent<v8::Value> value_;

 DISALLOW_COPY_AND_ASSIGN(V8Value);
};


class V8FunctionTemplate {
public: 
 V8FunctionTemplate(v8::Isolate* isolate, v8::Local<v8::FunctionTemplate> value);
 ~V8FunctionTemplate();

 v8::Local<v8::FunctionTemplate> GetLocal(v8::Isolate* isolate) const { 
   return value_.Get(isolate);
 }

private: 
 v8::Persistent<v8::FunctionTemplate> value_;

 DISALLOW_COPY_AND_ASSIGN(V8FunctionTemplate);
};

class V8ObjectTemplate {
public: 
 V8ObjectTemplate(v8::Isolate* isolate, v8::Local<v8::ObjectTemplate> value);
 ~V8ObjectTemplate();

 v8::Local<v8::ObjectTemplate> GetLocal(v8::Isolate* isolate) const { 
   return value_.Get(isolate);
 }

private: 
 v8::Persistent<v8::ObjectTemplate> value_;

 DISALLOW_COPY_AND_ASSIGN(V8ObjectTemplate);
};

}

#endif