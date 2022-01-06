// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "runtime/MumbaShims/v8/v8_value.h"

#include "base/logging.h"
#include "runtime/MumbaShims/v8/v8_context.h"

namespace mumba {

V8Data::V8Data(v8::Isolate* isolate, v8::Local<v8::Data> data) {
 data_.Reset(isolate, data);
}

V8Data::~V8Data() {
 data_.Reset();
}  

V8Value::V8Value(v8::Isolate* isolate, v8::Local<v8::Value> value) {
 DCHECK(isolate);
 DCHECK(!value.IsEmpty());
 value_.Reset(isolate, value);
}

V8Value::~V8Value() {
 value_.Reset();
}


V8FunctionTemplate::V8FunctionTemplate(v8::Isolate* isolate, v8::Local<v8::FunctionTemplate> value) {
 DCHECK(isolate);
 DCHECK(!value.IsEmpty());
 value_.Reset(isolate, value);
}

V8FunctionTemplate::~V8FunctionTemplate() {
 value_.Reset();
}

V8ObjectTemplate::V8ObjectTemplate(v8::Isolate* isolate, v8::Local<v8::ObjectTemplate> value) {
 DCHECK(isolate);
 DCHECK(!value.IsEmpty());
 value_.Reset(isolate, value);
}

V8ObjectTemplate::~V8ObjectTemplate() {
 value_.Reset();
}

}