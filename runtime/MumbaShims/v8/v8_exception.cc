// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "runtime/MumbaShims/v8/v8_exception.h"

namespace mumba {

V8Exception::V8Exception(): sintax_exception_(false) {
}

V8Exception::~V8Exception() {
  value_.Reset();
}

void V8Exception::set(v8::Isolate* isolate, v8::Local<v8::Value> value) {
 value_.Reset(isolate, value);
}

}