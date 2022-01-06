// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "runtime/MumbaShims/v8/v8_script.h"

namespace mumba {

V8Script::V8Script(v8::Isolate* isolate, v8::Local<v8::Script> script) {
 script_.Reset(isolate, script);
}

V8Script::~V8Script() {

}

}