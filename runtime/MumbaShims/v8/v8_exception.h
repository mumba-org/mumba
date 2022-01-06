// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_V8_EXCEPTION_H__
#define MUMBA_RUNTIME_MUMBA_SHIMS_V8_EXCEPTION_H__

#include "runtime/MumbaShims/v8/v8_value.h"

namespace mumba {

class V8Exception {
public:
 V8Exception();
 ~V8Exception();

 void set(v8::Isolate* isolate, v8::Local<v8::Value> value);

 bool IsSintaxException() const { return sintax_exception_; }
 bool IsRunException() const { return !sintax_exception_; }
 void SetSintaxException(bool exception) { sintax_exception_ = exception; }
 void SetRunException(bool exception) { sintax_exception_ = !exception; }

private:
 v8::Persistent<v8::Value> value_;
 
 bool sintax_exception_;
};

}

#endif