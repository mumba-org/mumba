// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_V8_SCRIPT_H__
#define MUMBA_RUNTIME_MUMBA_SHIMS_V8_SCRIPT_H__

#include <string>

#include "base/macros.h"
#include "v8/include/v8.h"

namespace mumba {

class V8Context;

class V8Script {
public:
 V8Script(v8::Isolate* isolate, v8::Local<v8::Script> value);
 ~V8Script();

 v8::Local<v8::Script> GetLocal(v8::Isolate* isolate) const { return script_.Get(isolate); }

private:
 friend class Context;

 v8::Global<v8::Script> script_;
 
 DISALLOW_COPY_AND_ASSIGN(V8Script);
};

}

#endif