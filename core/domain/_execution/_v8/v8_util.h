// Copyright 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_EXECUTION_V8_V8_UTIL_H_
#define MUMBA_DOMAIN_EXECUTION_V8_V8_UTIL_H_

#include <v8.h>

#include "base/memory/ref_counted.h"

namespace domain {

class V8 {
public:
  static bool NewString(v8::Isolate* isolate, const std::string& string, v8::Local<v8::String>& out);
  
  // TODO: this is all doomed.. we are relying on v8::String::Utf8Value which is scope based
  //       we need to do proper copy and always return a owned heap object, or assign
  //       to a existent one
  static bool AsString(v8::Isolate* isolate, v8::Local<v8::String> v8_str, std::string& out);
  static const char* AsCString(v8::Isolate* isolate, v8::Local<v8::String> v8_str);
  static const char* AsCString(v8::Isolate* isolate, v8::Local<v8::Value> v8_value);

  static int AsInt(v8::Local<v8::Value> v8_value);

  static std::string TypeString(v8::Isolate* isolate, v8::Local<v8::Value> value);

  static bool ToFunction(v8::Local<v8::Value> value, v8::Local<v8::Function>& fun);
};


}

#endif