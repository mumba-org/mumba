// Copyright 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/execution/v8/v8_util.h"

namespace domain {

// static
bool V8::NewString(v8::Isolate* isolate, const std::string& str, v8::Local<v8::String>& out) {
  out = v8::String::NewFromUtf8(isolate, str.c_str(), v8::NewStringType::kNormal)
          .ToLocalChecked();
  return true;
}

// static 
std::string V8::TypeString(v8::Isolate* isolate, v8::Local<v8::Value> value) {
  v8::Local<v8::String> type = value->TypeOf(isolate);
  return std::string(*v8::String::Utf8Value(isolate, type));
}

// static
bool V8::AsString(v8::Isolate* isolate, v8::Local<v8::String> v8_str, std::string& out) {
  out = std::string(*v8::String::Utf8Value(isolate, v8_str));
  return true;
}

// static 
const char* V8::AsCString(v8::Isolate* isolate, v8::Local<v8::String> v8_str) {
  return *v8::String::Utf8Value(isolate, v8_str); 
}

// static 
const char* V8::AsCString(v8::Isolate* isolate,  v8::Local<v8::Value> v8_value) {
 return *v8::String::Utf8Value(isolate, v8::Local<v8::String>::Cast(v8_value));
}

// static 
int V8::AsInt(v8::Local<v8::Value> v8_value) {
 v8::Local<v8::Int32> int_val = v8::Local<v8::Int32>::Cast(v8_value);
 return int_val->Value();
}

// static 
bool V8::ToFunction(v8::Local<v8::Value> value, v8::Local<v8::Function>& out) {
 out = v8::Local<v8::Function>::Cast(value);
 return true;
}

}