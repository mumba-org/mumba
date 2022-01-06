// Copyright 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/execution/v8/v8_value.h"
#include "base/strings/string_number_conversions.h"

namespace domain {

// static 
std::unique_ptr<V8Value> V8Value::FromBool(ExecutionContext* context, bool value) {
  v8::Isolate* isolate = context->isolate();
  v8::Isolate::Scope scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Boolean> v8_value = v8::Boolean::New(isolate, value);
  return std::unique_ptr<V8Value>(new V8Value(context, v8_value));
}
// static 
std::unique_ptr<V8Value> V8Value::FromInt64(ExecutionContext* context, int64_t value) {
  v8::Isolate* isolate = context->isolate();
  v8::Isolate::Scope scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Integer> v8_value = v8::Integer::New(isolate, static_cast<int32_t>(value));
  return std::unique_ptr<V8Value>(new V8Value(context, v8_value));
}
// static 
std::unique_ptr<V8Value> V8Value::FromInt32(ExecutionContext* context, int32_t value) {
  v8::Isolate* isolate = context->isolate();
  v8::Isolate::Scope scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Integer> v8_value = v8::Integer::New(isolate, value);
  return std::unique_ptr<V8Value>(new V8Value(context, v8_value));
}
// static 
std::unique_ptr<V8Value> V8Value::FromUInt32(ExecutionContext* context, uint32_t value) {
  v8::Isolate* isolate = context->isolate();
  v8::Isolate::Scope scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Integer> v8_value = v8::Integer::NewFromUnsigned(isolate, value);
  return std::unique_ptr<V8Value>(new V8Value(context, v8_value));
}
// static 
std::unique_ptr<V8Value> V8Value::FromDouble(ExecutionContext* context, double value) {
  v8::Isolate* isolate = context->isolate();
  v8::Isolate::Scope scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Number> v8_value = v8::Number::New(isolate, value);
  return std::unique_ptr<V8Value>(new V8Value(context, v8_value));
}
// static 
std::unique_ptr<V8Value> V8Value::FromString(ExecutionContext* context, const std::string& value) {
  v8::Isolate* isolate = context->isolate();
  v8::Isolate::Scope scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::String> v8_value = v8::String::NewFromUtf8(isolate, value.c_str(), v8::String::kNormalString, value.size());
  return std::unique_ptr<V8Value>(new V8Value(context, v8_value));
}
// static 
std::unique_ptr<V8ValueArray> V8Value::FromStringArray(ExecutionContext* context, const std::vector<std::string>& value) {
  //DLOG(INFO) << "V8Value::FromStringArray";
  v8::Isolate* isolate = context->isolate();
  v8::Isolate::Scope scope(isolate);
  v8::HandleScope handle_scope(isolate);

  size_t index = 0;
  std::unique_ptr<v8::Global<v8::Value>[]> arr(new v8::Global<v8::Value>[value.size()]);
  for (auto it = value.begin(); it != value.end(); ++it) {
    arr[index++].Reset(isolate, v8::String::NewFromUtf8(isolate, (*it).c_str(), v8::String::kNormalString, (*it).size()));
  }

  //DLOG(INFO) << "V8Value::FromStringArray end";
  return std::unique_ptr<V8ValueArray>(new V8ValueArray(std::move(arr), value.size(), value.size()));
}

// static 
std::unique_ptr<V8ValueArray> V8Value::FromStringArray(ExecutionContext* context, const std::string* values, size_t size) {
  v8::Isolate* isolate = context->isolate();
  v8::Isolate::Scope scope(isolate);
  v8::HandleScope handle_scope(isolate);

  std::unique_ptr<v8::Global<v8::Value>[]> arr(new v8::Global<v8::Value>[size]);
  for (size_t i = 0; i < size; i++) {
    arr[i].Reset(isolate, v8::String::NewFromUtf8(isolate, values[i].c_str(), v8::String::kNormalString, values[i].size()));
  }

  //DLOG(INFO) << "V8Value::FromStringArray end";
  return std::unique_ptr<V8ValueArray>(new V8ValueArray(std::move(arr), size, size)); 
}

// static 
std::unique_ptr<V8ValueArray> V8Value::FromStringToIntArray(ExecutionContext* context, const std::vector<std::string>& value) {
  v8::Isolate* isolate = context->isolate();
  v8::Isolate::Scope scope(isolate);
  v8::HandleScope handle_scope(isolate);

  size_t index = 0;
  std::unique_ptr<v8::Global<v8::Value>[]> arr(new v8::Global<v8::Value>[value.size()]);

  for (auto it = value.begin(); it != value.end(); ++it) {
    int ival = 0;
    base::StringToInt((*it), &ival);
    arr[index++].Reset(isolate, v8::Integer::New(isolate, ival));
  }

  //DLOG(INFO) << "V8Value::FromStringArray end";
  return std::unique_ptr<V8ValueArray>(new V8ValueArray(std::move(arr), value.size(), value.size()));
}

//static 
std::unique_ptr<V8ValueArray> V8Value::FromStringToIntArray(ExecutionContext* context, const std::string* values, size_t size) {
  v8::Isolate* isolate = context->isolate();
  v8::Isolate::Scope scope(isolate);
  v8::HandleScope handle_scope(isolate);

  std::unique_ptr<v8::Global<v8::Value>[]> arr(new v8::Global<v8::Value>[size]);
  for (size_t i = 0; i < size; i++) {
    int ival = 0;
    base::StringToInt(values[i], &ival);
    arr[i].Reset(isolate, v8::Integer::New(isolate, ival));
  }

  return std::unique_ptr<V8ValueArray>(new V8ValueArray(std::move(arr), size, size)); 
}

// static 
std::unique_ptr<V8ValueArray> V8Value::FromStringToDoubleArray(ExecutionContext* context, const std::vector<std::string>& value) {
  v8::Isolate* isolate = context->isolate();
  v8::Isolate::Scope scope(isolate);
  v8::HandleScope handle_scope(isolate);

  size_t index = 0;
  std::unique_ptr<v8::Global<v8::Value>[]> arr(new v8::Global<v8::Value>[value.size()]);

  for (auto it = value.begin(); it != value.end(); ++it) {
    double dval = 0;
    base::StringToDouble((*it), &dval);
    arr[index++].Reset(isolate, v8::Integer::New(isolate, dval));
  }

  return std::unique_ptr<V8ValueArray>(new V8ValueArray(std::move(arr), value.size(), value.size()));
}

// static 
std::unique_ptr<V8ValueArray> V8Value::FromStringToDoubleArray(ExecutionContext* context, const std::string* values, size_t size) {
  v8::Isolate* isolate = context->isolate();
  v8::Isolate::Scope scope(isolate);
  v8::HandleScope handle_scope(isolate);

  std::unique_ptr<v8::Global<v8::Value>[]> arr(new v8::Global<v8::Value>[size]);
  for (size_t i = 0; i < size; i++) {
    double dval = 0;
    base::StringToDouble(values[i], &dval);
    arr[i].Reset(isolate, v8::Number::New(isolate, dval));
  }

  return std::unique_ptr<V8ValueArray>(new V8ValueArray(std::move(arr), size, size));
}

// static 
std::unique_ptr<V8ValueArray> V8Value::FromIntArray(ExecutionContext* context, const std::vector<int>& value) {
  v8::Isolate* isolate = context->isolate();
  v8::Isolate::Scope scope(isolate);
  v8::HandleScope handle_scope(isolate);

  size_t index = 0;
  std::unique_ptr<v8::Global<v8::Value>[]> arr(new v8::Global<v8::Value>[value.size()]);
  for (auto it = value.begin(); it != value.end(); ++it) {
    arr[index++].Reset(isolate, v8::Integer::New(isolate, *it));
  }
  return std::unique_ptr<V8ValueArray>(new V8ValueArray(std::move(arr), value.size(), value.size()));
}

// static 
std::unique_ptr<V8ValueArray> V8Value::FromIntArray(ExecutionContext* context, const int* values, size_t size) {
  v8::Isolate* isolate = context->isolate();
  v8::Isolate::Scope scope(isolate);
  v8::HandleScope handle_scope(isolate);

  std::unique_ptr<v8::Global<v8::Value>[]> arr(new v8::Global<v8::Value>[size]);
  for (size_t i = 0; i < size; i++) {
    arr[i].Reset(isolate, v8::Integer::New(isolate, values[i]));
  }

  //DLOG(INFO) << "V8Value::FromStringArray end";
  return std::unique_ptr<V8ValueArray>(new V8ValueArray(std::move(arr), size, size)); 
}

// static 
std::unique_ptr<V8ValueArray> V8Value::FromInt64Array(ExecutionContext* context, const std::vector<int64_t>& value) {
  v8::Isolate* isolate = context->isolate();
  v8::Isolate::Scope scope(isolate);
  v8::HandleScope handle_scope(isolate);

  size_t index = 0;
  std::unique_ptr<v8::Global<v8::Value>[]> arr(new v8::Global<v8::Value>[value.size()]);
  
  for (auto it = value.begin(); it != value.end(); ++it) {
    arr[index++].Reset(isolate, v8::Integer::New(isolate, *it));
  }
  
  return std::unique_ptr<V8ValueArray>(new V8ValueArray(std::move(arr), value.size(), value.size()));
}

// static 
std::unique_ptr<V8ValueArray> V8Value::FromInt64Array(ExecutionContext* context, const int64_t* values, size_t size) {
  v8::Isolate* isolate = context->isolate();
  v8::Isolate::Scope scope(isolate);
  v8::HandleScope handle_scope(isolate);

  std::unique_ptr<v8::Global<v8::Value>[]> arr(new v8::Global<v8::Value>[size]);
  
  for (size_t i = 0; i < size; i++) {
    arr[i].Reset(isolate, v8::Integer::New(isolate, values[i]));
  }

  return std::unique_ptr<V8ValueArray>(new V8ValueArray(std::move(arr), size, size)); 
}

// static 
std::unique_ptr<V8ValueArray> V8Value::FromDoubleArray(ExecutionContext* context, const std::vector<double>& value) {
  v8::Isolate* isolate = context->isolate();
  v8::Isolate::Scope scope(isolate);
  v8::HandleScope handle_scope(isolate);

  size_t index = 0;
  std::unique_ptr<v8::Global<v8::Value>[]> arr(new v8::Global<v8::Value>[value.size()]);
  for (auto it = value.begin(); it != value.end(); ++it) {
    arr[index++].Reset(isolate, v8::Number::New(isolate, *it));
  }
  return std::unique_ptr<V8ValueArray>(new V8ValueArray(std::move(arr), value.size(), value.size()));
}

// static 
std::unique_ptr<V8ValueArray> V8Value::FromDoubleArray(ExecutionContext* context, const double* values, size_t size) {
  v8::Isolate* isolate = context->isolate();
  v8::Isolate::Scope scope(isolate);
  v8::HandleScope handle_scope(isolate);

  std::unique_ptr<v8::Global<v8::Value>[]> arr(new v8::Global<v8::Value>[size]);
  for (size_t i = 0; i < size; i++) {
    arr[i].Reset(isolate, v8::Number::New(isolate, values[i]));
  }

  //DLOG(INFO) << "V8Value::FromStringArray end";
  return std::unique_ptr<V8ValueArray>(new V8ValueArray(std::move(arr), size, size)); 
}

// static 
std::unique_ptr<V8ValueArray> V8Value::New(ExecutionContext* context, size_t size) {
 v8::Isolate* isolate = context->isolate();
  v8::Isolate::Scope scope(isolate);
  v8::HandleScope handle_scope(isolate);

  std::unique_ptr<v8::Global<v8::Value>[]> arr(new v8::Global<v8::Value>[size]);
  return std::unique_ptr<V8ValueArray>(new V8ValueArray(std::move(arr), size));  
}

V8Value::V8Value(ExecutionContext* context, v8::Local<v8::Value> value): 
  context_(context), 
  handle_(context->isolate(), value) {

}

V8Value::~V8Value() {
  handle_.Reset();
}

bool V8Value::ToBool() {
  v8::Isolate* isolate = context_->isolate();
  v8::Isolate::Scope scope(isolate);
  v8::HandleScope handle_scope(isolate);
  return handle()->BooleanValue(context_->handle()).ToChecked();
}

double V8Value::ToDouble() {
  v8::Isolate* isolate = context_->isolate();
  v8::Isolate::Scope scope(isolate);
  v8::HandleScope handle_scope(isolate);
  return handle()->NumberValue(context_->handle()).ToChecked();
}

int64_t V8Value::ToInt64() {
  v8::Isolate* isolate = context_->isolate();
  v8::Isolate::Scope scope(isolate);
  v8::HandleScope handle_scope(isolate);
  return handle()->IntegerValue(context_->handle()).ToChecked();
}

int32_t V8Value::ToInt32() {
  v8::Isolate* isolate = context_->isolate();
  v8::Isolate::Scope scope(isolate);
  v8::HandleScope handle_scope(isolate);
  return handle()->Int32Value(context_->handle()).ToChecked();
}

uint32_t V8Value::ToUint32() {
  v8::Isolate* isolate = context_->isolate();
  v8::Isolate::Scope scope(isolate);
  v8::HandleScope handle_scope(isolate);
  return handle()->Uint32Value(context_->handle()).ToChecked();
}

std::string V8Value::ToString() {
  v8::Isolate* isolate = context_->isolate();
  v8::Isolate::Scope scope(isolate);
  v8::HandleScope handle_scope(isolate);
  return std::string(*v8::String::Utf8Value(isolate, v8::Local<v8::String>::Cast(handle())));
}

std::string V8Value::TypeString() {
  v8::Isolate* isolate = context_->isolate();
  v8::Isolate::Scope scope(isolate);
  v8::HandleScope handle_scope(isolate);
  v8::Local<v8::String> type = handle()->TypeOf(isolate);
  return std::string(*v8::String::Utf8Value(isolate, type));
}

V8ValueArray::V8ValueArray(std::unique_ptr<v8::Global<v8::Value>[]> array, size_t size, size_t pos): array_(std::move(array)), 
  size_(size), 
  pos_(pos) {

}

V8ValueArray::~V8ValueArray() {
  for (size_t i = 0; i < size_; i++) {
    array_[i].Reset();
  }
}

void V8ValueArray::AppendBool(ExecutionContext* context, bool value) {
  DCHECK(pos_ <  size_);
  v8::Isolate* isolate = context->isolate();
  v8::Isolate::Scope scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Boolean> v8_value = v8::Boolean::New(isolate, value);
  array_[pos_].Reset(isolate, v8_value);
  pos_++;
}

void V8ValueArray::AppendInt(ExecutionContext* context, int value) {
  DCHECK(pos_ <  size_);
  v8::Isolate* isolate = context->isolate();
  v8::Isolate::Scope scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Integer> v8_value = v8::Integer::New(isolate, value);
  array_[pos_].Reset(isolate, v8_value);
  pos_++;
}

void V8ValueArray::AppendDouble(ExecutionContext* context, double value) {
  DCHECK(pos_ <  size_);
  v8::Isolate* isolate = context->isolate();
  v8::Isolate::Scope scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Number> v8_value = v8::Number::New(isolate, value);
  array_[pos_].Reset(isolate, v8_value);
  pos_++;
}

void V8ValueArray::AppendString(ExecutionContext* context, const std::string& value) {
  DCHECK(pos_ <  size_);
  v8::Isolate* isolate = context->isolate();
  v8::Isolate::Scope scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::String> v8_value = v8::String::NewFromUtf8(isolate, value.c_str(), v8::String::kNormalString, value.size()); 
  array_[pos_].Reset(isolate, v8_value);
  pos_++;
}

V8ValueArrayBuilder::V8ValueArrayBuilder(ExecutionContext* context, size_t len): 
  context_(context), 
  array_(new v8::Global<v8::Value>[len]), 
  len_(len), 
  offset_(0) {
}

void V8ValueArrayBuilder::PushBool(bool value) {
  v8::Isolate* isolate = context_->isolate();
  v8::Isolate::Scope scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Boolean> v8_value = v8::Boolean::New(isolate, value);
  array_[offset_].Reset(isolate, v8_value);
  offset_++;
}

void V8ValueArrayBuilder::PushInt(int value) {
  v8::Isolate* isolate = context_->isolate();
  v8::Isolate::Scope scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Integer> v8_value = v8::Integer::New(isolate, value);
  array_[offset_].Reset(isolate, v8_value);
  offset_++;
}

void V8ValueArrayBuilder::PushDouble(double value) {
  v8::Isolate* isolate = context_->isolate();
  v8::Isolate::Scope scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Number> v8_value = v8::Number::New(isolate, value);
  array_[offset_].Reset(isolate, v8_value);
  offset_++;
}

void V8ValueArrayBuilder::PushString(const std::string& value) {
  v8::Isolate* isolate = context_->isolate();
  v8::Isolate::Scope scope(isolate);
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::String> v8_value = v8::String::NewFromUtf8(isolate, value.c_str(), v8::String::kNormalString, value.size());
  array_[offset_].Reset(isolate, v8_value);
  offset_++;
}

std::unique_ptr<V8ValueArray> V8ValueArrayBuilder::Build() {
  return std::unique_ptr<V8ValueArray>(new V8ValueArray(std::move(array_), len_));  
}

}