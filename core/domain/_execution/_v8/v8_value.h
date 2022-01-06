// Copyright 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_EXECUTION_V8_V8_VALUE_H_
#define MUMBA_DOMAIN_EXECUTION_V8_V8_VALUE_H_

#include <string>
#include <v8.h>

#include "core/domain/execution/execution_context.h"

namespace domain {
class V8ValueArray;

class V8Value {
public:

  static std::unique_ptr<V8Value> FromBool(ExecutionContext* context, bool value);
  static std::unique_ptr<V8Value> FromInt64(ExecutionContext* context, int64_t value);
  static std::unique_ptr<V8Value> FromInt32(ExecutionContext* context, int32_t value);
  static std::unique_ptr<V8Value> FromUInt32(ExecutionContext* context, uint32_t value);
  static std::unique_ptr<V8Value> FromDouble(ExecutionContext* context, double value);
  static std::unique_ptr<V8Value> FromString(ExecutionContext* context, const std::string& value);
  static std::unique_ptr<V8ValueArray> FromStringArray(ExecutionContext* context, const std::vector<std::string>& value);
  static std::unique_ptr<V8ValueArray> FromStringArray(ExecutionContext* context, const std::string* values, size_t size);
  static std::unique_ptr<V8ValueArray> FromStringToIntArray(ExecutionContext* context, const std::vector<std::string>& value);
  static std::unique_ptr<V8ValueArray> FromStringToIntArray(ExecutionContext* context, const std::string* values, size_t size);
  static std::unique_ptr<V8ValueArray> FromStringToDoubleArray(ExecutionContext* context, const std::vector<std::string>& value);
  static std::unique_ptr<V8ValueArray> FromStringToDoubleArray(ExecutionContext* context, const std::string* values, size_t size);
  static std::unique_ptr<V8ValueArray> FromIntArray(ExecutionContext* context, const std::vector<int>& value);
  static std::unique_ptr<V8ValueArray> FromIntArray(ExecutionContext* context, const int* values, size_t size);
  static std::unique_ptr<V8ValueArray> FromInt64Array(ExecutionContext* context, const std::vector<int64_t>& value);
  static std::unique_ptr<V8ValueArray> FromInt64Array(ExecutionContext* context, const int64_t* values, size_t size);
  static std::unique_ptr<V8ValueArray> FromDoubleArray(ExecutionContext* context, const std::vector<double>& value);
  static std::unique_ptr<V8ValueArray> FromDoubleArray(ExecutionContext* context, const double* values, size_t size);
  static std::unique_ptr<V8ValueArray> New(ExecutionContext* context, size_t size);

  V8Value(ExecutionContext* context, v8::Local<v8::Value> value);
  ~V8Value();

  ExecutionContext* context() const { return context_; }

  inline v8::Local<v8::Value> handle() const { return handle_.Get(context_->isolate()); }
  
  bool IsUndefined() const { return handle()->IsUndefined(); }
  bool IsNull() const { return handle()->IsNull(); }
  bool IsNullOrUndefined() const { return handle()->IsNullOrUndefined(); }
  bool IsTrue() const { return handle()->IsTrue(); }
  bool IsFalse() const { return handle()->IsFalse(); }
  bool IsName() const { return handle()->IsName(); }
  bool IsString() const { return handle()->IsString(); }
  bool IsSymbol() const { return handle()->IsSymbol(); }
  bool IsFunction() const { return handle()->IsFunction(); }
  bool IsArray() const { return handle()->IsArray(); }
  bool IsObject() const { return handle()->IsObject(); }
  bool IsBoolean() const { return handle()->IsBoolean(); }
  bool IsNumber() const { return handle()->IsNumber(); }
  bool IsExternal() const { return handle()->IsExternal(); }
  bool IsInt32() const { return handle()->IsInt32(); }
  bool IsUint32() const { return handle()->IsUint32(); }
  bool IsDate() const { return handle()->IsDate(); }
  bool IsArgumentsObject() const { return handle()->IsArgumentsObject(); }
  bool IsBooleanObject() const { return handle()->IsBooleanObject(); }
  bool IsNumberObject() const { return handle()->IsNumberObject(); }
  bool IsStringObject() const { return handle()->IsStringObject(); }
  bool IsSymbolObject() const { return handle()->IsSymbolObject(); }
  bool IsNativeError() const { return handle()->IsNativeError(); }
  bool IsRegExp() const { return handle()->IsRegExp();}
  bool IsAsyncFunction() const { return handle()->IsAsyncFunction();}
  bool IsGeneratorFunction() const { return handle()->IsGeneratorFunction();}
  bool IsGeneratorObject() const { return handle()->IsGeneratorObject();}
  bool IsPromise() const { return handle()->IsPromise();}
  bool IsMap() const { return handle()->IsMap();}
  bool IsSet() const { return handle()->IsSet();}
  bool IsMapIterator() const { return handle()->IsMapIterator();}
  bool IsSetIterator() const { return handle()->IsSetIterator();}
  bool IsWeakMap() const { return handle()->IsWeakMap();}
  bool IsWeakSet() const { return handle()->IsWeakSet();}
  bool IsArrayBuffer() const { return handle()->IsArrayBuffer();}
  bool IsArrayBufferView() const { return handle()->IsArrayBufferView();}
  bool IsTypedArray() const { return handle()->IsTypedArray();}
  bool IsUint8Array() const { return handle()->IsUint8Array();}
  bool IsUint8ClampedArray() const { return handle()->IsUint8ClampedArray();}
  bool IsInt8Array() const { return handle()->IsInt8Array();}
  bool IsUint16Array() const { return handle()->IsUint16Array();}
  bool IsInt16Array() const { return handle()->IsInt16Array();}
  bool IsUint32Array() const { return handle()->IsUint32Array();}
  bool IsInt32Array() const { return handle()->IsInt32Array();}
  bool IsFloat32Array() const { return handle()->IsFloat32Array();}
  bool IsFloat64Array() const { return handle()->IsFloat64Array();}
  bool IsDataView() const { return handle()->IsDataView();}
  bool IsSharedArrayBuffer() const { return handle()->IsSharedArrayBuffer();}
  bool IsProxy() const { return handle()->IsProxy(); }

  bool ToBool();
  double ToDouble();
  int64_t ToInt64();
  int32_t ToInt32();
  uint32_t ToUint32();
  std::string ToString();

  std::string TypeString();  

private:
 
 ExecutionContext* context_;

 v8::Global<v8::Value> handle_;

 //v8::Global<v8::Value[]> array_;

 //bool is_array_;

 DISALLOW_COPY_AND_ASSIGN(V8Value);  
};

class V8ValueArray {
public:
 
  V8ValueArray(
    std::unique_ptr<v8::Global<v8::Value>[]> array, 
    size_t size,
    size_t pos = 0);
 
  ~V8ValueArray(); 

  inline size_t size() const { return size_; }

  inline v8::Global<v8::Value>* array() const { 
    return array_.get(); 
  }

  std::vector<v8::Local<v8::Value>> GetValues(ExecutionContext* context) const {
    std::vector<v8::Local<v8::Value>> argv;
    for (size_t i = 0; i < size_; ++i) {
      argv.push_back(array()[i].Get(context->isolate()));
    }
    return argv;
  }

  void AppendBool(ExecutionContext* context, bool value);
  void AppendInt(ExecutionContext* context, int value);
  void AppendDouble(ExecutionContext* context, double value);
  void AppendString(ExecutionContext* context, const std::string& value);

private: 
  std::unique_ptr<v8::Global<v8::Value>[]> array_;

  size_t size_;

  size_t pos_;

  DISALLOW_COPY_AND_ASSIGN(V8ValueArray); 
};

class V8ValueArrayBuilder {
public:
  
  V8ValueArrayBuilder(ExecutionContext* context, size_t len);
  
  void PushBool(bool value);
  void PushInt(int value);
  void PushDouble(double value);
  void PushString(const std::string& value);
  std::unique_ptr<V8ValueArray> Build();

private:
  ExecutionContext* context_;
  std::unique_ptr<v8::Global<v8::Value>[]> array_;
  size_t len_;
  size_t offset_;

  DISALLOW_COPY_AND_ASSIGN(V8ValueArrayBuilder);
};

}

#endif