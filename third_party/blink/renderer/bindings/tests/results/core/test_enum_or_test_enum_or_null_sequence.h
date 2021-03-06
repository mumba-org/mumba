// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file has been auto-generated from the Jinja2 template
// third_party/blink/renderer/bindings/templates/union_container.h.tmpl
// by the script code_generator_v8.py.
// DO NOT MODIFY!

// clang-format off
#ifndef TestEnumOrTestEnumOrNullSequence_h
#define TestEnumOrTestEnumOrNullSequence_h

#include "base/optional.h"
#include "bindings/core/v8/dictionary.h"
#include "bindings/core/v8/exception_state.h"
#include "bindings/core/v8/native_value_traits.h"
#include "bindings/core/v8/v8_binding_for_core.h"
#include "core/core_export.h"
#include "platform/heap/handle.h"

namespace blink {

class CORE_EXPORT TestEnumOrTestEnumOrNullSequence final {
  DISALLOW_NEW_EXCEPT_PLACEMENT_NEW();
 public:
  TestEnumOrTestEnumOrNullSequence();
  bool IsNull() const { return type_ == SpecificType::kNone; }

  bool IsTestEnum() const { return type_ == SpecificType::kTestEnum; }
  const String& GetAsTestEnum() const;
  void SetTestEnum(const String&);
  static TestEnumOrTestEnumOrNullSequence FromTestEnum(const String&);

  bool IsTestEnumOrNullSequence() const { return type_ == SpecificType::kTestEnumOrNullSequence; }
  const Vector<String>& GetAsTestEnumOrNullSequence() const;
  void SetTestEnumOrNullSequence(const Vector<String>&);
  static TestEnumOrTestEnumOrNullSequence FromTestEnumOrNullSequence(const Vector<String>&);

  TestEnumOrTestEnumOrNullSequence(const TestEnumOrTestEnumOrNullSequence&);
  ~TestEnumOrTestEnumOrNullSequence();
  TestEnumOrTestEnumOrNullSequence& operator=(const TestEnumOrTestEnumOrNullSequence&);
  void Trace(blink::Visitor*);

 private:
  enum class SpecificType {
    kNone,
    kTestEnum,
    kTestEnumOrNullSequence,
  };
  SpecificType type_;

  String test_enum_;
  Vector<String> test_enum_or_null_sequence_;

  friend CORE_EXPORT v8::Local<v8::Value> ToV8(const TestEnumOrTestEnumOrNullSequence&, v8::Local<v8::Object>, v8::Isolate*);
};

class V8TestEnumOrTestEnumOrNullSequence final {
 public:
  CORE_EXPORT static void ToImpl(v8::Isolate*, v8::Local<v8::Value>, TestEnumOrTestEnumOrNullSequence&, UnionTypeConversionMode, ExceptionState&);
};

CORE_EXPORT v8::Local<v8::Value> ToV8(const TestEnumOrTestEnumOrNullSequence&, v8::Local<v8::Object>, v8::Isolate*);

template <class CallbackInfo>
inline void V8SetReturnValue(const CallbackInfo& callbackInfo, TestEnumOrTestEnumOrNullSequence& impl) {
  V8SetReturnValue(callbackInfo, ToV8(impl, callbackInfo.Holder(), callbackInfo.GetIsolate()));
}

template <class CallbackInfo>
inline void V8SetReturnValue(const CallbackInfo& callbackInfo, TestEnumOrTestEnumOrNullSequence& impl, v8::Local<v8::Object> creationContext) {
  V8SetReturnValue(callbackInfo, ToV8(impl, creationContext, callbackInfo.GetIsolate()));
}

template <>
struct NativeValueTraits<TestEnumOrTestEnumOrNullSequence> : public NativeValueTraitsBase<TestEnumOrTestEnumOrNullSequence> {
  CORE_EXPORT static TestEnumOrTestEnumOrNullSequence NativeValue(v8::Isolate*, v8::Local<v8::Value>, ExceptionState&);
  CORE_EXPORT static TestEnumOrTestEnumOrNullSequence NullValue() { return TestEnumOrTestEnumOrNullSequence(); }
};

template <>
struct V8TypeOf<TestEnumOrTestEnumOrNullSequence> {
  typedef V8TestEnumOrTestEnumOrNullSequence Type;
};

}  // namespace blink

// We need to set canInitializeWithMemset=true because HeapVector supports
// items that can initialize with memset or have a vtable. It is safe to
// set canInitializeWithMemset=true for a union type object in practice.
// See https://codereview.chromium.org/1118993002/#msg5 for more details.
WTF_ALLOW_MOVE_AND_INIT_WITH_MEM_FUNCTIONS(blink::TestEnumOrTestEnumOrNullSequence);

#endif  // TestEnumOrTestEnumOrNullSequence_h
