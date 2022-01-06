// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_ANDROID_JAVA_GIN_JAVA_SCRIPT_TO_JAVA_TYPES_COERCION_H_
#define CONTENT_BROWSER_ANDROID_JAVA_GIN_JAVA_SCRIPT_TO_JAVA_TYPES_COERCION_H_

#include <map>

#include "base/android/jni_weak_ref.h"
#include "base/values.h"
#include "core/host/android/java/gin_java_bound_object.h"
#include "core/host/android/java/java_type.h"
#include "core/common/android/gin_java_bridge_errors.h"

namespace host {

typedef std::map<GinJavaBoundObject::ObjectID, JavaObjectWeakGlobalRef>
    ObjectRefs;

jvalue CoerceJavaScriptValueToJavaValue(
    JNIEnv* env,
    const base::Value* value,
    const JavaType& target_type,
    bool coerce_to_string,
    const ObjectRefs& object_refs,
    GinJavaBridgeError* error);

void ReleaseJavaValueIfRequired(JNIEnv* env,
                                jvalue* value,
                                const JavaType& type);

}  // namespace host

#endif  // CONTENT_BROWSER_ANDROID_JAVA_GIN_JAVA_SCRIPT_TO_JAVA_TYPES_COERCION_H_
