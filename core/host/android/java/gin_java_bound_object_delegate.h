// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_ANDROID_JAVA_GIN_JAVA_BOUND_OBJECT_DELEGATE_H_
#define CONTENT_BROWSER_ANDROID_JAVA_GIN_JAVA_BOUND_OBJECT_DELEGATE_H_

#include <stddef.h>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "core/host/android/java/gin_java_bound_object.h"
#include "core/host/android/java/gin_java_method_invocation_helper.h"

namespace host {

class GinJavaBoundObjectDelegate
    : public GinJavaMethodInvocationHelper::ObjectDelegate {
 public:
  GinJavaBoundObjectDelegate(scoped_refptr<GinJavaBoundObject> object);
  ~GinJavaBoundObjectDelegate() override;

  base::android::ScopedJavaLocalRef<jobject> GetLocalRef(JNIEnv* env) override;
  base::android::ScopedJavaLocalRef<jclass> GetLocalClassRef(
      JNIEnv* env) override;
  const JavaMethod* FindMethod(const std::string& method_name,
                               size_t num_parameters) override;
  bool IsObjectGetClassMethod(const JavaMethod* method) override;
  const base::android::JavaRef<jclass>& GetSafeAnnotationClass() override;

 private:
  scoped_refptr<GinJavaBoundObject> object_;

  DISALLOW_COPY_AND_ASSIGN(GinJavaBoundObjectDelegate);
};

}  // namespace host

#endif  // CONTENT_BROWSER_ANDROID_JAVA_GIN_JAVA_BOUND_OBJECT_DELEGATE_H_
