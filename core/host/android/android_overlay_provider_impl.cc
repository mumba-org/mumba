// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/android/android_overlay_provider_impl.h"

#include "jni/AndroidOverlayProviderImpl_jni.h"

using base::android::AttachCurrentThread;
using base::android::ScopedJavaLocalRef;

namespace host {

// static
AndroidOverlayProvider* AndroidOverlayProvider::GetInstance() {
  static AndroidOverlayProvider* instance = nullptr;
  if (!instance)
    instance = new AndroidOverlayProviderImpl();

  return instance;
}

AndroidOverlayProviderImpl::AndroidOverlayProviderImpl() {}

AndroidOverlayProviderImpl::~AndroidOverlayProviderImpl() {}

bool AndroidOverlayProviderImpl::AreOverlaysSupported() const {
  JNIEnv* env = AttachCurrentThread();

  return Java_AndroidOverlayProviderImpl_areOverlaysSupported(env);
}

}  // namespace host
