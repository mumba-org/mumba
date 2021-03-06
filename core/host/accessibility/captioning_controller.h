// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_ACCESSIBILITY_CAPTIONING_CONTROLLER_H_
#define CONTENT_BROWSER_ACCESSIBILITY_CAPTIONING_CONTROLLER_H_

#include "base/android/jni_android.h"
#include "base/android/jni_weak_ref.h"
#include "base/android/scoped_java_ref.h"
#include "base/macros.h"
#include "core/host/application_contents_observer.h"

namespace host {

class ApplicationContents;

// System captioning bridge for Android. Owns itself, and gets destroyed
// together with ApplicationContents.
class CaptioningController : public WebContentsObserver {
 public:
  CaptioningController(JNIEnv* env,
                       const base::android::JavaRef<jobject>& obj,
                       ApplicationContents* application_contents);

  ~CaptioningController() override;

  void SetTextTrackSettings(
      JNIEnv* env,
      const base::android::JavaParamRef<jobject>& obj,
      jboolean textTracksEnabled,
      const base::android::JavaParamRef<jstring>& textTrackBackgroundColor,
      const base::android::JavaParamRef<jstring>& textTrackFontFamily,
      const base::android::JavaParamRef<jstring>& textTrackFontStyle,
      const base::android::JavaParamRef<jstring>& textTrackFontVariant,
      const base::android::JavaParamRef<jstring>& textTrackTextColor,
      const base::android::JavaParamRef<jstring>& textTrackTextShadow,
      const base::android::JavaParamRef<jstring>& textTrackTextSize);

 private:
  // WebContentsObserver implementation.
  void RenderViewReady() override;
  void RenderViewHostChanged(RenderViewHost* old_host,
                             RenderViewHost* new_host) override;
  void WebContentsDestroyed() override;

  // A weak reference to the Java CaptioningController object.
  JavaObjectWeakGlobalRef java_ref_;

  DISALLOW_COPY_AND_ASSIGN(CaptioningController);
};

}  // namespace host

#endif  // CONTENT_BROWSER_ACCESSIBILITY_CAPTIONING_CONTROLLER_H_
