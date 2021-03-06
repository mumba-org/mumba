// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/accessibility/captioning_controller.h"

#include "base/android/jni_string.h"
#include "core/host/application/application_contents.h"
#include "core/common/frame_messages.h"
#include "jni/CaptioningController_jni.h"

using base::android::AttachCurrentThread;
using base::android::ConvertJavaStringToUTF8;
using base::android::JavaParamRef;
using base::android::JavaRef;
using base::android::ScopedJavaLocalRef;

namespace host {

namespace {

int GetRenderProcessIdFromRenderViewHost(RenderViewHost* host) {
  DCHECK(host);
  RenderProcessHost* render_process = host->GetProcess();
  DCHECK(render_process);
  if (render_process->HasConnection())
    return render_process->GetProcess().Handle();
  return 0;
}

}  // namespace

CaptioningController::CaptioningController(JNIEnv* env,
                                           const JavaRef<jobject>& obj,
                                           ApplicationContents* application_contents)
    : WebContentsObserver(application_contents), java_ref_(env, obj) {}

CaptioningController::~CaptioningController() {
  JNIEnv* env = AttachCurrentThread();
  ScopedJavaLocalRef<jobject> obj = java_ref_.get(env);
  if (!obj.is_null())
    Java_CaptioningController_onDestroy(env, obj);
}

void CaptioningController::RenderViewReady() {
  JNIEnv* env = AttachCurrentThread();
  ScopedJavaLocalRef<jobject> obj = java_ref_.get(env);
  if (!obj.is_null())
    Java_CaptioningController_onRenderProcessChange(env, obj);
}

void CaptioningController::RenderViewHostChanged(RenderViewHost* old_host,
                                                 RenderViewHost* new_host) {
  int old_pid = 0;
  if (old_host) {
    old_pid = GetRenderProcessIdFromRenderViewHost(old_host);
  }
  int new_pid =
      GetRenderProcessIdFromRenderViewHost(application_contents()->GetRenderViewHost());
  if (new_pid != old_pid) {
    JNIEnv* env = AttachCurrentThread();
    ScopedJavaLocalRef<jobject> obj = java_ref_.get(env);
    if (!obj.is_null())
      Java_CaptioningController_onRenderProcessChange(env, obj);
  }
}

void CaptioningController::WebContentsDestroyed() {
  delete this;
}

void CaptioningController::SetTextTrackSettings(
    JNIEnv* env,
    const JavaParamRef<jobject>& obj,
    jboolean textTracksEnabled,
    const JavaParamRef<jstring>& textTrackBackgroundColor,
    const JavaParamRef<jstring>& textTrackFontFamily,
    const JavaParamRef<jstring>& textTrackFontStyle,
    const JavaParamRef<jstring>& textTrackFontVariant,
    const JavaParamRef<jstring>& textTrackTextColor,
    const JavaParamRef<jstring>& textTrackTextShadow,
    const JavaParamRef<jstring>& textTrackTextSize) {
  FrameMsg_TextTrackSettings_Params params;
  params.text_tracks_enabled = textTracksEnabled;
  params.text_track_background_color =
      ConvertJavaStringToUTF8(env, textTrackBackgroundColor);
  params.text_track_font_family =
      ConvertJavaStringToUTF8(env, textTrackFontFamily);
  params.text_track_font_style =
      ConvertJavaStringToUTF8(env, textTrackFontStyle);
  params.text_track_font_variant =
      ConvertJavaStringToUTF8(env, textTrackFontVariant);
  params.text_track_text_color =
      ConvertJavaStringToUTF8(env, textTrackTextColor);
  params.text_track_text_shadow =
      ConvertJavaStringToUTF8(env, textTrackTextShadow);
  params.text_track_text_size = ConvertJavaStringToUTF8(env, textTrackTextSize);
  static_cast<ApplicationContents*>(application_contents())
      ->GetMainFrame()
      ->SetTextTrackSettings(params);
}

jlong JNI_CaptioningController_Init(
    JNIEnv* env,
    const JavaParamRef<jobject>& obj,
    const JavaParamRef<jobject>& japplication_contents) {
  ApplicationContents* application_contents = static_cast<ApplicationContents*>(
      ApplicationContents::FromJavaWebContents(japplication_contents));
  CHECK(application_contents);
  return reinterpret_cast<intptr_t>(
      new CaptioningController(env, obj, application_contents));
}

}  // namespace host
