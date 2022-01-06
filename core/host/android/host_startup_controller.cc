// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/android/host_startup_controller.h"

#include "base/android/jni_android.h"
#include "base/android/jni_string.h"
#include "core/host/android/content_startup_flags.h"
#include "core/host/host_main_loop.h"
#include "ppapi/buildflags/buildflags.h"

#include "jni/HostStartupController_jni.h"

using base::android::JavaParamRef;

namespace host {

void HostStartupComplete(int result) {
  JNIEnv* env = base::android::AttachCurrentThread();
  Java_HostStartupController_hostStartupComplete(env, result);
}

bool ShouldStartGpuProcessOnHostStartup() {
  JNIEnv* env = base::android::AttachCurrentThread();
  return Java_HostStartupController_shouldStartGpuProcessOnHostStartup(
      env);
}

static void JNI_HostStartupController_SetCommandLineFlags(
    JNIEnv* env,
    const JavaParamRef<jclass>& clazz,
    jboolean single_process,
    const JavaParamRef<jstring>& plugin_descriptor) {
  std::string plugin_str =
      (plugin_descriptor == NULL
           ? std::string()
           : base::android::ConvertJavaStringToUTF8(env, plugin_descriptor));
  SetContentCommandLineFlags(static_cast<bool>(single_process), plugin_str);
}

static jboolean JNI_HostStartupController_IsOfficialBuild(
    JNIEnv* env,
    const JavaParamRef<jclass>& clazz) {
#if defined(OFFICIAL_BUILD)
  return true;
#else
  return false;
#endif
}

static jboolean JNI_HostStartupController_IsPluginEnabled(
    JNIEnv* env,
    const JavaParamRef<jclass>& clazz) {
#if BUILDFLAG(ENABLE_PLUGINS)
  return true;
#else
  return false;
#endif
}

static void JNI_HostStartupController_FlushStartupTasks(
    JNIEnv* env,
    const JavaParamRef<jclass>& clazz) {
  HostMainLoop::GetInstance()->SynchronouslyFlushStartupTasks();
}

}  // namespace host
