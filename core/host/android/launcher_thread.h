// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_ANDROID_LAUNCHER_THREAD_H
#define CONTENT_BROWSER_ANDROID_LAUNCHER_THREAD_H

#include "base/android/java_handler_thread.h"

#include "base/lazy_instance.h"

namespace base {
class MessageLoop;
}

namespace host {
namespace android {

// This is Android's launcher thread. This should not be used directly in
// native code, but accessed through HostThread(Impl) instead.
class LauncherThread {
 public:
  static base::MessageLoop* GetMessageLoop();

 private:
  friend base::LazyInstanceTraitsBase<LauncherThread>;

  LauncherThread();
  ~LauncherThread();

  base::android::JavaHandlerThread java_handler_thread_;
};

}  // namespace android
}  // namespace host

#endif  // CONTENT_BROWSER_ANDROID_LAUNCHER_THREAD_H
