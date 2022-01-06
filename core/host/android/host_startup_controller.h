// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_ANDROID_BROWSER_STARTUP_CONTROLLER_H_
#define CONTENT_BROWSER_ANDROID_BROWSER_STARTUP_CONTROLLER_H_

namespace host {

void HostStartupComplete(int result);
bool ShouldStartGpuProcessOnHostStartup();

}  // namespace host
#endif  // CONTENT_BROWSER_ANDROID_BROWSER_STARTUP_CONTROLLER_H_
