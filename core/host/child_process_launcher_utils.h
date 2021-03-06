// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_PUBLIC_BROWSER_CHILD_PROCESS_LAUNCHER_UTILS_H_
#define CONTENT_PUBLIC_BROWSER_CHILD_PROCESS_LAUNCHER_UTILS_H_

#include "core/shared/common/content_export.h"

namespace base {
class SingleThreadTaskRunner;
}

namespace host {

// The caller must take a reference to the returned TaskRunner pointer if it
// wants to use the pointer directly.
CONTENT_EXPORT base::SingleThreadTaskRunner* GetProcessLauncherTaskRunner();

CONTENT_EXPORT bool CurrentlyOnProcessLauncherTaskRunner();

}  // namespace host

#endif  // CONTENT_PUBLIC_BROWSER_CHILD_PROCESS_LAUNCHER_UTILES_H_
