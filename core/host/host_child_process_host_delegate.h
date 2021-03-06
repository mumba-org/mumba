// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_PUBLIC_BROWSER_BROWSER_CHILD_PROCESS_HOST_DELEGATE_H_
#define CONTENT_PUBLIC_BROWSER_BROWSER_CHILD_PROCESS_HOST_DELEGATE_H_

#include "core/shared/common/content_export.h"
#include "ipc/ipc_listener.h"

namespace host {

// Interface that all users of HostChildProcessHost need to provide.
class CONTENT_EXPORT HostChildProcessHostDelegate : public IPC::Listener {
 public:
  ~HostChildProcessHostDelegate() override {}

  // Called when the process has been started.
  virtual void OnProcessLaunched() {}

  // Called if the process failed to launch.  In this case the process never
  // started so the code here is a platform specific error code.
  virtual void OnProcessLaunchFailed(int error_code) {}

  // Called if the process crashed. |exit_code| is the status returned when the
  // process crashed (for posix, as returned from waitpid(), for Windows, as
  // returned from GetExitCodeProcess()).
  virtual void OnProcessCrashed(int exit_code) {}
};

};  // namespace host

#endif  // CONTENT_PUBLIC_BROWSER_BROWSER_CHILD_PROCESS_HOST_DELEGATE_H_
