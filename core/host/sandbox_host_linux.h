// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_SANDBOX_HOST_LINUX_H_
#define CONTENT_BROWSER_SANDBOX_HOST_LINUX_H_

#include <memory>
#include <string>

#include "base/logging.h"
#include "base/macros.h"
#include "base/threading/simple_thread.h"
#include "core/host/sandbox_ipc_linux.h"
#include "core/shared/common/content_export.h"

namespace base {
template <typename T>
struct DefaultSingletonTraits;
}

namespace host {

// This is a singleton object which handles sandbox requests from the
// sandboxed processes.
class CONTENT_EXPORT SandboxHostLinux {
 public:
  // Returns the singleton instance.
  static CONTENT_EXPORT SandboxHostLinux* GetInstance();

  // Get the file descriptor which sandboxed processes should be given in order
  // to communicate with the host. This is used for things like communicating
  // renderer crashes to the host, as well as requesting fonts from sandboxed
  // processes.
  int GetChildSocket() const {
    DCHECK(initialized_);
    return child_socket_;
  }
  void CONTENT_EXPORT Init();

  bool IsInitialized() const { return initialized_; }

 private:
  friend struct base::DefaultSingletonTraits<SandboxHostLinux>;
  // This object must be constructed on the main thread.
  SandboxHostLinux();
  ~SandboxHostLinux();

  bool ShutdownIPCChannel();

  // Whether Init() has been called yet.
  bool initialized_ = false;

  int child_socket_ = 0;
  int childs_lifeline_fd_ = 0;

  std::unique_ptr<SandboxIPCHandler> ipc_handler_;
  std::unique_ptr<base::DelegateSimpleThread> ipc_thread_;

  DISALLOW_COPY_AND_ASSIGN(SandboxHostLinux);
};

}  // namespace host

#endif  // CONTENT_BROWSER_RENDERER_HOST_RENDER_SANDBOX_HOST_LINUX_H_
