// Copyright 2016 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PATCHPANEL_HELPER_PROCESS_H_
#define PATCHPANEL_HELPER_PROCESS_H_

#include <sys/types.h>

#include <memory>
#include <string>
#include <vector>

#include <base/files/scoped_file.h>
#include <google/protobuf/message_lite.h>

#include "patchpanel/message_dispatcher.h"

namespace patchpanel {

// Tracks a helper subprocess.  Handles forking, cleaning up on termination,
// and IPC.
// This object is used by the main Manager process.
class HelperProcess {
 public:
  HelperProcess() = default;
  HelperProcess(const HelperProcess&) = delete;
  HelperProcess& operator=(const HelperProcess&) = delete;

  virtual ~HelperProcess() = default;

  // Re-execs patchpanel with a new argument: "|fd_arg|=N", where N is the
  // side of |control_fd|.  This tells the subprocess to start up a different
  // mainloop.
  void Start(int argc, char* argv[], const std::string& fd_arg);

  // Attempts to restart the process with the original arguments.
  // Returns false if the maximum number of restarts has been exceeded.
  bool Restart();

  // Serializes a protobuf and sends it to the helper process.
  void SendMessage(const google::protobuf::MessageLite& proto) const;

  // Start listening on messages from subprocess and dispatching them to
  // handlers. This function can only be called after that the message loop of
  // main process is initialized.
  void Listen();

  void RegisterNDProxyMessageHandler(
      base::RepeatingCallback<void(const NDProxyMessage&)> handler);

  pid_t pid() const { return pid_; }
  uint8_t restarts() const { return restarts_; }

 private:
  void Launch();

  pid_t pid_{0};
  uint8_t restarts_{0};
  std::vector<std::string> argv_;
  std::string fd_arg_;
  std::unique_ptr<MessageDispatcher> msg_dispatcher_;
};

}  // namespace patchpanel

#endif  // PATCHPANEL_HELPER_PROCESS_H_
