// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PATCHPANEL_MESSAGE_DISPATCHER_H_
#define PATCHPANEL_MESSAGE_DISPATCHER_H_

#include <memory>
#include <string>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/scoped_file.h>
#include <base/memory/weak_ptr.h>

#include "patchpanel/ipc.pb.h"

namespace patchpanel {

// Helper message processor
class MessageDispatcher {
 public:
  explicit MessageDispatcher(base::ScopedFD fd, bool start = true);
  MessageDispatcher(const MessageDispatcher&) = delete;
  MessageDispatcher& operator=(const MessageDispatcher&) = delete;

  void Start();

  void RegisterFailureHandler(base::RepeatingCallback<void()> handler);

  void RegisterNDProxyMessageHandler(
      base::RepeatingCallback<void(const NDProxyMessage&)> handler);

  void RegisterGuestMessageHandler(
      base::RepeatingCallback<void(const GuestMessage&)> handler);

  void RegisterDeviceMessageHandler(
      base::RepeatingCallback<void(const DeviceMessage&)> handler);

  void SendMessage(const google::protobuf::MessageLite& proto) const;

 private:
  // Overrides MessageLoopForIO callbacks for new data on |control_fd_|.
  void OnFileCanReadWithoutBlocking();

  base::ScopedFD fd_;
  std::unique_ptr<base::FileDescriptorWatcher::Controller> watcher_;
  base::RepeatingCallback<void()> failure_handler_;
  base::RepeatingCallback<void(const NDProxyMessage&)> ndproxy_handler_;
  base::RepeatingCallback<void(const GuestMessage&)> guest_handler_;
  base::RepeatingCallback<void(const DeviceMessage&)> device_handler_;

  IpHelperMessage msg_;

  base::WeakPtrFactory<MessageDispatcher> weak_factory_{this};
};

}  // namespace patchpanel

#endif  // PATCHPANEL_MESSAGE_DISPATCHER_H_
