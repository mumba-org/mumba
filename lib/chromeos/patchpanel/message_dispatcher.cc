// Copyright 2016 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/message_dispatcher.h"

#include <utility>
#include <vector>

#include <base/bind.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/posix/unix_domain_socket.h>

namespace patchpanel {

MessageDispatcher::MessageDispatcher(base::ScopedFD fd, bool start)
    : fd_(std::move(fd)) {
  if (start)
    Start();
}

void MessageDispatcher::Start() {
  watcher_ = base::FileDescriptorWatcher::WatchReadable(
      fd_.get(),
      base::BindRepeating(&MessageDispatcher::OnFileCanReadWithoutBlocking,
                          base::Unretained(this)));
}

void MessageDispatcher::RegisterFailureHandler(
    base::RepeatingCallback<void()> handler) {
  failure_handler_ = std::move(handler);
}

void MessageDispatcher::RegisterNDProxyMessageHandler(
    base::RepeatingCallback<void(const NDProxyMessage&)> handler) {
  ndproxy_handler_ = std::move(handler);
}

void MessageDispatcher::RegisterGuestMessageHandler(
    base::RepeatingCallback<void(const GuestMessage&)> handler) {
  guest_handler_ = std::move(handler);
}

void MessageDispatcher::RegisterDeviceMessageHandler(
    base::RepeatingCallback<void(const DeviceMessage&)> handler) {
  device_handler_ = std::move(handler);
}

void MessageDispatcher::OnFileCanReadWithoutBlocking() {
  char buffer[1024];
  std::vector<base::ScopedFD> fds{};
  ssize_t len =
      base::UnixDomainSocket::RecvMsg(fd_.get(), buffer, sizeof(buffer), &fds);

  if (len <= 0) {
    PLOG(ERROR) << "Read failed: exiting";
    watcher_.reset();
    if (!failure_handler_.is_null())
      failure_handler_.Run();
    return;
  }

  msg_.Clear();
  if (!msg_.ParseFromArray(buffer, len)) {
    LOG(ERROR) << "Error parsing protobuf";
    return;
  }

  if (msg_.has_ndproxy_message() && !ndproxy_handler_.is_null()) {
    ndproxy_handler_.Run(msg_.ndproxy_message());
  }

  if (msg_.has_guest_message() && !guest_handler_.is_null()) {
    guest_handler_.Run(msg_.guest_message());
  }

  if (msg_.has_device_message() && !device_handler_.is_null()) {
    device_handler_.Run(msg_.device_message());
  }
}
void MessageDispatcher::SendMessage(
    const google::protobuf::MessageLite& proto) const {
  std::string str;
  if (!proto.SerializeToString(&str)) {
    LOG(ERROR) << "error serializing protobuf";
  }
  if (write(fd_.get(), str.data(), str.size()) !=
      static_cast<ssize_t>(str.size())) {
    LOG(ERROR) << "short write on protobuf";
  }
}

}  // namespace patchpanel
