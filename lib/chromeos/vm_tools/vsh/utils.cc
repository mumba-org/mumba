// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/vsh/utils.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/types.h>

#include <base/bind.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <brillo/message_loops/message_loop.h>

using google::protobuf::MessageLite;

namespace vm_tools {
namespace vsh {
namespace {

bool SendAllBytes(int sockfd, const uint8_t* buf, uint32_t buf_size) {
  uint32_t msg_size = htole32(buf_size);

  if (!base::WriteFileDescriptor(
          sockfd, base::as_bytes(base::make_span(&msg_size, 1)))) {
    PLOG(ERROR) << "Failed to write message size to socket";
    return false;
  }

  if (!base::WriteFileDescriptor(
          sockfd, base::as_bytes(base::make_span(buf, buf_size)))) {
    PLOG(ERROR) << "Failed to write message to socket";
    return false;
  }

  return true;
}

ssize_t RecvAllBytes(int sockfd, uint8_t* buf, uint32_t buf_size) {
  uint32_t msg_size;

  if (!base::ReadFromFD(sockfd, reinterpret_cast<char*>(&msg_size),
                        sizeof(msg_size))) {
    PLOG(ERROR) << "Failed to read message size from socket";
    return -1;
  }
  msg_size = le32toh(msg_size);

  if (buf_size < msg_size) {
    LOG(ERROR) << "Message size of " << msg_size << " exceeds buffer size of "
               << buf_size;
    return -1;
  }

  if (!base::ReadFromFD(sockfd, reinterpret_cast<char*>(buf), msg_size)) {
    PLOG(ERROR) << "Failed to read message from socket";
    return -1;
  }

  return msg_size;
}

void ShutdownTask() {
  brillo::MessageLoop::current()->BreakLoop();
}

}  // namespace

bool SendMessage(int sockfd, const MessageLite& message) {
  size_t msg_size = message.ByteSizeLong();
  if (msg_size > kMaxMessageSize) {
    LOG(ERROR) << "Serialized message too large: " << msg_size;
    return false;
  }

  uint8_t buf[kMaxMessageSize];

  if (!message.SerializeToArray(buf, sizeof(buf))) {
    LOG(ERROR) << "Failed to serialize message";
    return false;
  }

  if (!SendAllBytes(sockfd, buf, msg_size)) {
    return false;
  }

  return true;
}

bool RecvMessage(int sockfd, MessageLite* message) {
  ssize_t count;
  uint8_t buf[kMaxMessageSize];

  count = RecvAllBytes(sockfd, buf, sizeof(buf));
  if (count < 0) {
    return false;
  }

  if (!message->ParseFromArray(buf, count)) {
    LOG(ERROR) << "Failed to parse message";
    return false;
  }

  return true;
}

// Posts a shutdown task to the main message loop.
void Shutdown() {
  brillo::MessageLoop::current()->PostTask(FROM_HERE,
                                           base::BindOnce(&ShutdownTask));
}

}  // namespace vsh
}  // namespace vm_tools
