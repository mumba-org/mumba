// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/sensor_service/sensor_data_forwarder.h"

#include <poll.h>
#include <unistd.h>

#include <array>
#include <utility>

#include <base/bind.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/task/task_runner.h>

namespace arc {

SensorDataForwarder::SensorDataForwarder(base::ScopedFD fd_in,
                                         base::ScopedFD fd_out)
    : fd_in_(std::move(fd_in)),
      fd_out_(std::move(fd_out)),
      thread_("SensorDataForwarder") {
  DCHECK(fd_in_.is_valid());
  DCHECK(fd_out_.is_valid());
}

SensorDataForwarder::~SensorDataForwarder() {
  // Close cancel_pipe_in_ to unblock ForwardData().
  cancel_pipe_in_.reset();
}

bool SensorDataForwarder::Init() {
  if (!base::CreatePipe(&cancel_pipe_in_, &cancel_pipe_out_)) {
    PLOG(ERROR) << "Failed to create a cancel pipe.";
    return false;
  }
  if (!thread_.Start()) {
    LOG(ERROR) << "Failed to start the thread.";
    return false;
  }
  thread_.task_runner()->PostTask(
      FROM_HERE, base::BindOnce(&SensorDataForwarder::ForwardData,
                                base::Unretained(this)));
  return true;
}

void SensorDataForwarder::ForwardData() {
  while (true) {
    // Wait for the FD to be readable.
    if (!PollFd(fd_in_.get(), POLLIN)) {
      return;
    }
    // Read the data from the FD.
    char buf[4096];
    ssize_t read_size = HANDLE_EINTR(read(fd_in_.get(), buf, sizeof(buf)));
    if (read_size < 0) {
      PLOG(ERROR) << "read failed";
      return;
    }

    for (ssize_t written = 0; written < read_size;) {
      // Wait for the FD to be writable.
      if (!PollFd(fd_out_.get(), POLLOUT)) {
        return;
      }
      // Write the data to the FD.
      ssize_t r = HANDLE_EINTR(
          write(fd_out_.get(), buf + written, read_size - written));
      if (r < 0) {
        PLOG(ERROR) << "write failed";
        return;
      }
      written += r;
    }
  }
}

bool SensorDataForwarder::PollFd(int fd, int16_t events) {
  std::array<struct pollfd, 2> fds{{
      {.fd = cancel_pipe_out_.get(), .events = POLLIN},
      {.fd = fd, .events = events},
  }};
  if (HANDLE_EINTR(poll(fds.data(), fds.size(), /*timeout=*/-1)) < 0) {
    PLOG(ERROR) << "poll failed. events = " << events;
    return false;
  }
  // Receiving an event on cancel_pipe_out_ means cancel_pipe_in_ was closed.
  if (fds[0].revents) {
    LOG(INFO) << "Cancelled. events = " << events;
    return false;
  }
  return true;
}

}  // namespace arc
