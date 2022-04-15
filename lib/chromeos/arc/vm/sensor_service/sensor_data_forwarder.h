// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_VM_SENSOR_SERVICE_SENSOR_DATA_FORWARDER_H_
#define ARC_VM_SENSOR_SERVICE_SENSOR_DATA_FORWARDER_H_

#include <base/files/scoped_file.h>
#include <base/threading/thread.h>

namespace arc {

// SensorDataForwarder forwards the sensor data from an FD to another.
class SensorDataForwarder {
 public:
  SensorDataForwarder(base::ScopedFD fd_in, base::ScopedFD fd_out);
  ~SensorDataForwarder();
  SensorDataForwarder(const SensorDataForwarder&) = delete;
  SensorDataForwarder& operator=(const SensorDataForwarder&) = delete;

  // Initializes this object.
  bool Init();

 private:
  // Forwards data from fd_in_ to fd_out_.
  void ForwardData();

  // Polls the FD for the events.
  // Returns false if cancelled.
  bool PollFd(int fd, int16_t events);

  base::ScopedFD fd_in_;
  base::ScopedFD fd_out_;

  // The main thread closes cancel_pipe_in_ to stop the thread.
  // The thread polls cancel_pipe_out_ to detect this.
  base::ScopedFD cancel_pipe_in_, cancel_pipe_out_;

  // The thread to read and write the FDs.
  base::Thread thread_;
};

}  // namespace arc

#endif  // ARC_VM_SENSOR_SERVICE_SENSOR_DATA_FORWARDER_H_
