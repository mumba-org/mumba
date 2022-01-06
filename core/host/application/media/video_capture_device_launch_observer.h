// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_MEDIA_VIDEO_CAPTURE_DEVICE_LAUNCH_OBSERVER_H_
#define MUMBA_HOST_APPLICATION_MEDIA_VIDEO_CAPTURE_DEVICE_LAUNCH_OBSERVER_H_

#include "core/shared/common/content_export.h"

namespace host {

class VideoCaptureController;

class CONTENT_EXPORT VideoCaptureDeviceLaunchObserver {
 public:
  virtual ~VideoCaptureDeviceLaunchObserver() {}
  virtual void OnDeviceLaunched(VideoCaptureController* controller) = 0;
  virtual void OnDeviceLaunchFailed(VideoCaptureController* controller) = 0;
  virtual void OnDeviceLaunchAborted() = 0;
  virtual void OnDeviceConnectionLost(VideoCaptureController* controller) = 0;
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_MEDIA_VIDEO_CAPTURE_DEVICE_LAUNCH_OBSERVER_H_
