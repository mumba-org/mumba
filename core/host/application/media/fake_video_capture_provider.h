// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_MEDIA_FAKE_VIDEO_CAPTURE_PROVIDER_H_
#define MUMBA_HOST_APPLICATION_MEDIA_FAKE_VIDEO_CAPTURE_PROVIDER_H_

#include "core/host/application/media/video_capture_provider.h"
#include "media/capture/video/video_capture_system_impl.h"

namespace host {

// Implementation of VideoCaptureProvider that produces fake devices
// generating test frames.
class FakeVideoCaptureProvider : public VideoCaptureProvider {
 public:
  FakeVideoCaptureProvider();
  ~FakeVideoCaptureProvider() override;

  // VideoCaptureProvider implementation.
  void GetDeviceInfosAsync(GetDeviceInfosCallback result_callback) override;
  std::unique_ptr<VideoCaptureDeviceLauncher> CreateDeviceLauncher() override;

 private:
  media::VideoCaptureSystemImpl system_;
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_MEDIA_FAKE_VIDEO_CAPTURE_PROVIDER_H_
