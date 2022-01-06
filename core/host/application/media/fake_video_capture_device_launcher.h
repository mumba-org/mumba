// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_MEDIA_FAKE_VIDEO_CAPTURE_DEVICE_LAUNCHER_H_
#define MUMBA_HOST_APPLICATION_MEDIA_FAKE_VIDEO_CAPTURE_DEVICE_LAUNCHER_H_

#include "core/host/video_capture_device_launcher.h"
#include "media/capture/video/video_capture_system.h"

namespace host {

class FakeVideoCaptureDeviceLauncher
    : public content::VideoCaptureDeviceLauncher {
 public:
  FakeVideoCaptureDeviceLauncher(media::VideoCaptureSystem* system);
  ~FakeVideoCaptureDeviceLauncher() override;

  void LaunchDeviceAsync(const std::string& device_id,
                         content::MediaStreamType stream_type,
                         const media::VideoCaptureParams& params,
                         base::WeakPtr<media::VideoFrameReceiver> receiver,
                         base::OnceClosure connection_lost_cb,
                         Callbacks* callbacks,
                         base::OnceClosure done_cb) override;
  void AbortLaunch() override;

 private:
  media::VideoCaptureSystem* system_;
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_MEDIA_FAKE_VIDEO_CAPTURE_DEVICE_LAUNCHER_H_
