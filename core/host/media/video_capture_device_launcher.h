// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MEDIA_VIDEO_CAPTURE_DEVICE_LAUNCHER_H_
#define MUMBA_HOST_MEDIA_VIDEO_CAPTURE_DEVICE_LAUNCHER_H_

#include <memory>
#include <string>

#include "core/shared/common/content_export.h"
#include "core/shared/common/media_stream_request.h"
#include "media/capture/video/video_capture_device.h"
#include "media/capture/video/video_capture_device_info.h"
#include "media/capture/video/video_frame_receiver.h"
#include "media/capture/video_capture_types.h"

namespace host {

class LaunchedVideoCaptureDevice;

// Asynchronously launches video capture devices. After a call to
// LaunchDeviceAsync() it is illegal to call LaunchDeviceAsync() again until
// |callbacks| has been notified about the outcome of the asynchronous launch.
class CONTENT_EXPORT VideoCaptureDeviceLauncher {
 public:
  class CONTENT_EXPORT Callbacks {
   public:
    virtual ~Callbacks() {}
    virtual void OnDeviceLaunched(
        std::unique_ptr<LaunchedVideoCaptureDevice> device) = 0;
    virtual void OnDeviceLaunchFailed() = 0;
    virtual void OnDeviceLaunchAborted() = 0;
  };

  virtual ~VideoCaptureDeviceLauncher() {}

  // The passed-in |done_cb| must guarantee that the context relevant
  // during the asynchronous processing stays alive.
  virtual void LaunchDeviceAsync(
      const std::string& device_id,
      common::MediaStreamType stream_type,
      const media::VideoCaptureParams& params,
      base::WeakPtr<media::VideoFrameReceiver> receiver,
      base::OnceClosure connection_lost_cb,
      Callbacks* callbacks,
      base::OnceClosure done_cb) = 0;

  virtual void AbortLaunch() = 0;
};

class CONTENT_EXPORT LaunchedVideoCaptureDevice
    : public media::VideoFrameConsumerFeedbackObserver {
 public:
  // Device operation methods.
  virtual void GetPhotoState(
      media::VideoCaptureDevice::GetPhotoStateCallback callback) const = 0;
  virtual void SetPhotoOptions(
      media::mojom::PhotoSettingsPtr settings,
      media::VideoCaptureDevice::SetPhotoOptionsCallback callback) = 0;
  virtual void TakePhoto(
      media::VideoCaptureDevice::TakePhotoCallback callback) = 0;
  virtual void MaybeSuspendDevice() = 0;
  virtual void ResumeDevice() = 0;
  virtual void RequestRefreshFrame() = 0;

  // Methods for specific types of devices.
  virtual void SetDesktopCaptureWindowIdAsync(gfx::NativeViewId window_id,
                                              base::OnceClosure done_cb) = 0;
};

}  // namespace host

#endif  // CONTENT_PUBLIC_BROWSER_VIDEO_CAPTURE_DEVICE_LAUNCHER_H_
