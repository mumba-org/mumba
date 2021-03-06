// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_MEDIA_BUILDABLE_VIDEO_CAPTURE_DEVICE_H_
#define MUMBA_HOST_APPLICATION_MEDIA_BUILDABLE_VIDEO_CAPTURE_DEVICE_H_

#include "base/memory/ref_counted.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/media_stream_request.h"
#include "media/capture/video/video_capture_device.h"
#include "media/capture/video/video_capture_device_info.h"
#include "media/capture/video/video_frame_receiver.h"
#include "media/capture/video_capture_types.h"

namespace host {

class VideoCaptureDeviceLauncher;

// Note: GetDeviceInfosAsync is only relevant for devices with
// MediaStreamType == MEDIA_DEVICE_VIDEO_CAPTURE, i.e. camera devices.
class CONTENT_EXPORT VideoCaptureProvider {
 public:
  using GetDeviceInfosCallback = base::OnceCallback<void(
      const std::vector<media::VideoCaptureDeviceInfo>&)>;

  virtual ~VideoCaptureProvider() {}

  // The passed-in |result_callback| must guarantee that the called
  // instance stays alive until |result_callback| is invoked.
  virtual void GetDeviceInfosAsync(GetDeviceInfosCallback result_callback) = 0;

  virtual std::unique_ptr<VideoCaptureDeviceLauncher>
  CreateDeviceLauncher() = 0;
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_MEDIA_BUILDABLE_VIDEO_CAPTURE_DEVICE_H_
