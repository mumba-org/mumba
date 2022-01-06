// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_MEDIA_VIDEO_CAPTURE_PROVIDER_SWITCHER_H_
#define MUMBA_HOST_APPLICATION_MEDIA_VIDEO_CAPTURE_PROVIDER_SWITCHER_H_

#include "core/host/application/media/video_capture_provider.h"
#include "services/video_capture/public/mojom/device_factory.mojom.h"

namespace host {

// Routes requests for media devices, e.g. cameras, to
// |media_device_capture_provider| and for all other types of capture, e.g.
// screen or tab capture, to the given |other_types_capture_provider|.
class CONTENT_EXPORT VideoCaptureProviderSwitcher
    : public VideoCaptureProvider {
 public:
  VideoCaptureProviderSwitcher(
      std::unique_ptr<VideoCaptureProvider> media_device_capture_provider,
      std::unique_ptr<VideoCaptureProvider> other_types_capture_provider);
  ~VideoCaptureProviderSwitcher() override;

  void GetDeviceInfosAsync(GetDeviceInfosCallback result_callback) override;

  std::unique_ptr<VideoCaptureDeviceLauncher> CreateDeviceLauncher() override;

 private:
  const std::unique_ptr<VideoCaptureProvider> media_device_capture_provider_;
  const std::unique_ptr<VideoCaptureProvider> other_types_capture_provider_;
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_MEDIA_VIDEO_CAPTURE_PROVIDER_SWITCHER_H_
