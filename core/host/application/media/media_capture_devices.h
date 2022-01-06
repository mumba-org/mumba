// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_MEDIA_MEDIA_CAPTURE_DEVICES_H_
#define MUMBA_HOST_APPLICATION_MEDIA_MEDIA_CAPTURE_DEVICES_H_

#include "core/shared/common/media_stream_request.h"
#include "media/base/video_facing.h"

namespace host {

// This is a singleton class, used to get Audio/Video devices, it must be
// called in UI thread.
class CONTENT_EXPORT  MediaCaptureDevices {
 public:
  // Get signleton instance of MediaCaptureDevices.
  static MediaCaptureDevices* GetInstance();

  // Return all Audio/Video devices.
  virtual const common::MediaStreamDevices& GetAudioCaptureDevices() = 0;
  virtual const common::MediaStreamDevices& GetVideoCaptureDevices() = 0;

  virtual void AddVideoCaptureObserver(
      media::VideoCaptureObserver* observer) = 0;
  virtual void RemoveAllVideoCaptureObservers() = 0;

 private:
  // This interface should only be implemented inside content.
  friend class MediaCaptureDevicesImpl;
  MediaCaptureDevices() {}
  virtual ~MediaCaptureDevices() {}
};

}  // namespace host

#endif  // CONTENT_PUBLIC_BROWSER_MEDIA_CAPTURE_DEVICES_H_
