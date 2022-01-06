// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_MEDIA_MEDIA_ACCESS_HANDLER_H_
#define CHROME_BROWSER_MEDIA_MEDIA_ACCESS_HANDLER_H_

#include "base/callback.h"
#include "core/host/media/media_request_state.h"
#include "core/shared/common/media_stream_request.h"

namespace host {
class ApplicationWindowHost;
class ApplicationContents;

// Interface for handling media access requests that are propagated from
// MediaCaptureDevicesDispatcher.
class MediaAccessHandler {
 public:
  MediaAccessHandler() {}
  virtual ~MediaAccessHandler() {}

  // Check if the media stream type is supported by MediaAccessHandler.
  virtual bool SupportsStreamType(ApplicationContents* app_contents,
                                  const common::MediaStreamType type) = 0;
  // Check media access permission. |extension| is set to NULL if request was
  // made from a drive-by page.
  virtual bool CheckMediaAccessPermission(
      ApplicationWindowHost* app_window_host,
      const GURL& security_origin,
      common::MediaStreamType type) = 0;
  // Process media access requests. |extension| is set to NULL if request was
  // made from a drive-by page.
  virtual void HandleRequest(ApplicationContents* appb_contents,
                             const common::MediaStreamRequest& request,
                             const common::MediaResponseCallback& callback) = 0;
  // Update media request state. Called on UI thread.
  virtual void UpdateMediaRequestState(int render_process_id,
                                       int render_frame_id,
                                       int page_request_id,
                                       common::MediaStreamType stream_type,
                                       MediaRequestState state) {}

 protected:
  // Helper function for derived classes which takes in whether audio/video
  // permissions are allowed and queries for the requested devices, running the
  // callback with the appropriate device list and status.
  static void CheckDevicesAndRunCallback(
      ApplicationContents* web_contents,
      const common::MediaStreamRequest& request,
      const common::MediaResponseCallback& callback,
      bool audio_allowed,
      bool video_allowed);
};

}

#endif  // CHROME_BROWSER_MEDIA_MEDIA_ACCESS_HANDLER_H_
