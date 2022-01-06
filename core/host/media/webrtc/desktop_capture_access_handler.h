// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_MEDIA_WEBRTC_DESKTOP_CAPTURE_ACCESS_HANDLER_H_
#define CHROME_BROWSER_MEDIA_WEBRTC_DESKTOP_CAPTURE_ACCESS_HANDLER_H_

#include <list>

#include "core/host/media/capture_access_handler_base.h"
#include "core/host/media/media_access_handler.h"

namespace host {

// MediaAccessHandler for DesktopCapture API.
class DesktopCaptureAccessHandler : public CaptureAccessHandlerBase {
 public:
  DesktopCaptureAccessHandler();
  ~DesktopCaptureAccessHandler() override;

  // MediaAccessHandler implementation.
  bool SupportsStreamType(ApplicationContents* web_contents,
                          const common::MediaStreamType type) override;
  bool CheckMediaAccessPermission(
      ApplicationWindowHost* app_window_host,
      const GURL& security_origin,
      common::MediaStreamType type) override;
  void HandleRequest(ApplicationContents* app_contents,
                     const common::MediaStreamRequest& request,
                     const common::MediaResponseCallback& callback) override;

 private:
  void ProcessScreenCaptureAccessRequest(
      ApplicationContents* appb_contents,
      const common::MediaStreamRequest& request,
      const common::MediaResponseCallback& callback);

  // Returns whether desktop capture is always approved for |extension|.
  // Currently component extensions and some whitelisted extensions are default
  // approved.
  //static bool IsDefaultApproved(const extensions::Extension* extension);
};

}

#endif  // CHROME_BROWSER_MEDIA_WEBRTC_DESKTOP_CAPTURE_ACCESS_HANDLER_H_
