// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_MEDIA_WEBRTC_TAB_CAPTURE_ACCESS_HANDLER_H_
#define CHROME_BROWSER_MEDIA_WEBRTC_TAB_CAPTURE_ACCESS_HANDLER_H_

#include "core/host/media/capture_access_handler_base.h"

namespace host {

// MediaAccessHandler for TabCapture API.
class TabCaptureAccessHandler : public CaptureAccessHandlerBase {
 public:
  TabCaptureAccessHandler();
  ~TabCaptureAccessHandler() override;

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
};

}

#endif  // CHROME_BROWSER_MEDIA_WEBRTC_TAB_CAPTURE_ACCESS_HANDLER_H_
