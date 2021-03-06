// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_MEDIA_WEBRTC_MEDIA_STREAM_DEVICE_PERMISSIONS_H_
#define CHROME_BROWSER_MEDIA_WEBRTC_MEDIA_STREAM_DEVICE_PERMISSIONS_H_

//#include "components/content_settings/core/common/content_settings.h"
//#include "components/content_settings/core/common/content_settings_types.h"
#include "base/memory/ref_counted.h"
#include "core/shared/common/media_stream_request.h"

class GURL;

namespace host {
class Workspace;

enum MediaStreamDevicePolicy {
  POLICY_NOT_SET,
  ALWAYS_DENY,
  ALWAYS_ALLOW,
};

// Get the device policy for |security_origin| and |profile|.
MediaStreamDevicePolicy GetDevicePolicy(scoped_refptr<Workspace> workspace,
                                        const GURL& security_origin,
                                        const char* policy_name,
                                        const char* whitelist_policy_name);

}

#endif  // CHROME_BROWSER_MEDIA_WEBRTC_MEDIA_STREAM_DEVICE_PERMISSIONS_H_
