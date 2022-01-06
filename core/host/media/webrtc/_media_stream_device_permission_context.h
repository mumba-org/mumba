// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_MEDIA_WEBRTC_MEDIA_STREAM_DEVICE_PERMISSION_CONTEXT_H_
#define CHROME_BROWSER_MEDIA_WEBRTC_MEDIA_STREAM_DEVICE_PERMISSION_CONTEXT_H_

#include "base/macros.h"
#include "core/host/permissions/permission_context_base.h"
#include "components/content_settings/core/common/content_settings_types.h"

namespace host {

// Common class which handles the mic and camera permissions.
class MediaStreamDevicePermissionContext : public PermissionContextBase {
 public:
  MediaStreamDevicePermissionContext(Profile* profile,
                                     ContentSettingsType content_settings_type);
  ~MediaStreamDevicePermissionContext() override;

  // PermissionContextBase:
  void DecidePermission(ApplicationContents* web_contents,
                        const PermissionRequestID& id,
                        const GURL& requesting_origin,
                        const GURL& embedding_origin,
                        bool user_gesture,
                        const BrowserPermissionCallback& callback) override;

  // TODO(xhwang): GURL.GetOrigin() shouldn't be used as the origin. Need to
  // refactor to use url::Origin. crbug.com/527149 is filed for this.
  ContentSetting GetPermissionStatusInternal(
      content::RenderFrameHost* render_frame_host,
      const GURL& requesting_origin,
      const GURL& embedding_origin) const override;

  void ResetPermission(const GURL& requesting_origin,
                       const GURL& embedding_origin) override;

 private:
  // PermissionContextBase:
  bool IsRestrictedToSecureOrigins() const override;

  ContentSettingsType content_settings_type_;

  DISALLOW_COPY_AND_ASSIGN(MediaStreamDevicePermissionContext);
};

}

#endif  // CHROME_BROWSER_MEDIA_WEBRTC_MEDIA_STREAM_DEVICE_PERMISSION_CONTEXT_H_
