// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_NOTIFICATIONS_NOTIFICATION_PERMISSION_CONTEXT_H_
#define CHROME_BROWSER_NOTIFICATIONS_NOTIFICATION_PERMISSION_CONTEXT_H_

#include "base/gtest_prod_util.h"
//#include "core/host/permissions/permission_context_base.h"
//#include "components/content_settings/core/common/content_settings.h"

class GURL;

namespace host {

class Domain;

class NotificationPermissionContext {// : public PermissionContextBase {
 public:
  explicit NotificationPermissionContext(Domain* domain);
  ~NotificationPermissionContext() ;//override;

  // PermissionContextBase implementation.
  ContentSetting GetPermissionStatusInternal(
      RenderFrameHost* render_frame_host,
      const GURL& requesting_origin,
      const GURL& embedding_origin) const;// override;
  void ResetPermission(const GURL& requesting_origin,
                       const GURL& embedder_origin);// override;

 private:

  // PermissionContextBase implementation.
  void DecidePermission(ApplicationContents* web_contents,
                        const PermissionRequestID& id,
                        const GURL& requesting_origin,
                        const GURL& embedding_origin,
                        bool user_gesture,
                        const BrowserPermissionCallback& callback);// override;
  void UpdateContentSetting(const GURL& requesting_origin,
                            const GURL& embedder_origin,
                            ContentSetting content_setting);// override;
  bool IsRestrictedToSecureOrigins() const;// override;

  base::WeakPtrFactory<NotificationPermissionContext> weak_factory_ui_thread_;
};

}

#endif  // CHROME_BROWSER_NOTIFICATIONS_NOTIFICATION_PERMISSION_CONTEXT_H_
