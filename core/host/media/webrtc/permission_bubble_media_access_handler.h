// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_MEDIA_WEBRTC_PERMISSION_BUBBLE_MEDIA_ACCESS_HANDLER_H_
#define CHROME_BROWSER_MEDIA_WEBRTC_PERMISSION_BUBBLE_MEDIA_ACCESS_HANDLER_H_

#include <map>

#include "base/containers/circular_deque.h"
#include "core/host/media/media_access_handler.h"
#include "core/host/notification_observer.h"
#include "core/host/notification_registrar.h"

namespace host {

// MediaAccessHandler for permission bubble requests.
class PermissionBubbleMediaAccessHandler
    : public MediaAccessHandler,
      public NotificationObserver {
 public:
  PermissionBubbleMediaAccessHandler();
  ~PermissionBubbleMediaAccessHandler() override;

  // MediaAccessHandler implementation.
  bool SupportsStreamType(ApplicationContents* app_contents,
                          const common::MediaStreamType type) override;
  bool CheckMediaAccessPermission(
      ApplicationWindowHost* app_window_host,
      const GURL& security_origin,
      common::MediaStreamType type) override;
  void HandleRequest(ApplicationContents* web_contents,
                     const common::MediaStreamRequest& request,
                     const common::MediaResponseCallback& callback) override;
  void UpdateMediaRequestState(int render_process_id,
                               int render_frame_id,
                               int page_request_id,
                               common::MediaStreamType stream_type,
                               MediaRequestState state) override;

 private:
  struct PendingAccessRequest;
  using RequestsQueue = base::circular_deque<PendingAccessRequest>;
  using RequestsQueues = std::map<ApplicationContents*, RequestsQueue>;

  void ProcessQueuedAccessRequest(ApplicationContents* web_contents);
  void OnAccessRequestResponse(ApplicationContents* web_contents,
                               const common::MediaStreamDevices& devices,
                               common::MediaStreamRequestResult result,
                               std::unique_ptr<common::MediaStreamUI> ui);

  // content::NotificationObserver implementation.
  void Observe(int type,
               const NotificationSource& source,
               const NotificationDetails& details) override;

  RequestsQueues pending_requests_;
  NotificationRegistrar notifications_registrar_;
};

}

#endif  // CHROME_BROWSER_MEDIA_WEBRTC_PERMISSION_BUBBLE_MEDIA_ACCESS_HANDLER_H_
