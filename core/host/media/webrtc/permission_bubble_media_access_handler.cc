// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/media/webrtc/permission_bubble_media_access_handler.h"

#include <utility>

#include "base/metrics/field_trial.h"
#include "core/host/media/webrtc/media_stream_device_permissions.h"
#include "core/host/media/webrtc/media_stream_devices_controller.h"
//#include "chrome/browser/permissions/permission_manager.h"
//#include "chrome/browser/permissions/permission_result.h"
#include "core/host/workspace/workspace.h"
//#include "chrome/common/pref_names.h"
//#include "components/content_settings/core/browser/host_content_settings_map.h"
#include "core/host/host_thread.h"
#include "core/host/notification_service.h"
#include "core/host/notification_types.h"
#include "core/host/application/application_contents.h"

#if defined(OS_ANDROID)
#include <vector>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "chrome/browser/android/chrome_feature_list.h"
#include "core/host/media/webrtc/screen_capture_infobar_delegate_android.h"
#include "chrome/browser/permissions/permission_uma_util.h"
#include "chrome/browser/permissions/permission_util.h"
#endif  // defined(OS_ANDROID)

namespace host {

struct PermissionBubbleMediaAccessHandler::PendingAccessRequest {
  PendingAccessRequest(const common::MediaStreamRequest& request,
                       const common::MediaResponseCallback& callback)
      : request(request), callback(callback) {}
  ~PendingAccessRequest() {}

  // TODO(gbillock): make the MediaStreamDevicesController owned by
  // this object when we're using bubbles.
  common::MediaStreamRequest request;
  common::MediaResponseCallback callback;
};

PermissionBubbleMediaAccessHandler::PermissionBubbleMediaAccessHandler() {
  // PermissionBubbleMediaAccessHandler should be created on UI thread.
  // Otherwise, it will not receive
  // content::NOTIFICATION_WEB_CONTENTS_DESTROYED, and that will result in
  // possible use after free.
  DCHECK_CURRENTLY_ON(HostThread::UI);
  notifications_registrar_.Add(this,
                               NOTIFICATION_WEB_CONTENTS_DESTROYED,
                               NotificationService::AllSources());
}

PermissionBubbleMediaAccessHandler::~PermissionBubbleMediaAccessHandler() {}

bool PermissionBubbleMediaAccessHandler::SupportsStreamType(
    ApplicationContents* web_contents,
    const common::MediaStreamType type) {
#if defined(OS_ANDROID)
  return type == common::MEDIA_DEVICE_VIDEO_CAPTURE ||
         type == common::MEDIA_DEVICE_AUDIO_CAPTURE ||
         type == common::MEDIA_DESKTOP_VIDEO_CAPTURE;
#else
  return type == common::MEDIA_DEVICE_VIDEO_CAPTURE ||
         type == common::MEDIA_DEVICE_AUDIO_CAPTURE;
#endif
}

bool PermissionBubbleMediaAccessHandler::CheckMediaAccessPermission(
    ApplicationWindowHost* render_frame_host,
    const GURL& security_origin,
    common::MediaStreamType type) {
  // ApplicationContents* web_contents =
  //     ApplicationContents::FromApplicationWindowHost(render_frame_host);
  // Workspace* workspace = Workspace::GetCurrent();
  //     //Profile::FromBrowserContext(web_contents->GetBrowserContext());
  // ContentSettingsType content_settings_type =
  //     type == common::MEDIA_DEVICE_AUDIO_CAPTURE
  //         ? CONTENT_SETTINGS_TYPE_MEDIASTREAM_MIC
  //         : CONTENT_SETTINGS_TYPE_MEDIASTREAM_CAMERA;

  // DCHECK(!security_origin.is_empty());
  // GURL embedding_origin = web_contents->GetLastCommittedURL().GetOrigin();
  // PermissionManager* permission_manager = PermissionManager::Get(profile);
  // return permission_manager
  //            ->GetPermissionStatusForFrame(content_settings_type,
  //                                          render_frame_host, security_origin)
  //            .content_setting == CONTENT_SETTING_ALLOW;
  return true;
}

void PermissionBubbleMediaAccessHandler::HandleRequest(
    ApplicationContents* web_contents,
    const common::MediaStreamRequest& request,
    const common::MediaResponseCallback& callback) {
  DCHECK_CURRENTLY_ON(HostThread::UI);

#if defined(OS_ANDROID)
  if (request.video_type == common::MEDIA_DESKTOP_VIDEO_CAPTURE &&
      !base::FeatureList::IsEnabled(
          chrome::android::kUserMediaScreenCapturing)) {
    // If screen capturing isn't enabled on Android, we'll use "invalid state"
    // as result, same as on desktop.
    callback.Run(content::MediaStreamDevices(),
                 content::MEDIA_DEVICE_INVALID_STATE, nullptr);
    return;
  }
#endif  // defined(OS_ANDROID)

  RequestsQueue& queue = pending_requests_[web_contents];
  queue.push_back(PendingAccessRequest(request, callback));

  // If this is the only request then show the infobar.
  if (queue.size() == 1)
    ProcessQueuedAccessRequest(web_contents);
}

void PermissionBubbleMediaAccessHandler::ProcessQueuedAccessRequest(
    ApplicationContents* web_contents) {
  DCHECK_CURRENTLY_ON(HostThread::UI);

  std::map<ApplicationContents*, RequestsQueue>::iterator it =
      pending_requests_.find(web_contents);

  if (it == pending_requests_.end() || it->second.empty()) {
    // Don't do anything if the tab was closed.
    return;
  }

  DCHECK(!it->second.empty());

  const common::MediaStreamRequest request = it->second.front().request;
#if defined(OS_ANDROID)
  if (request.video_type == common::MEDIA_DESKTOP_VIDEO_CAPTURE) {
    ScreenCaptureInfoBarDelegateAndroid::Create(
        web_contents, request,
        base::Bind(&PermissionBubbleMediaAccessHandler::OnAccessRequestResponse,
                   base::Unretained(this), web_contents));
    return;
  }
#endif

  MediaStreamDevicesController::RequestPermissions(
      request,
      base::Bind(&PermissionBubbleMediaAccessHandler::OnAccessRequestResponse,
                 base::Unretained(this), web_contents));
}

void PermissionBubbleMediaAccessHandler::UpdateMediaRequestState(
    int render_process_id,
    int render_frame_id,
    int page_request_id,
    common::MediaStreamType stream_type,
    MediaRequestState state) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  if (state != MEDIA_REQUEST_STATE_CLOSING)
    return;

  bool found = false;
  for (RequestsQueues::iterator rqs_it = pending_requests_.begin();
       rqs_it != pending_requests_.end(); ++rqs_it) {
    RequestsQueue& queue = rqs_it->second;
    for (RequestsQueue::iterator it = queue.begin(); it != queue.end(); ++it) {
      if (it->request.render_process_id == render_process_id &&
          it->request.render_frame_id == render_frame_id &&
          it->request.page_request_id == page_request_id) {
        queue.erase(it);
        found = true;
        break;
      }
    }
    if (found)
      break;
  }
}

void PermissionBubbleMediaAccessHandler::OnAccessRequestResponse(
    ApplicationContents* web_contents,
    const common::MediaStreamDevices& devices,
    common::MediaStreamRequestResult result,
    std::unique_ptr<common::MediaStreamUI> ui) {
  DCHECK_CURRENTLY_ON(HostThread::UI);

  std::map<ApplicationContents*, RequestsQueue>::iterator it =
      pending_requests_.find(web_contents);
  if (it == pending_requests_.end()) {
    // ApplicationContents has been destroyed. Don't need to do anything.
    return;
  }

  RequestsQueue& queue(it->second);
  if (queue.empty())
    return;

  common::MediaResponseCallback callback = queue.front().callback;
  queue.pop_front();

  if (!queue.empty()) {
    // Post a task to process next queued request. It has to be done
    // asynchronously to make sure that calling infobar is not destroyed until
    // after this function returns.
    HostThread::PostTask(
        HostThread::UI, FROM_HERE,
        base::BindOnce(
            &PermissionBubbleMediaAccessHandler::ProcessQueuedAccessRequest,
            base::Unretained(this), web_contents));
  }

  callback.Run(devices, result, std::move(ui));
}

void PermissionBubbleMediaAccessHandler::Observe(
    int type,
    const NotificationSource& source,
    const NotificationDetails& details) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  DCHECK_EQ(NOTIFICATION_WEB_CONTENTS_DESTROYED, type);

  pending_requests_.erase(Source<ApplicationContents>(source).ptr());
}

}