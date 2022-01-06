// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/media/webrtc/tab_capture_access_handler.h"

#include <utility>

//#include "core/host/extensions/api/tab_capture/tab_capture_registry.h"
#include "core/host/media/webrtc/media_capture_devices_dispatcher.h"
#include "core/host/media/webrtc/media_stream_capture_indicator.h"
#include "core/host/workspace/workspace.h"
#include "core/host/application/application_contents.h"
//#include "extensions/common/permissions/permissions_data.h"

namespace host {

TabCaptureAccessHandler::TabCaptureAccessHandler() {
}

TabCaptureAccessHandler::~TabCaptureAccessHandler() {
}

bool TabCaptureAccessHandler::SupportsStreamType(
    ApplicationContents* web_contents,
    const common::MediaStreamType type) {
  return type == common::MEDIA_TAB_VIDEO_CAPTURE ||
         type == common::MEDIA_TAB_AUDIO_CAPTURE;
}

bool TabCaptureAccessHandler::CheckMediaAccessPermission(
    ApplicationWindowHost* app_window_host,
    const GURL& security_origin,
    common::MediaStreamType type) {
  return false;
}

void TabCaptureAccessHandler::HandleRequest(
    ApplicationContents* web_contents,
    const common::MediaStreamRequest& request,
    const common::MediaResponseCallback& callback) {
  common::MediaStreamDevices devices;
  std::unique_ptr<common::MediaStreamUI> ui;

  //if (!extension) {
//    callback.Run(devices, common::MEDIA_DEVICE_TAB_CAPTURE_FAILURE,
                 //std::move(ui));
    //return;
  //}

  //Profile* profile =
  //    Profile::FromBrowserContext(web_contents->GetBrowserContext());
  //extensions::TabCaptureRegistry* tab_capture_registry =
      //extensions::TabCaptureRegistry::Get(profile);
  //if (!tab_capture_registry) {
//    NOTREACHED();
    //callback.Run(devices, content::MEDIA_DEVICE_INVALID_STATE, std::move(ui));
    //return;
  //}
  const bool tab_capture_allowed = true;//tab_capture_registry->VerifyRequest(
      //request.render_process_id, request.render_frame_id, extension->id());

  if (request.audio_type == common::MEDIA_TAB_AUDIO_CAPTURE &&
      tab_capture_allowed) { //&&
      //extension->permissions_data()->HasAPIPermission(
      //    extensions::APIPermission::kTabCapture)) {
    devices.push_back(common::MediaStreamDevice(
        common::MEDIA_TAB_AUDIO_CAPTURE, std::string(), std::string()));
  }

  if (request.video_type == common::MEDIA_TAB_VIDEO_CAPTURE &&
      tab_capture_allowed) { //&&
      //extension->permissions_data()->HasAPIPermission(
      //    extensions::APIPermission::kTabCapture)) {
    devices.push_back(common::MediaStreamDevice(
        common::MEDIA_TAB_VIDEO_CAPTURE, std::string(), std::string()));
  }

  if (!devices.empty()) {
    ui = MediaCaptureDevicesDispatcher::GetInstance()
             ->GetMediaStreamCaptureIndicator()
             ->RegisterMediaStream(web_contents, devices);
  }
  //UpdateExtensionTrusted(request, extension);
  callback.Run(devices, devices.empty() ? common::MEDIA_DEVICE_INVALID_STATE
                                        : common::MEDIA_DEVICE_OK,
               std::move(ui));
}

}