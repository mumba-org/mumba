// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/media/media_access_handler.h"

#include <utility>

#include "core/host/media/webrtc/media_capture_devices_dispatcher.h"
#include "core/host/media/webrtc/media_stream_capture_indicator.h"
#include "core/host/workspace/workspace.h"
#include "core/host/application/application_contents.h"

namespace host {

// static
void MediaAccessHandler::CheckDevicesAndRunCallback(
    ApplicationContents* web_contents,
    const common::MediaStreamRequest& request,
    const common::MediaResponseCallback& callback,
    bool audio_allowed,
    bool video_allowed) {
  // TODO(vrk): This code is largely duplicated in
  // MediaStreamDevicesController::GetDevices(). Move this code into a shared
  // method between the two classes.
  bool get_default_audio_device = audio_allowed;
  bool get_default_video_device = video_allowed;

  common::MediaStreamDevices devices;

  // Set an initial error result. If neither audio or video is allowed, we'll
  // never try to get any device below but will just create |ui| and return an
  // empty list with "invalid state" result. If at least one is allowed, we'll
  // try to get device(s), and if failure, we want to return "no hardware"
  // result.
  // TODO(grunell): The invalid state result should be changed to a new denied
  // result + a dcheck to ensure at least one of audio or video types is
  // capture.
  common::MediaStreamRequestResult result =
      (audio_allowed || video_allowed) ? common::MEDIA_DEVICE_NO_HARDWARE
                                       : common::MEDIA_DEVICE_INVALID_STATE;

  // Get the exact audio or video device if an id is specified.
  // We only set any error result here and before running the callback change
  // it to OK if we have any device.
  if (audio_allowed && !request.requested_audio_device_id.empty()) {
    const common::MediaStreamDevice* audio_device =
        MediaCaptureDevicesDispatcher::GetInstance()->GetRequestedAudioDevice(
            request.requested_audio_device_id);
    if (audio_device) {
      devices.push_back(*audio_device);
      get_default_audio_device = false;
    }
  }
  if (video_allowed && !request.requested_video_device_id.empty()) {
    const common::MediaStreamDevice* video_device =
        MediaCaptureDevicesDispatcher::GetInstance()->GetRequestedVideoDevice(
            request.requested_video_device_id);
    if (video_device) {
      devices.push_back(*video_device);
      get_default_video_device = false;
    }
  }

  scoped_refptr<Workspace> workspace = Workspace::GetCurrent();
      //Profile::FromBrowserContext(web_contents->GetBrowserContext());

  // If either or both audio and video devices were requested but not
  // specified by id, get the default devices.
  if (get_default_audio_device || get_default_video_device) {
    MediaCaptureDevicesDispatcher::GetInstance()->GetDefaultDevicesForProfile(
        workspace, get_default_audio_device, get_default_video_device, &devices);
  }

  std::unique_ptr<common::MediaStreamUI> ui;
  if (!devices.empty()) {
    result = common::MEDIA_DEVICE_OK;
    ui = MediaCaptureDevicesDispatcher::GetInstance()
             ->GetMediaStreamCaptureIndicator()
             ->RegisterMediaStream(web_contents, devices);
  }

  callback.Run(devices, result, std::move(ui));
}

}