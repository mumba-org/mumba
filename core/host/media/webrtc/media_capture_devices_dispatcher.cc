// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/media/webrtc/media_capture_devices_dispatcher.h"

#include "base/command_line.h"
#include "base/logging.h"
#include "base/metrics/field_trial.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "build/build_config.h"
#include "core/host/media/media_access_handler.h"
#include "core/host/media/webrtc/desktop_streams_registry.h"
#include "core/host/media/webrtc/media_stream_capture_indicator.h"
#include "core/host/media/webrtc/permission_bubble_media_access_handler.h"
#include "core/host/media/webrtc/tab_capture_access_handler.h"
#include "core/host/media/webrtc/desktop_capture_access_handler.h"
#include "core/host/workspace/workspace.h"
#include "core/host/ui/dock.h"
#include "core/host/ui/dock_window.h"
#include "core/shared/common/switches.h"
//#include "chrome/common/pref_names.h"
//#include "components/pref_registry/pref_registry_syncable.h"
//#include "components/prefs/pref_service.h"
//#include "components/prefs/scoped_user_pref_update.h"
#include "core/host/host_thread.h"
#include "core/host/application/media/media_capture_devices.h"
#include "core/host/notification_source.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/application_process_host.h"
#include "core/host/application/application_contents.h"
#include "core/shared/common/media_stream_request.h"
#include "media/base/media_switches.h"

#if defined(OS_CHROMEOS)
#include "ash/shell.h"
#include "core/host/media/chromeos_login_media_access_handler.h"
#include "core/host/media/public_session_media_access_handler.h"
#include "core/host/media/public_session_tab_capture_access_handler.h"
#endif  // defined(OS_CHROMEOS)

namespace host {

namespace {

// Finds a device in |devices| that has |device_id|, or NULL if not found.
const common::MediaStreamDevice* FindDeviceWithId(
    const common::MediaStreamDevices& devices,
    const std::string& device_id) {
  common::MediaStreamDevices::const_iterator iter = devices.begin();
  for (; iter != devices.end(); ++iter) {
    if (iter->id == device_id) {
      return &(*iter);
    }
  }
  return NULL;
}

ApplicationContents* ApplicationContentsFromIds(int render_process_id,
                                                int render_frame_id) {
  ApplicationContents* app_contents =
      ApplicationContents::FromApplicationWindowHost(
          ApplicationWindowHost::FromID(render_process_id, render_frame_id));
  return app_contents;
}

}  // namespace

MediaCaptureDevicesDispatcher* MediaCaptureDevicesDispatcher::GetInstance() {
  return base::Singleton<MediaCaptureDevicesDispatcher>::get();
}

MediaCaptureDevicesDispatcher::MediaCaptureDevicesDispatcher()
    : is_device_enumeration_disabled_(false),
      media_stream_capture_indicator_(new MediaStreamCaptureIndicator()) {
  DCHECK_CURRENTLY_ON(HostThread::UI);

  media_access_handlers_.push_back(
      std::make_unique<DesktopCaptureAccessHandler>());
#if defined(OS_CHROMEOS)
  // Wrapper around TabCaptureAccessHandler used in Public Sessions.
  media_access_handlers_.push_back(
      std::make_unique<PublicSessionTabCaptureAccessHandler>());
#else
  media_access_handlers_.push_back(std::make_unique<TabCaptureAccessHandler>());
#endif
  media_access_handlers_.push_back(
      std::make_unique<PermissionBubbleMediaAccessHandler>());
}

MediaCaptureDevicesDispatcher::~MediaCaptureDevicesDispatcher() {}

bool MediaCaptureDevicesDispatcher::IsOriginForCasting(const GURL& origin) {
  // Whitelisted tab casting extensions.
  return
      // Media Router Dev
      origin.spec() == "chrome-extension://enhhojjnijigcajfphajepfemndkmdlo/" ||
      // Media Router Stable
      origin.spec() == "chrome-extension://pkedcjkdefgpdelpbcmbmeomcjbeemfm/";
}

void MediaCaptureDevicesDispatcher::AddObserver(Observer* observer) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  if (!observers_.HasObserver(observer))
    observers_.AddObserver(observer);
}

void MediaCaptureDevicesDispatcher::RemoveObserver(Observer* observer) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  observers_.RemoveObserver(observer);
}

const common::MediaStreamDevices&
MediaCaptureDevicesDispatcher::GetAudioCaptureDevices() {
  DLOG(INFO) << "MediaCaptureDevicesDispatcher::GetAudioCaptureDevices";
  DCHECK_CURRENTLY_ON(HostThread::UI);
  if (is_device_enumeration_disabled_ || !test_audio_devices_.empty())
    return test_audio_devices_;

  return MediaCaptureDevices::GetInstance()->GetAudioCaptureDevices();
}

const common::MediaStreamDevices&
MediaCaptureDevicesDispatcher::GetVideoCaptureDevices() {
  DLOG(INFO) << "MediaCaptureDevicesDispatcher::GetVideoCaptureDevices";
  DCHECK_CURRENTLY_ON(HostThread::UI);
  if (is_device_enumeration_disabled_ || !test_video_devices_.empty())
    return test_video_devices_;

  return MediaCaptureDevices::GetInstance()->GetVideoCaptureDevices();
}

void MediaCaptureDevicesDispatcher::ProcessMediaAccessRequest(
    ApplicationContents* web_contents,
    const common::MediaStreamRequest& request,
    const common::MediaResponseCallback& callback) {
  DCHECK_CURRENTLY_ON(HostThread::UI);

  for (const auto& handler : media_access_handlers_) {
    if (handler->SupportsStreamType(web_contents, request.video_type) ||
        handler->SupportsStreamType(web_contents, request.audio_type)) {
      handler->HandleRequest(web_contents, request, callback);
      return;
    }
  }
  callback.Run(common::MediaStreamDevices(),
               common::MEDIA_DEVICE_NOT_SUPPORTED, nullptr);
}

bool MediaCaptureDevicesDispatcher::CheckMediaAccessPermission(
    ApplicationWindowHost* app_window_host,
    const GURL& security_origin,
    common::MediaStreamType type) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  DCHECK_CURRENTLY_ON(HostThread::UI);
  for (const auto& handler : media_access_handlers_) {
    if (handler->SupportsStreamType(
            ApplicationContents::FromApplicationWindowHost(app_window_host), type)) {
      return handler->CheckMediaAccessPermission(
          app_window_host, security_origin, type);
    }
  }
  return false;
}

void MediaCaptureDevicesDispatcher::GetDefaultDevicesForProfile(
    scoped_refptr<Workspace> profile,
    bool audio,
    bool video,
    common::MediaStreamDevices* devices) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  DCHECK(audio || video);

  //PrefService* prefs = profile->GetPrefs();
  std::string default_device;
  if (audio) {
    //default_device = prefs->GetString(prefs::kDefaultAudioCaptureDevice);
    //const common::MediaStreamDevice* device =
        //GetRequestedAudioDevice(default_device);
    //if (!device)
    //  device = GetFirstAvailableAudioDevice();
    const common::MediaStreamDevice* device = GetFirstAvailableAudioDevice();
    if (device)
      devices->push_back(*device);
  }

  if (video) {
    //default_device = prefs->GetString(prefs::kDefaultVideoCaptureDevice);
    //const content::MediaStreamDevice* device =
    //    GetRequestedVideoDevice(default_device);
    //if (!device)
    //  device = GetFirstAvailableVideoDevice();
    const common::MediaStreamDevice* device = GetFirstAvailableVideoDevice();
    if (device)
      devices->push_back(*device);
  }
}

std::string MediaCaptureDevicesDispatcher::GetDefaultDeviceIDForProfile(
    scoped_refptr<Workspace> profile,
    common::MediaStreamType type) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  //PrefService* prefs = profile->GetPrefs();
  //if (type == content::MEDIA_DEVICE_AUDIO_CAPTURE)
  //  return prefs->GetString(prefs::kDefaultAudioCaptureDevice);
  //else if (type == content::MEDIA_DEVICE_VIDEO_CAPTURE)
  //  return prefs->GetString(prefs::kDefaultVideoCaptureDevice);
  //else
    return std::string();
}

const common::MediaStreamDevice*
MediaCaptureDevicesDispatcher::GetRequestedAudioDevice(
    const std::string& requested_audio_device_id) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  const common::MediaStreamDevices& audio_devices = GetAudioCaptureDevices();
  const common::MediaStreamDevice* const device =
      FindDeviceWithId(audio_devices, requested_audio_device_id);
  return device;
}

const common::MediaStreamDevice*
MediaCaptureDevicesDispatcher::GetFirstAvailableAudioDevice() {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  const common::MediaStreamDevices& audio_devices = GetAudioCaptureDevices();
  if (audio_devices.empty())
    return NULL;
  return &(*audio_devices.begin());
}

const common::MediaStreamDevice*
MediaCaptureDevicesDispatcher::GetRequestedVideoDevice(
    const std::string& requested_video_device_id) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  const common::MediaStreamDevices& video_devices = GetVideoCaptureDevices();
  const common::MediaStreamDevice* const device =
      FindDeviceWithId(video_devices, requested_video_device_id);
  return device;
}

const common::MediaStreamDevice*
MediaCaptureDevicesDispatcher::GetFirstAvailableVideoDevice() {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  const common::MediaStreamDevices& video_devices = GetVideoCaptureDevices();
  if (video_devices.empty())
    return NULL;
  return &(*video_devices.begin());
}

void MediaCaptureDevicesDispatcher::DisableDeviceEnumerationForTesting() {
  is_device_enumeration_disabled_ = true;
}

scoped_refptr<MediaStreamCaptureIndicator>
MediaCaptureDevicesDispatcher::GetMediaStreamCaptureIndicator() {
  return media_stream_capture_indicator_;
}

DesktopStreamsRegistry*
MediaCaptureDevicesDispatcher::GetDesktopStreamsRegistry() {
  if (!desktop_streams_registry_)
    desktop_streams_registry_.reset(new DesktopStreamsRegistry());
  return desktop_streams_registry_.get();
}

void MediaCaptureDevicesDispatcher::OnAudioCaptureDevicesChanged() {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  HostThread::PostTask(
      HostThread::UI, FROM_HERE,
      base::BindOnce(
          &MediaCaptureDevicesDispatcher::NotifyAudioDevicesChangedOnUIThread,
          base::Unretained(this)));
}

void MediaCaptureDevicesDispatcher::OnVideoCaptureDevicesChanged() {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  HostThread::PostTask(
      HostThread::UI, FROM_HERE,
      base::BindOnce(
          &MediaCaptureDevicesDispatcher::NotifyVideoDevicesChangedOnUIThread,
          base::Unretained(this)));
}

void MediaCaptureDevicesDispatcher::OnMediaRequestStateChanged(
    int render_process_id,
    int render_frame_id,
    int page_request_id,
    const GURL& security_origin,
    common::MediaStreamType stream_type,
    MediaRequestState state) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  HostThread::PostTask(
      HostThread::UI, FROM_HERE,
      base::BindOnce(
          &MediaCaptureDevicesDispatcher::UpdateMediaRequestStateOnUIThread,
          base::Unretained(this), render_process_id, render_frame_id,
          page_request_id, security_origin, stream_type, state));
}

void MediaCaptureDevicesDispatcher::OnCreatingAudioStream(
    int render_process_id,
    int render_frame_id) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  HostThread::PostTask(
      HostThread::UI, FROM_HERE,
      base::BindOnce(
          &MediaCaptureDevicesDispatcher::OnCreatingAudioStreamOnUIThread,
          base::Unretained(this), render_process_id, render_frame_id));
}

void MediaCaptureDevicesDispatcher::NotifyAudioDevicesChangedOnUIThread() {
  common::MediaStreamDevices devices = GetAudioCaptureDevices();
  for (auto& observer : observers_)
    observer.OnUpdateAudioDevices(devices);
}

void MediaCaptureDevicesDispatcher::NotifyVideoDevicesChangedOnUIThread() {
  common::MediaStreamDevices devices = GetVideoCaptureDevices();
  for (auto& observer : observers_)
    observer.OnUpdateVideoDevices(devices);
}

void MediaCaptureDevicesDispatcher::UpdateMediaRequestStateOnUIThread(
    int render_process_id,
    int render_frame_id,
    int page_request_id,
    const GURL& security_origin,
    common::MediaStreamType stream_type,
    MediaRequestState state) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  for (const auto& handler : media_access_handlers_) {
    if (handler->SupportsStreamType(
            ApplicationContentsFromIds(render_process_id, render_frame_id), stream_type)) {
      handler->UpdateMediaRequestState(render_process_id, render_frame_id,
                                       page_request_id, stream_type, state);
      break;
    }
  }

#if defined(OS_CHROMEOS)
  if (IsOriginForCasting(security_origin) && IsVideoMediaType(stream_type)) {
    // Notify ash that casting state has changed.
    if (state == MEDIA_REQUEST_STATE_DONE) {
      ash::Domain::Get()->OnCastingSessionStartedOrStopped(true);
    } else if (state == MEDIA_REQUEST_STATE_CLOSING) {
      ash::Domain::Get()->OnCastingSessionStartedOrStopped(false);
    }
  }
#endif

  for (auto& observer : observers_) {
    observer.OnRequestUpdate(render_process_id, render_frame_id, stream_type,
                             state);
  }
}

void MediaCaptureDevicesDispatcher::OnCreatingAudioStreamOnUIThread(
    int render_process_id,
    int render_frame_id) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  for (auto& observer : observers_)
    observer.OnCreatingAudioStream(render_process_id, render_frame_id);
}

bool MediaCaptureDevicesDispatcher::IsInsecureCapturingInProgress(
    int render_process_id,
    int render_frame_id) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  return false;
}

void MediaCaptureDevicesDispatcher::SetTestAudioCaptureDevices(
    const common::MediaStreamDevices& devices) {
  test_audio_devices_ = devices;
}

void MediaCaptureDevicesDispatcher::SetTestVideoCaptureDevices(
    const common::MediaStreamDevices& devices) {
  test_video_devices_ = devices;
}

void MediaCaptureDevicesDispatcher::OnSetCapturingLinkSecured(
    int render_process_id,
    int render_frame_id,
    int page_request_id,
    common::MediaStreamType stream_type,
    bool is_secure) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  if (stream_type != common::MEDIA_TAB_VIDEO_CAPTURE &&
      stream_type != common::MEDIA_DESKTOP_VIDEO_CAPTURE)
    return;

  HostThread::PostTask(
      HostThread::UI, FROM_HERE,
      base::BindOnce(&MediaCaptureDevicesDispatcher::UpdateCapturingLinkSecured,
                     base::Unretained(this), render_process_id, render_frame_id,
                     page_request_id, stream_type, is_secure));
}

void MediaCaptureDevicesDispatcher::UpdateCapturingLinkSecured(
    int render_process_id,
    int render_frame_id,
    int page_request_id,
    common::MediaStreamType stream_type,
    bool is_secure) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  if (stream_type != common::MEDIA_TAB_VIDEO_CAPTURE &&
      stream_type != common::MEDIA_DESKTOP_VIDEO_CAPTURE)
    return;

}

}