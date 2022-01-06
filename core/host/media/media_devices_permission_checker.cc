// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/media/media_devices_permission_checker.h"

#include <utility>
#include <vector>

#include "base/bind.h"
#include "base/command_line.h"
#include "base/feature_list.h"
//#include "core/host/frame_host/render_frame_host_delegate.h"
//#include "core/host/frame_host/render_frame_host_impl.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/application_window_host_delegate.h"
#include "core/host/application/application_process_host.h"
#include "core/shared/common/media/media_devices.h"
//#include "core/host/browser_context.h"
#include "core/host/host_thread.h"
#include "core/shared/common/content_features.h"
#include "core/shared/common/switches.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace host {

namespace {

MediaDevicesManager::BoolDeviceTypes DoCheckPermissionsOnUIThread(
    MediaDevicesManager::BoolDeviceTypes requested_device_types,
    int render_process_id,
    int render_frame_id) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  ApplicationWindowHost* window_host =
      ApplicationWindowHost::FromID(render_process_id, render_frame_id);

  // If there is no |frame_host|, return false for all permissions.
  if (!window_host)
    return MediaDevicesManager::BoolDeviceTypes();

  //ApplicationWindowHostDelegate* delegate = window_host->delegate();
  url::Origin origin = url::Origin();//window_host->GetLastCommittedOrigin();
  bool audio_permission = true;//delegate->CheckMediaAccessPermission(
      //window_host, origin, common::MEDIA_DEVICE_AUDIO_CAPTURE);
  bool mic_feature_policy = true;
  bool camera_feature_policy = true;
  //if (base::FeatureList::IsEnabled(features::kUseFeaturePolicyForPermissions)) {
  //  mic_feature_policy = frame_host->IsFeatureEnabled(
  //      blink::mojom::FeaturePolicyFeature::kMicrophone);
  //  camera_feature_policy = frame_host->IsFeatureEnabled(
  //      blink::mojom::FeaturePolicyFeature::kCamera);
 // }

  MediaDevicesManager::BoolDeviceTypes result;
  // Speakers.
  // TODO(guidou): use specific permission for audio output when it becomes
  // available. See http://crbug.com/556542.
  result[common::MEDIA_DEVICE_TYPE_AUDIO_OUTPUT] =
      requested_device_types[common::MEDIA_DEVICE_TYPE_AUDIO_OUTPUT] &&
      audio_permission;

  // Mic.
  result[common::MEDIA_DEVICE_TYPE_AUDIO_INPUT] =
      requested_device_types[common::MEDIA_DEVICE_TYPE_AUDIO_INPUT] &&
      audio_permission && mic_feature_policy;

  // Camera.
  result[common::MEDIA_DEVICE_TYPE_VIDEO_INPUT] =
      requested_device_types[common::MEDIA_DEVICE_TYPE_VIDEO_INPUT] &&
      //delegate->CheckMediaAccessPermission(window_host, origin,
      //                                     common::MEDIA_DEVICE_VIDEO_CAPTURE) &&
      camera_feature_policy;

  return result;
}

bool CheckSinglePermissionOnUIThread(common::MediaDeviceType device_type,
                                     int render_process_id,
                                     int render_frame_id) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  MediaDevicesManager::BoolDeviceTypes requested;
  requested[device_type] = true;
  MediaDevicesManager::BoolDeviceTypes result = DoCheckPermissionsOnUIThread(
      requested, render_process_id, render_frame_id);
  return result[device_type];
}

}  // namespace

MediaDevicesPermissionChecker::MediaDevicesPermissionChecker()
    : use_override_(false),//(base::CommandLine::ForCurrentProcess()->HasSwitch(
          //switches::kUseFakeUIForMediaStream)),
      override_value_(true) {}//(
          //base::CommandLine::ForCurrentProcess()->GetSwitchValueASCII(
          //    switches::kUseFakeUIForMediaStream) != "deny") {}

MediaDevicesPermissionChecker::MediaDevicesPermissionChecker(
    bool override_value)
    : use_override_(true), override_value_(override_value) {}

bool MediaDevicesPermissionChecker::CheckPermissionOnUIThread(
    common::MediaDeviceType device_type,
    int render_process_id,
    int render_frame_id) const {
  if (use_override_)
    return override_value_;

  return CheckSinglePermissionOnUIThread(device_type, render_process_id,
                                         render_frame_id);
}

void MediaDevicesPermissionChecker::CheckPermission(
    common::MediaDeviceType device_type,
    int render_process_id,
    int render_frame_id,
    base::OnceCallback<void(bool)> callback) const {
  if (use_override_) {
    std::move(callback).Run(override_value_);
    return;
  }

  HostThread::PostTaskAndReplyWithResult(
      HostThread::UI, FROM_HERE,
      base::BindOnce(&CheckSinglePermissionOnUIThread, device_type,
                     render_process_id, render_frame_id),
      std::move(callback));
}

void MediaDevicesPermissionChecker::CheckPermissions(
    MediaDevicesManager::BoolDeviceTypes requested,
    int render_process_id,
    int render_frame_id,
    base::OnceCallback<void(const MediaDevicesManager::BoolDeviceTypes&)>
        callback) const {
  if (use_override_) {
    MediaDevicesManager::BoolDeviceTypes result;
    result.fill(override_value_);
    std::move(callback).Run(result);
    return;
  }

  HostThread::PostTaskAndReplyWithResult(
      HostThread::UI, FROM_HERE,
      base::BindOnce(&DoCheckPermissionsOnUIThread, requested,
                     render_process_id, render_frame_id),
      std::move(callback));
}

}  // namespace host
