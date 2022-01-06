// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/media/media_devices_util.h"

#include <utility>
#include <vector>

#include "base/bind.h"
#include "base/command_line.h"
#include "base/strings/string_split.h"
#include "base/strings/string_tokenizer.h"
//#include "core/host/frame_host/render_frame_host_delegate.h"
//#include "core/host/frame_host/render_frame_host_impl.h"
//#include "core/host/host_context.h"
#include "core/host/host_thread.h"
#include "core/host/application/media/media_device_id.h"
#include "core/host/application/application_window_host_delegate.h"
#include "core/host/application/application_window_host.h"
#include "core/shared/common/media_stream_request.h"
#include "media/base/media_switches.h"

namespace host {

namespace {

std::string GetDefaultMediaDeviceIDOnUIThread(common::MediaDeviceType device_type,
                                              int render_process_id,
                                              int render_frame_id) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  ApplicationWindowHost* window_host =
      ApplicationWindowHost::FromID(render_process_id, render_frame_id);
  if (!window_host)
    return std::string();

  ApplicationWindowHostDelegate* delegate = window_host->delegate();
  if (!delegate)
    return std::string();

  common::MediaStreamType media_stream_type;
  switch (device_type) {
    case common::MEDIA_DEVICE_TYPE_AUDIO_INPUT:
      media_stream_type = common::MEDIA_DEVICE_AUDIO_CAPTURE;
      break;
    case common::MEDIA_DEVICE_TYPE_VIDEO_INPUT:
      media_stream_type = common::MEDIA_DEVICE_VIDEO_CAPTURE;
      break;
    default:
      return std::string();
  }

  return delegate->GetDefaultMediaDeviceID(media_stream_type);
}

// This function is intended for testing purposes. It returns an empty string
// if no default device is supplied via the command line.
// std::string GetDefaultMediaDeviceIDFromCommandLine(
//     common::MediaDeviceType device_type) {
//   DCHECK(base::CommandLine::ForCurrentProcess()->HasSwitch(
//       switches::kUseFakeDeviceForMediaStream));
//   const std::string option =
//       base::CommandLine::ForCurrentProcess()->GetSwitchValueASCII(
//           switches::kUseFakeDeviceForMediaStream);
//   // Optional comma delimited parameters to the command line can specify values
//   // for the default device IDs.
//   // Examples: "video-input-default-id=mycam, audio-input-default-id=mymic"
//   base::StringTokenizer option_tokenizer(option, ", ");
//   option_tokenizer.set_quote_chars("\"");

//   while (option_tokenizer.GetNext()) {
//     std::vector<std::string> param =
//         base::SplitString(option_tokenizer.token(), "=", base::TRIM_WHITESPACE,
//                           base::SPLIT_WANT_NONEMPTY);
//     if (param.size() != 2u) {
//       DLOG(WARNING) << "Forgot a value '" << option << "'? Use name=value for "
//                     << switches::kUseFakeDeviceForMediaStream << ".";
//       return std::string();
//     }

//     if (device_type == common::MEDIA_DEVICE_TYPE_AUDIO_INPUT &&
//         param.front() == "audio-input-default-id") {
//       return param.back();
//     } else if (device_type == common::MEDIA_DEVICE_TYPE_VIDEO_INPUT &&
//                param.front() == "video-input-default-id") {
//       return param.back();
//     }
//   }

//   return std::string();
// }

}  // namespace

void GetDefaultMediaDeviceID(
    common::MediaDeviceType device_type,
    int render_process_id,
    int render_frame_id,
    const base::Callback<void(const std::string&)>& callback) {
  // if (base::CommandLine::ForCurrentProcess()->HasSwitch(
  //         switches::kUseFakeDeviceForMediaStream)) {
  //   std::string command_line_default_device_id =
  //       GetDefaultMediaDeviceIDFromCommandLine(device_type);
  //   if (!command_line_default_device_id.empty()) {
  //     callback.Run(command_line_default_device_id);
  //     return;
  //   }
  // }

  HostThread::PostTaskAndReplyWithResult(
      HostThread::UI, FROM_HERE,
      base::Bind(&GetDefaultMediaDeviceIDOnUIThread, device_type,
                 render_process_id, render_frame_id),
      callback);
}

std::pair<std::string, url::Origin> GetMediaDeviceSaltAndOrigin(
    int render_process_id,
    int render_frame_id) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  //ApplicationWindowHost* window_host =
  //    ApplicationWindowHost::FromID(render_process_id, render_frame_id);
  //ApplicationProcessHost* process_host =
  //    ApplicationProcessHost::FromID(render_process_id);
  //return std::make_pair(
  //    process_host ? process_host->GetBrowserContext()->GetMediaDeviceIDSalt()
  //                 : std::string(),
  //    window_host ? window_host->GetLastCommittedOrigin() : url::Origin());
  return std::make_pair(std::string(), url::Origin());
}

common::MediaDeviceInfo TranslateMediaDeviceInfo(bool has_permission,
                                         const std::string& device_id_salt,
                                         const std::string& group_id_salt,
                                         const url::Origin& security_origin,
                                         const common::MediaDeviceInfo& device_info) {
  return common::MediaDeviceInfo(
      GetHMACForMediaDeviceID(device_id_salt, security_origin,
                              device_info.device_id),
      has_permission ? device_info.label : std::string(),
      device_info.group_id.empty()
          ? std::string()
          : GetHMACForMediaDeviceID(group_id_salt, security_origin,
                                    device_info.group_id));
}

common::MediaDeviceInfoArray TranslateMediaDeviceInfoArray(
    bool has_permission,
    const std::string& device_id_salt,
    const std::string& group_id_salt,
    const url::Origin& security_origin,
    const common::MediaDeviceInfoArray& device_infos) {
  common::MediaDeviceInfoArray result;
  for (const auto& device_info : device_infos) {
    result.push_back(TranslateMediaDeviceInfo(has_permission, device_id_salt,
                                              group_id_salt, security_origin,
                                              device_info));
  }
  return result;
}

}  // namespace host
