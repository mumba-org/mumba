// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MEDIA_MEDIA_DEVICES_UTIL_H_
#define MUMBA_HOST_MEDIA_MEDIA_DEVICES_UTIL_H_

#include <string>
#include <utility>

#include "base/callback.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/media/media_devices.h"
#include "url/origin.h"

namespace host {

// Returns the ID of the user-default device ID via |callback|.
// If no such device ID can be found, |callback| receives an empty string.
void CONTENT_EXPORT GetDefaultMediaDeviceID(
    common::MediaDeviceType device_type,
    int render_process_id,
    int render_frame_id,
    const base::Callback<void(const std::string&)>& callback);

// Returns the current media device ID salt and security origin for the given
// |render_process_id| and |render_frame_id|. These values are used to produce
// unique media-device IDs for each origin and renderer process. These values
// should not be cached since the user can explicitly change them at any time.
// This function must run on the UI thread.
std::pair<std::string, url::Origin> GetMediaDeviceSaltAndOrigin(
    int render_process_id,
    int render_frame_id);

// Returns a translated version of |device_info| suitable for use in a renderer
// process.
// The |device_id| field is hashed using |device_id_salt| and |security_origin|.
// The |group_id| field is hashed using |group_id_salt| and |security_origin|.
// The |label| field is removed if |has_permission| is false.
common::MediaDeviceInfo TranslateMediaDeviceInfo(bool has_permission,
                                         const std::string& device_id_salt,
                                         const std::string& group_id_salt,
                                         const url::Origin& security_origin,
                                         const common::MediaDeviceInfo& device_info);

// Returns a translated version of |device_infos|, with each element translated
// using TranslateMediaDeviceInfo().
common::MediaDeviceInfoArray TranslateMediaDeviceInfoArray(
    bool has_permission,
    const std::string& device_id_salt,
    const std::string& group_id_salt,
    const url::Origin& security_origin,
    const common::MediaDeviceInfoArray& device_infos);

// Type definition to make it easier to use mock alternatives to
// GetMediaDeviceSaltAndOrigin.
using MediaDeviceSaltAndOriginCallback =
    base::RepeatingCallback<std::pair<std::string, url::Origin>(int, int)>;

}  // namespace host

#endif  // MUMBA_HOST_MEDIA_MEDIA_DEVICES_UTIL_H_
