// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/common/media/media_stream_typemap_traits.h"

#include "base/logging.h"

namespace mojo {

// static
common::mojom::MediaStreamType
EnumTraits<common::mojom::MediaStreamType, common::MediaStreamType>::ToMojom(
    common::MediaStreamType type) {
  switch (type) {
    case common::MediaStreamType::MEDIA_NO_SERVICE:
      return common::mojom::MediaStreamType::MEDIA_NO_SERVICE;
    case common::MediaStreamType::MEDIA_DEVICE_AUDIO_CAPTURE:
      return common::mojom::MediaStreamType::MEDIA_DEVICE_AUDIO_CAPTURE;
    case common::MediaStreamType::MEDIA_DEVICE_VIDEO_CAPTURE:
      return common::mojom::MediaStreamType::MEDIA_DEVICE_VIDEO_CAPTURE;
    case common::MediaStreamType::MEDIA_TAB_AUDIO_CAPTURE:
      return common::mojom::MediaStreamType::MEDIA_TAB_AUDIO_CAPTURE;
    case common::MediaStreamType::MEDIA_TAB_VIDEO_CAPTURE:
      return common::mojom::MediaStreamType::MEDIA_TAB_VIDEO_CAPTURE;
    case common::MediaStreamType::MEDIA_DESKTOP_VIDEO_CAPTURE:
      return common::mojom::MediaStreamType::MEDIA_DESKTOP_VIDEO_CAPTURE;
    case common::MediaStreamType::MEDIA_DESKTOP_AUDIO_CAPTURE:
      return common::mojom::MediaStreamType::MEDIA_DESKTOP_AUDIO_CAPTURE;
    case common::MediaStreamType::NUM_MEDIA_TYPES:
      return common::mojom::MediaStreamType::NUM_MEDIA_TYPES;
  }
  NOTREACHED();
  return common::mojom::MediaStreamType::MEDIA_NO_SERVICE;
}

// static
bool EnumTraits<common::mojom::MediaStreamType, common::MediaStreamType>::
    FromMojom(common::mojom::MediaStreamType input,
              common::MediaStreamType* out) {
  switch (input) {
    case common::mojom::MediaStreamType::MEDIA_NO_SERVICE:
      *out = common::MediaStreamType::MEDIA_NO_SERVICE;
      return true;
    case common::mojom::MediaStreamType::MEDIA_DEVICE_AUDIO_CAPTURE:
      *out = common::MediaStreamType::MEDIA_DEVICE_AUDIO_CAPTURE;
      return true;
    case common::mojom::MediaStreamType::MEDIA_DEVICE_VIDEO_CAPTURE:
      *out = common::MediaStreamType::MEDIA_DEVICE_VIDEO_CAPTURE;
      return true;
    case common::mojom::MediaStreamType::MEDIA_TAB_AUDIO_CAPTURE:
      *out = common::MediaStreamType::MEDIA_TAB_AUDIO_CAPTURE;
      return true;
    case common::mojom::MediaStreamType::MEDIA_TAB_VIDEO_CAPTURE:
      *out = common::MediaStreamType::MEDIA_TAB_VIDEO_CAPTURE;
      return true;
    case common::mojom::MediaStreamType::MEDIA_DESKTOP_VIDEO_CAPTURE:
      *out = common::MediaStreamType::MEDIA_DESKTOP_VIDEO_CAPTURE;
      return true;
    case common::mojom::MediaStreamType::MEDIA_DESKTOP_AUDIO_CAPTURE:
      *out = common::MediaStreamType::MEDIA_DESKTOP_AUDIO_CAPTURE;
      return true;
    case common::mojom::MediaStreamType::NUM_MEDIA_TYPES:
      *out = common::MediaStreamType::NUM_MEDIA_TYPES;
      return true;
  }
  NOTREACHED();
  return false;
}

// static
common::mojom::MediaStreamRequestResult
EnumTraits<common::mojom::MediaStreamRequestResult,
           common::MediaStreamRequestResult>::
    ToMojom(common::MediaStreamRequestResult result) {
  switch (result) {
    case common::MediaStreamRequestResult::MEDIA_DEVICE_OK:
      return common::mojom::MediaStreamRequestResult::OK;
    case common::MediaStreamRequestResult::MEDIA_DEVICE_PERMISSION_DENIED:
      return common::mojom::MediaStreamRequestResult::PERMISSION_DENIED;
    case common::MediaStreamRequestResult::MEDIA_DEVICE_PERMISSION_DISMISSED:
      return common::mojom::MediaStreamRequestResult::PERMISSION_DISMISSED;
    case common::MediaStreamRequestResult::MEDIA_DEVICE_INVALID_STATE:
      return common::mojom::MediaStreamRequestResult::INVALID_STATE;
    case common::MediaStreamRequestResult::MEDIA_DEVICE_NO_HARDWARE:
      return common::mojom::MediaStreamRequestResult::NO_HARDWARE;
    case common::MediaStreamRequestResult::
        MEDIA_DEVICE_INVALID_SECURITY_ORIGIN:
      return common::mojom::MediaStreamRequestResult::INVALID_SECURITY_ORIGIN;
    case common::MediaStreamRequestResult::MEDIA_DEVICE_TAB_CAPTURE_FAILURE:
      return common::mojom::MediaStreamRequestResult::TAB_CAPTURE_FAILURE;
    case common::MediaStreamRequestResult::MEDIA_DEVICE_SCREEN_CAPTURE_FAILURE:
      return common::mojom::MediaStreamRequestResult::SCREEN_CAPTURE_FAILURE;
    case common::MediaStreamRequestResult::MEDIA_DEVICE_CAPTURE_FAILURE:
      return common::mojom::MediaStreamRequestResult::CAPTURE_FAILURE;
    case common::MediaStreamRequestResult::
        MEDIA_DEVICE_CONSTRAINT_NOT_SATISFIED:
      return common::mojom::MediaStreamRequestResult::CONSTRAINT_NOT_SATISFIED;
    case common::MediaStreamRequestResult::
        MEDIA_DEVICE_TRACK_START_FAILURE_AUDIO:
      return common::mojom::MediaStreamRequestResult::
          TRACK_START_FAILURE_AUDIO;
    case common::MediaStreamRequestResult::
        MEDIA_DEVICE_TRACK_START_FAILURE_VIDEO:
      return common::mojom::MediaStreamRequestResult::
          TRACK_START_FAILURE_VIDEO;
    case common::MediaStreamRequestResult::MEDIA_DEVICE_NOT_SUPPORTED:
      return common::mojom::MediaStreamRequestResult::NOT_SUPPORTED;
    case common::MediaStreamRequestResult::MEDIA_DEVICE_FAILED_DUE_TO_SHUTDOWN:
      return common::mojom::MediaStreamRequestResult::FAILED_DUE_TO_SHUTDOWN;
    case common::MediaStreamRequestResult::MEDIA_DEVICE_KILL_SWITCH_ON:
      return common::mojom::MediaStreamRequestResult::KILL_SWITCH_ON;
    default:
      break;
  }
  NOTREACHED();
  return common::mojom::MediaStreamRequestResult::OK;
}

// static
bool EnumTraits<common::mojom::MediaStreamRequestResult,
                common::MediaStreamRequestResult>::
    FromMojom(common::mojom::MediaStreamRequestResult input,
              common::MediaStreamRequestResult* out) {
  switch (input) {
    case common::mojom::MediaStreamRequestResult::OK:
      *out = common::MediaStreamRequestResult::MEDIA_DEVICE_OK;
      return true;
    case common::mojom::MediaStreamRequestResult::PERMISSION_DENIED:
      *out = common::MediaStreamRequestResult::MEDIA_DEVICE_PERMISSION_DENIED;
      return true;
    case common::mojom::MediaStreamRequestResult::PERMISSION_DISMISSED:
      *out =
          common::MediaStreamRequestResult::MEDIA_DEVICE_PERMISSION_DISMISSED;
      return true;
    case common::mojom::MediaStreamRequestResult::INVALID_STATE:
      *out = common::MediaStreamRequestResult::MEDIA_DEVICE_INVALID_STATE;
      return true;
    case common::mojom::MediaStreamRequestResult::NO_HARDWARE:
      *out = common::MediaStreamRequestResult::MEDIA_DEVICE_NO_HARDWARE;
      return true;
    case common::mojom::MediaStreamRequestResult::INVALID_SECURITY_ORIGIN:
      *out = common::MediaStreamRequestResult::
          MEDIA_DEVICE_INVALID_SECURITY_ORIGIN;
      return true;
    case common::mojom::MediaStreamRequestResult::TAB_CAPTURE_FAILURE:
      *out =
          common::MediaStreamRequestResult::MEDIA_DEVICE_TAB_CAPTURE_FAILURE;
      return true;
    case common::mojom::MediaStreamRequestResult::SCREEN_CAPTURE_FAILURE:
      *out = common::MediaStreamRequestResult::
          MEDIA_DEVICE_SCREEN_CAPTURE_FAILURE;
      return true;
    case common::mojom::MediaStreamRequestResult::CAPTURE_FAILURE:
      *out = common::MediaStreamRequestResult::MEDIA_DEVICE_CAPTURE_FAILURE;
      return true;
    case common::mojom::MediaStreamRequestResult::CONSTRAINT_NOT_SATISFIED:
      *out = common::MediaStreamRequestResult::
          MEDIA_DEVICE_CONSTRAINT_NOT_SATISFIED;
      return true;
    case common::mojom::MediaStreamRequestResult::TRACK_START_FAILURE_AUDIO:
      *out = common::MediaStreamRequestResult::
          MEDIA_DEVICE_TRACK_START_FAILURE_AUDIO;
      return true;
    case common::mojom::MediaStreamRequestResult::TRACK_START_FAILURE_VIDEO:
      *out = common::MediaStreamRequestResult::
          MEDIA_DEVICE_TRACK_START_FAILURE_VIDEO;
      return true;
    case common::mojom::MediaStreamRequestResult::NOT_SUPPORTED:
      *out = common::MediaStreamRequestResult::MEDIA_DEVICE_NOT_SUPPORTED;
      return true;
    case common::mojom::MediaStreamRequestResult::FAILED_DUE_TO_SHUTDOWN:
      *out = common::MediaStreamRequestResult::
          MEDIA_DEVICE_FAILED_DUE_TO_SHUTDOWN;
      return true;
    case common::mojom::MediaStreamRequestResult::KILL_SWITCH_ON:
      *out = common::MediaStreamRequestResult::MEDIA_DEVICE_KILL_SWITCH_ON;
      return true;
  }
  NOTREACHED();
  return false;
}

// static
bool StructTraits<
    common::mojom::TrackControlsDataView,
    common::TrackControls>::Read(common::mojom::TrackControlsDataView input,
                                  common::TrackControls* out) {
  out->requested = input.requested();
  if (!input.ReadStreamSource(&out->stream_source))
    return false;
  if (!input.ReadDeviceId(&out->device_id))
    return false;
  return true;
}

// static
bool StructTraits<
    common::mojom::StreamControlsDataView,
    common::StreamControls>::Read(common::mojom::StreamControlsDataView input,
                                   common::StreamControls* out) {
  if (!input.ReadAudio(&out->audio))
    return false;
  if (!input.ReadVideo(&out->video))
    return false;
#if DCHECK_IS_ON()
  if (input.hotword_enabled() || input.disable_local_echo())
    DCHECK(out->audio.requested);
#endif
  out->hotword_enabled = input.hotword_enabled();
  out->disable_local_echo = input.disable_local_echo();
  return true;
}

}  // namespace mojo
