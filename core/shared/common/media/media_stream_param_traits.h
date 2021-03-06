// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// IPC messages for the media streaming.
// Multiply-included message file, hence no include guard.

#include "core/shared/common/content_export.h"
#include "core/shared/common/media_stream_request.h"
#include "ipc/ipc_message_macros.h"
#include "media/base/ipc/media_param_traits.h"
#include "media/capture/ipc/capture_param_traits.h"

#undef IPC_MESSAGE_EXPORT
#define IPC_MESSAGE_EXPORT CONTENT_EXPORT

IPC_ENUM_TRAITS_MAX_VALUE(common::MediaStreamType,
                          common::NUM_MEDIA_TYPES - 1)

IPC_ENUM_TRAITS_MAX_VALUE(media::VideoFacingMode,
                          media::NUM_MEDIA_VIDEO_FACING_MODES - 1)

IPC_STRUCT_TRAITS_BEGIN(common::MediaStreamDevice)
  IPC_STRUCT_TRAITS_MEMBER(type)
  IPC_STRUCT_TRAITS_MEMBER(id)
  IPC_STRUCT_TRAITS_MEMBER(video_facing)
  IPC_STRUCT_TRAITS_MEMBER(matched_output_device_id)
  IPC_STRUCT_TRAITS_MEMBER(name)
  IPC_STRUCT_TRAITS_MEMBER(input)
  IPC_STRUCT_TRAITS_MEMBER(session_id)
  IPC_STRUCT_TRAITS_MEMBER(camera_calibration)
IPC_STRUCT_TRAITS_END()
