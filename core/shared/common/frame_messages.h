// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_COMMON_FRAME_MESSAGES_H_
#define CONTENT_COMMON_FRAME_MESSAGES_H_

#include <stddef.h>
#include <stdint.h>

#include <set>
#include <string>
#include <vector>

#include "base/memory/shared_memory.h"
#include "base/optional.h"
#include "base/process/process.h"
#include "base/strings/string16.h"
#include "build/build_config.h"
#include "cc/ipc/cc_param_traits.h"
#include "ipc/ipc_channel_handle.h"
#include "ipc/ipc_message_macros.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/content_param_traits.h"
#include "mojo/public/cpp/system/message_pipe.h"

#undef IPC_MESSAGE_EXPORT
#define IPC_MESSAGE_EXPORT CONTENT_EXPORT

#define IPC_MESSAGE_START FrameMsgStart

IPC_STRUCT_BEGIN(FrameHostMsg_CreateNewWindow_Params)
  IPC_STRUCT_MEMBER(int32_t, parent_routing_id)
  //IPC_STRUCT_MEMBER(blink::WebTreeScopeType, scope)
  IPC_STRUCT_MEMBER(std::string, frame_name)
  IPC_STRUCT_MEMBER(std::string, frame_unique_name)
  IPC_STRUCT_MEMBER(bool, is_created_by_script)
  //IPC_STRUCT_MEMBER(blink::FramePolicy, frame_policy)
  //IPC_STRUCT_MEMBER(content::FrameOwnerProperties, frame_owner_properties)
IPC_STRUCT_END()

IPC_MESSAGE_ROUTED1(FrameHostMsg_VisualStateResponse, uint64_t /* id */)

IPC_MESSAGE_CONTROL2(FrameMsg_VisualStateRequest, int /* routing_id */, uint64_t /* id */)

IPC_SYNC_MESSAGE_CONTROL1_2(
    FrameHostMsg_CreateNewWindow,
    FrameHostMsg_CreateNewWindow_Params,
    int32_t,                 /* new_routing_id */
    mojo::MessagePipeHandle /* new_interface_provider */)

#endif  // CONTENT_COMMON_FRAME_MESSAGES_H_