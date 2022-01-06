// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Singly or Multiply-included shared traits file depending on circumstances.
// This allows the use of IPC serialization macros in more than one IPC message
// file.
#ifndef CONTENT_COMMON_CONTENT_PARAM_TRAITS_MACROS_H_
#define CONTENT_COMMON_CONTENT_PARAM_TRAITS_MACROS_H_

#include "ipc/ipc_message_macros.h"
#include "third_party/WebKit/public/platform/WebPageVisibilityState.h"
#include "third_party/WebKit/public/web/WebCompositionUnderline.h"
#include "third_party/WebKit/public/web/WebContentSecurityPolicy.h"
#include "third_party/WebKit/public/web/WebInputEvent.h"

#undef IPC_MESSAGE_EXPORT
#define IPC_MESSAGE_EXPORT


//IPC_ENUM_TRAITS_MAX_VALUE(common::InputEventAckState,
//                          common::INPUT_EVENT_ACK_STATE_MAX)
//IPC_ENUM_TRAITS_MAX_VALUE(common::ResourceType,
//                          common::RESOURCE_TYPE_LAST_TYPE - 1)
//IPC_ENUM_TRAITS_MAX_VALUE(common::RequestContextType,
//                          common::REQUEST_CONTEXT_TYPE_LAST)
//IPC_ENUM_TRAITS_MAX_VALUE(common::RequestContextFrameType,
//                          common::REQUEST_CONTEXT_FRAME_TYPE_LAST)
IPC_ENUM_TRAITS_MAX_VALUE(blink::WebContentSecurityPolicyType,
                          blink::WebContentSecurityPolicyTypeLast)
IPC_ENUM_TRAITS_MIN_MAX_VALUE(blink::WebInputEvent::Type,
                              blink::WebInputEvent::TypeFirst,
                              blink::WebInputEvent::TypeLast)
IPC_ENUM_TRAITS_MAX_VALUE(blink::WebPageVisibilityState,
                          blink::WebPageVisibilityStateLast)

IPC_STRUCT_TRAITS_BEGIN(blink::WebCompositionUnderline)
  IPC_STRUCT_TRAITS_MEMBER(startOffset)
  IPC_STRUCT_TRAITS_MEMBER(endOffset)
  IPC_STRUCT_TRAITS_MEMBER(color)
  IPC_STRUCT_TRAITS_MEMBER(thick)
  IPC_STRUCT_TRAITS_MEMBER(backgroundColor)
IPC_STRUCT_TRAITS_END()

#endif  // CONTENT_COMMON_CONTENT_PARAM_TRAITS_MACROS_H_
