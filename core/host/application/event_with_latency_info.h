// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_EVENT_WITH_LATENCY_INFO_H_
#define MUMBA_HOST_APPLICATION_EVENT_WITH_LATENCY_INFO_H_

#include "core/shared/common/input/event_with_latency_info.h"
#include "core/host/application/native_web_keyboard_event.h"

namespace host {

typedef common::EventWithLatencyInfo<NativeWebKeyboardEvent>
    NativeWebKeyboardEventWithLatencyInfo;

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_EVENT_WITH_LATENCY_INFO_H_
