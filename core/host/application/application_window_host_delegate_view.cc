// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/application_window_host_delegate_view.h"

namespace host {

#if defined(OS_ANDROID)
ui::OverscrollRefreshHandler*
ApplicationWindowHostDelegateView::GetOverscrollRefreshHandler() const {
  return nullptr;
}
#endif

int ApplicationWindowHostDelegateView::GetTopControlsHeight() const {
  return 0;
}

int ApplicationWindowHostDelegateView::GetBottomControlsHeight() const {
  return 0;
}

bool ApplicationWindowHostDelegateView::DoBrowserControlsShrinkBlinkSize() const {
  return false;
}

void ApplicationWindowHostDelegateView::GestureEventAck(
    const blink::WebGestureEvent& event,
    common::InputEventAckState ack_result) {}

}  //  namespace host
