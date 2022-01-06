// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/unhandled_keyboard_event_handler.h"

#import "base/mac/foundation_util.h"
#import "ui/views/cocoa/native_widget_mac_nswindow.h"

namespace host {

// static
void UnhandledKeyboardEventHandler::HandleNativeKeyboardEvent(
    gfx::NativeEvent event,
    views::FocusManager* focus_manager) {
  [base::mac::ObjCCastStrict<NativeWidgetMacNSWindow>([event window])
      redispatchKeyEvent:event];
}

}  // namespace views
