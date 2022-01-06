// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/unhandled_keyboard_event_handler.h"

#include "ui/events/event.h"

namespace host {

// static
void UnhandledKeyboardEventHandler::HandleNativeKeyboardEvent(
    gfx::NativeEvent event,
    views::FocusManager* focus_manager) {
  // Any unhandled keyboard/character messages should be defproced.
  // This allows stuff like F10, etc to work correctly.
  const MSG& message(event->native_event());
  DefWindowProc(message.hwnd, message.message, message.wParam, message.lParam);
}

}  // namespace views
