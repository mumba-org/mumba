// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/unhandled_keyboard_event_handler.h"

#include "ui/events/event.h"
#include "ui/views/focus/focus_manager.h"

namespace host {

// static
void UnhandledKeyboardEventHandler::HandleNativeKeyboardEvent(
    gfx::NativeEvent event,
    views::FocusManager* focus_manager) {
  focus_manager->OnKeyEvent(*static_cast<ui::KeyEvent*>(event));
}

}  // namespace views
