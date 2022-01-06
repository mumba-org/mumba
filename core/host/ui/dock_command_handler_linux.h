// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_VIEWS_FRAME_BROWSER_COMMAND_HANDLER_LINUX_H_
#define CHROME_BROWSER_UI_VIEWS_FRAME_BROWSER_COMMAND_HANDLER_LINUX_H_

#include "base/macros.h"
#include "ui/events/event_handler.h"

namespace host {
class DockWindow;

class DockCommandHandlerLinux : public ui::EventHandler {
 public:
  explicit DockCommandHandlerLinux(DockWindow* dock_window);
  ~DockCommandHandlerLinux() override;

 private:
  // ui::EventHandler:
  void OnMouseEvent(ui::MouseEvent* event) override;

  DockWindow* dock_window_;

  DISALLOW_COPY_AND_ASSIGN(DockCommandHandlerLinux);
};

}

#endif  // CHROME_BROWSER_UI_VIEWS_FRAME_BROWSER_COMMAND_HANDLER_LINUX_H_
