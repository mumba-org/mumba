// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/dock_command_handler_linux.h"

#include "core/host/ui/dock.h"
#include "core/host/ui/tablist/tablist_model.h"
#include "core/host/ui/dock_window.h"
#include "core/host/ui/dock_frame.h"
//#include "core/host/navigation_controller.h"
#include "core/host/application/application_contents.h"
//#include "core/shared/common/content_features.h"
#include "ui/aura/window.h"
#include "ui/events/event.h"

namespace host {

DockCommandHandlerLinux::DockCommandHandlerLinux(
    DockWindow* dock_window)
    : dock_window_(dock_window) {
  aura::Window* window = dock_window_->frame()->GetNativeWindow();
  DCHECK(window);
  if (window)
    window->AddPreTargetHandler(this);
}

DockCommandHandlerLinux::~DockCommandHandlerLinux() {
  aura::Window* window = dock_window_->frame()->GetNativeWindow();
  if (window)
    window->RemovePreTargetHandler(this);
}

void DockCommandHandlerLinux::OnMouseEvent(ui::MouseEvent* event) {
  // Handle standard Linux mouse buttons for going back and forward.
  // Mouse press events trigger the navigations, while mouse release events are
  // consumed and ignored so they aren't forwarded as unpaired events (which may
  // trigger navigations as well)
  // bool mouse_pressed = (event->type() == ui::ET_MOUSE_PRESSED);
  // bool mouse_released = (event->type() == ui::ET_MOUSE_RELEASED);
  // if (!mouse_pressed && !mouse_released)
  //   return;

  // // If extended mouse buttons are supported handle them in the renderer.
  // if (base::FeatureList::IsEnabled(features::kExtendedMouseButtons))
  //   return;

  // bool back_button_toggled =
  //     (event->changed_button_flags() == ui::EF_BACK_MOUSE_BUTTON);
  // bool forward_button_toggled =
  //     (event->changed_button_flags() == ui::EF_FORWARD_MOUSE_BUTTON);
  // if (!back_button_toggled && !forward_button_toggled)
  //   return;

  // ApplicationContents* contents =
  //     dock_window_->dock()->tablist_model()->GetActiveApplicationContents();
  // if (!contents)
  //   return;

  // // Always consume the event, whether a navigation is successful or not.
  // //
  // // TODO(mustaq): Perhaps we should mark "handled" only for successful
  // //   navigation above but a bug in the past didn't allow it:
  // //   https://codereview.chromium.org/2763313002/#msg19
  // event->SetHandled();

  // if (!mouse_pressed)
  //   return;

  // content::NavigationController& controller = contents->GetController();
  // if (back_button_toggled && controller.CanGoBack())
  //   controller.GoBack();
  // else if (forward_button_toggled && controller.CanGoForward())
  //   controller.GoForward();
}

}
