// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/usb/web_usb_chooser_service_desktop.h"

#include <utility>

#include "core/host/ui/browser_finder.h"
#include "core/host/ui/chrome_bubble_manager.h"
#include "core/host/ui/permission_bubble/chooser_bubble_delegate.h"
#include "core/host/usb/usb_chooser_controller.h"
#include "components/bubble/bubble_controller.h"
#include "core/host/application_contents.h"

namespace host {

WebUsbChooserServiceDesktop::WebUsbChooserServiceDesktop(
    ApplicationWindowHost* application_window_host)
    : WebUsbChooserService(application_window_host) {}

WebUsbChooserServiceDesktop::~WebUsbChooserServiceDesktop() {
  if (bubble_)
    bubble_->CloseBubble(BUBBLE_CLOSE_FORCED);
}

void WebUsbChooserServiceDesktop::ShowChooser(
    std::unique_ptr<UsbChooserController> controller) {
  // Only one chooser bubble may be shown at a time.
  if (bubble_)
    bubble_->CloseBubble(BUBBLE_CLOSE_FORCED);

  auto delegate = std::make_unique<ChooserBubbleDelegate>(
      application_window_host(), std::move(controller));
  auto* application_contents =
      ApplicationContents::FromApplicationWindowHost(application_window_host());
  Browser* browser = chrome::FindBrowserWithApplicationContents(application_contents);
  bubble_ = browser->GetBubbleManager()->ShowBubble(std::move(delegate));
}

}