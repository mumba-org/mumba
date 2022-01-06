// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include "components/constrained_window/constrained_window_views.h"
#include "components/web_modal/single_application_contents_dialog_manager.h"
#include "components/web_modal/application_contents_modal_dialog_manager.h"
#include "content/public/browser/application_contents.h"
#include "ui/base/ui_features.h"
#include "ui/gfx/native_widget_types.h"

// TODO(patricialor): This is a layering violation and should be deleted.
// Currently it's needed because on Cocoa, the dialog needs to be shown with a
// SingleApplicationContentsDialogManagerViewsMac, which depends on things inside
// chrome/browser/ui/cocoa/constrained_window/* and thus can't be moved out into
// components/constrained_window/*. Instead, to get this to work, the
// CreateNativeWebModalManager() method is declared in the web_modal component,
// but defined outside of that in c/b/u/cocoa/.

namespace constrained_window {

void ShowModalDialogCocoa(gfx::NativeWindow dialog,
                          host::ApplicationContents* initiator_application_contents) {
  web_modal::ApplicationContentsModalDialogManager* manager =
      web_modal::ApplicationContentsModalDialogManager::FromApplicationContents(
          initiator_application_contents);
  std::unique_ptr<web_modal::SingleApplicationContentsDialogManager> dialog_manager(
      web_modal::ApplicationContentsModalDialogManager::CreateNativeWebModalManager(
          dialog, manager));
  manager->ShowDialogWithManager(dialog, std::move(dialog_manager));
}

#if !BUILDFLAG(MAC_VIEWS_BROWSER)
void ShowModalDialog(gfx::NativeWindow dialog,
                     host::ApplicationContents* initiator_application_contents) {
  ShowModalDialogCocoa(dialog, initiator_application_contents);
}
#endif

}  // namespace constrained_window
