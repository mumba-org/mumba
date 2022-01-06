// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include "build/build_config.h"
#include "components/constrained_window/constrained_window_views.h"
#include "components/constrained_window/native_application_contents_modal_dialog_manager_views.h"
#include "components/web_modal/single_application_contents_dialog_manager.h"
#include "components/web_modal/application_contents_modal_dialog_manager.h"
#include "core/host/application/application_contents.h"
#include "ui/base/ui_base_features.h"
#include "ui/gfx/native_widget_types.h"

namespace constrained_window {

void ShowModalDialog(gfx::NativeWindow dialog,
                     host::ApplicationContents* application_contents) {
#if defined(OS_MACOSX)
  if (features::IsViewsBrowserCocoa())
    return ShowModalDialogCocoa(dialog, application_contents);
#endif
  web_modal::ApplicationContentsModalDialogManager* manager =
      web_modal::ApplicationContentsModalDialogManager::FromApplicationContents(application_contents);
  DCHECK(manager);
  std::unique_ptr<web_modal::SingleApplicationContentsDialogManager> dialog_manager(
      new constrained_window::NativeApplicationContentsModalDialogManagerViews(
          dialog, manager));
  manager->ShowDialogWithManager(dialog, std::move(dialog_manager));
}

}  // namespace constrained_window
