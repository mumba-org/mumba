// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/dock_application_modal_dialog_manager_delegate.h"

#include "core/host/ui/platform_util.h"
#include "core/host/application/application_contents.h"

namespace host {

DockApplicationModalDialogManagerDelegate::DockApplicationModalDialogManagerDelegate() {
}

DockApplicationModalDialogManagerDelegate::~DockApplicationModalDialogManagerDelegate() {
}

bool DockApplicationModalDialogManagerDelegate::IsApplicationContentsVisible(
    ApplicationContents* app_contents) {
  return platform_util::IsVisible(app_contents->GetNativeView());
}

}