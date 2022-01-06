// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/web_modal/application_contents_modal_dialog_manager_delegate.h"

#include <string.h>

namespace web_modal {

void ApplicationContentsModalDialogManagerDelegate::SetApplicationContentsBlocked(
    host::ApplicationContents* app_contents, bool blocked) {
}

ApplicationContentsModalDialogHost*
    ApplicationContentsModalDialogManagerDelegate::GetApplicationContentsModalDialogHost() {
  return nullptr;
}

bool ApplicationContentsModalDialogManagerDelegate::IsApplicationContentsVisible(
    host::ApplicationContents* app_contents) {
  return true;
}

ApplicationContentsModalDialogManagerDelegate::~ApplicationContentsModalDialogManagerDelegate(
) {}

}  // namespace web_modal
