// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/web_modal/test_application_contents_modal_dialog_manager_delegate.h"

namespace web_modal {

TestApplicationContentsModalDialogManagerDelegate::
    TestApplicationContentsModalDialogManagerDelegate()
    : application_contents_visible_(true),
      application_contents_blocked_(false),
      application_contents_modal_dialog_host_(nullptr) {}

void TestApplicationContentsModalDialogManagerDelegate::SetApplicationContentsBlocked(
    content::ApplicationContents* application_contents,
    bool blocked) {
  application_contents_blocked_ = blocked;
}

ApplicationContentsModalDialogHost* TestApplicationContentsModalDialogManagerDelegate::
    GetApplicationContentsModalDialogHost() {
  return application_contents_modal_dialog_host_;
}

bool TestApplicationContentsModalDialogManagerDelegate::IsApplicationContentsVisible(
  content::ApplicationContents* application_contents) {
  return application_contents_visible_;
}

}  // namespace web_modal
