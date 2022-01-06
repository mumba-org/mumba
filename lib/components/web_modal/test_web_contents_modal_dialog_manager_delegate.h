// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_WEB_MODAL_TEST_APPLICATION_CONTENTS_MODAL_DIALOG_MANAGER_DELEGATE_H_
#define COMPONENTS_WEB_MODAL_TEST_APPLICATION_CONTENTS_MODAL_DIALOG_MANAGER_DELEGATE_H_

#include "components/web_modal/application_contents_modal_dialog_manager_delegate.h"

#include "base/compiler_specific.h"
#include "base/macros.h"

namespace web_modal {

class TestApplicationContentsModalDialogManagerDelegate
    : public ApplicationContentsModalDialogManagerDelegate {
 public:
  TestApplicationContentsModalDialogManagerDelegate();

  // ApplicationContentsModalDialogManagerDelegate overrides:
  void SetApplicationContentsBlocked(content::ApplicationContents* application_contents,
                             bool blocked) override;

  ApplicationContentsModalDialogHost* GetApplicationContentsModalDialogHost() override;

  bool IsApplicationContentsVisible(content::ApplicationContents* application_contents) override;

  void set_application_contents_visible(bool visible) {
    application_contents_visible_ = visible;
  }

  void set_application_contents_modal_dialog_host(ApplicationContentsModalDialogHost* host) {
    application_contents_modal_dialog_host_ = host;
  }

  bool application_contents_blocked() const { return application_contents_blocked_; }

 private:
  bool application_contents_visible_;
  bool application_contents_blocked_;
  ApplicationContentsModalDialogHost* application_contents_modal_dialog_host_;  // Not owned.

  DISALLOW_COPY_AND_ASSIGN(TestApplicationContentsModalDialogManagerDelegate);
};

}  // namespace web_modal

#endif  // COMPONENTS_WEB_MODAL_TEST_APPLICATION_CONTENTS_MODAL_DIALOG_MANAGER_DELEGATE_H_
