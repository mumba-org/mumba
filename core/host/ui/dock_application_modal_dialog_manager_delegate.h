// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_CHROME_WEB_MODAL_DIALOG_MANAGER_DELEGATE_H_
#define CHROME_BROWSER_UI_CHROME_WEB_MODAL_DIALOG_MANAGER_DELEGATE_H_

#include "base/compiler_specific.h"
#include "base/macros.h"
#include "components/web_modal/application_contents_modal_dialog_manager_delegate.h"

namespace host {

class DockApplicationModalDialogManagerDelegate
    : public web_modal::ApplicationContentsModalDialogManagerDelegate {
 public:
  DockApplicationModalDialogManagerDelegate();
  ~DockApplicationModalDialogManagerDelegate() override;

 protected:
  // Overridden from web_modal::WebContentsModalDialogManagerDelegate:
  bool IsApplicationContentsVisible(ApplicationContents* app_contents) override;

 private:
  DISALLOW_COPY_AND_ASSIGN(DockApplicationModalDialogManagerDelegate);
};

}

#endif  // CHROME_BROWSER_UI_CHROME_WEB_MODAL_DIALOG_MANAGER_DELEGATE_H_
