// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_WEB_MODAL_APPLICATION_CONTENTS_MODAL_DIALOG_MANAGER_DELEGATE_H_
#define COMPONENTS_WEB_MODAL_APPLICATION_CONTENTS_MODAL_DIALOG_MANAGER_DELEGATE_H_

namespace host {
class ApplicationContents;
}

namespace web_modal {

class ApplicationContentsModalDialogHost;

class ApplicationContentsModalDialogManagerDelegate {
 public:
  // Changes the blocked state of |application_contents|. ApplicationContentses are considered
  // blocked while displaying a web contents modal dialog. During that time
  // renderer host will ignore any UI interaction within ApplicationContents outside of
  // the currently displaying dialog.
  virtual void SetApplicationContentsBlocked(host::ApplicationContents* app_contents,
                                     bool blocked);

  // Returns the ApplicationContentsModalDialogHost for use in positioning web contents
  // modal dialogs within the browser window.
  virtual ApplicationContentsModalDialogHost* GetApplicationContentsModalDialogHost();

  // Returns whether the ApplicationContents is currently visible or not.
  virtual bool IsApplicationContentsVisible(host::ApplicationContents* app_contents);

 protected:
  virtual ~ApplicationContentsModalDialogManagerDelegate();
};

}  // namespace web_modal

#endif  // COMPONENTS_WEB_MODAL_APPLICATION_CONTENTS_MODAL_DIALOG_MANAGER_DELEGATE_H_
