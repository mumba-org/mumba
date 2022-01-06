// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_WEB_MODAL_SINGLE_APPLICATION_CONTENTS_DIALOG_MANAGER_H_
#define COMPONENTS_WEB_MODAL_SINGLE_APPLICATION_CONTENTS_DIALOG_MANAGER_H_

#include "base/macros.h"
#include "ui/gfx/native_widget_types.h"

namespace host {
class ApplicationContents;
}  // namespace content

namespace web_modal {

class ApplicationContentsModalDialogHost;

// Interface from SingleApplicationContentsDialogManager to
// ApplicationContentsModalDialogManager.
class SingleApplicationContentsDialogManagerDelegate {
 public:
  SingleApplicationContentsDialogManagerDelegate() {}
  virtual ~SingleApplicationContentsDialogManagerDelegate() {}

  virtual host::ApplicationContents* GetApplicationContents() const = 0;

  // Notify the delegate that the dialog is closing. The native
  // manager will be deleted before the end of this call.
  virtual void WillClose(gfx::NativeWindow dialog) = 0;

 private:
  DISALLOW_COPY_AND_ASSIGN(SingleApplicationContentsDialogManagerDelegate);
};

// Provides an interface for platform-specific UI implementation for the web
// contents modal dialog. Each object will manage a single dialog window
// during its lifecycle.
//
// Implementation classes should accept a dialog window at construction time
// and register to be notified when the dialog is closing, so that it can
// notify its delegate (WillClose method).
class SingleApplicationContentsDialogManager {
 public:
  virtual ~SingleApplicationContentsDialogManager() {}

  // Makes the web contents modal dialog visible. Only one web contents modal
  // dialog is shown at a time per tab.
  virtual void Show() = 0;

  // Hides the web contents modal dialog without closing it.
  virtual void Hide() = 0;

  // Closes the web contents modal dialog.
  // If this method causes a WillClose() call to the delegate, the manager
  // will be deleted at the close of that invocation.
  virtual void Close() = 0;

  // Sets focus on the web contents modal dialog.
  virtual void Focus() = 0;

  // Runs a pulse animation for the web contents modal dialog.
  virtual void Pulse() = 0;

  // Called when the host view for the dialog has changed.
  virtual void HostChanged(ApplicationContentsModalDialogHost* new_host) = 0;

  // Return the dialog under management by this object.
  virtual gfx::NativeWindow dialog() = 0;

 protected:
  SingleApplicationContentsDialogManager() {}

 private:
  DISALLOW_COPY_AND_ASSIGN(SingleApplicationContentsDialogManager);
};

}  // namespace web_modal

#endif  // COMPONENTS_WEB_MODAL_SINGLE_APPLICATION_CONTENTS_DIALOG_MANAGER_H_
