// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_CONSTRAINED_WINDOW_NATIVE_WEB_CONTENTS_MODAL_DIALOG_MANAGER_VIEWS_MAC_H_
#define COMPONENTS_CONSTRAINED_WINDOW_NATIVE_WEB_CONTENTS_MODAL_DIALOG_MANAGER_VIEWS_MAC_H_

#include "components/constrained_window/native_application_contents_modal_dialog_manager_views.h"

namespace web_modal {
class SingleApplicationContentsDialogManagerDelegate;
}

namespace constrained_window {

// Class for parenting a Mac Cocoa sheet on a views tab modal dialog off of a
// views browser, e.g. for tab-modal Cocoa sheets. Since Cocoa sheets are modal
// to the parent window, the sheet is instead parented to an invisible views
// overlay window which is tab-modal.
class NativeApplicationContentsModalDialogManagerViewsMac
    : public NativeApplicationContentsModalDialogManagerViews {
 public:
  NativeApplicationContentsModalDialogManagerViewsMac(
      gfx::NativeWindow dialog,
      web_modal::SingleApplicationContentsDialogManagerDelegate* native_delegate);

  // NativeApplicationContentsModalDialogManagerViews:
  void OnPositionRequiresUpdate() override;
  void ShowWidget(views::Widget* widget) override;
  void HideWidget(views::Widget* widget) override;

 private:
  DISALLOW_COPY_AND_ASSIGN(NativeApplicationContentsModalDialogManagerViewsMac);
};

}  // namespace constrained_window

#endif  // COMPONENTS_CONSTRAINED_WINDOW_NATIVE_WEB_CONTENTS_MODAL_DIALOG_MANAGER_VIEWS_MAC_H_
