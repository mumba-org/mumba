// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_CONSTRAINED_WINDOW_CONSTRAINED_WINDOW_VIEWS_H_
#define COMPONENTS_CONSTRAINED_WINDOW_CONSTRAINED_WINDOW_VIEWS_H_

#include <memory>

#include "build/build_config.h"
#include "ui/gfx/native_widget_types.h"

namespace host {
class ApplicationContents;
}

namespace views {
class DialogDelegate;
class Widget;
class WidgetDelegate;
}

namespace web_modal {
class ModalDialogHost;
class ApplicationContentsModalDialogHost;
}

namespace constrained_window {

class ConstrainedWindowViewsClient;

// Sets the ConstrainedWindowClient impl.
void SetConstrainedWindowViewsClient(
    std::unique_ptr<ConstrainedWindowViewsClient> client);

// Update the position of dialog |widget| against |dialog_host|. This is used to
// reposition widgets e.g. when the host dimensions change.
void UpdateApplicationContentsModalDialogPosition(
    views::Widget* widget,
    web_modal::ApplicationContentsModalDialogHost* dialog_host);

void UpdateWidgetModalDialogPosition(
    views::Widget* widget,
    web_modal::ModalDialogHost* dialog_host);

// Returns the top level ApplicationContents of |initiator_app_contents|.
host::ApplicationContents* GetTopLevelApplicationContents(
    host::ApplicationContents* initiator_app_contents);

// Shows the dialog with a new SingleApplicationContentsDialogManager. The dialog will
// notify via WillClose() when it is being destroyed.
void ShowModalDialog(gfx::NativeWindow dialog,
                     host::ApplicationContents* app_contents);
#if defined(OS_MACOSX)
// Temporary shim for Polychrome. See bottom of first comment in
// https://crbug.com/804950 for details.
void ShowModalDialogCocoa(gfx::NativeWindow dialog,
                          host::ApplicationContents* app_contents);
#endif

// Calls CreateWebModalDialogViews, shows the dialog, and returns its widget.
views::Widget* ShowWebModalDialogViews(
    views::WidgetDelegate* dialog,
    host::ApplicationContents* initiator_app_contents);

#if defined(OS_MACOSX)
// Like ShowWebModalDialogViews, but used to show a native dialog "sheet" on
// Mac. Sheets are always modal to their parent window. To make them tab-modal,
// this provides an invisible tab-modal overlay window managed by
// ApplicationContentsModalDialogManager, which can host a dialog sheet.
views::Widget* ShowWebModalDialogWithOverlayViews(
    views::WidgetDelegate* dialog,
    host::ApplicationContents* initiator_app_contents);
#endif

// Create a widget for |dialog| that is modal to |app_contents|.
// The modal type of |dialog->GetModalType()| must be ui::MODAL_TYPE_CHILD.
views::Widget* CreateWebModalDialogViews(views::WidgetDelegate* dialog,
                                         host::ApplicationContents* app_contents);

// Create a widget for |dialog| that has a modality given by
// |dialog->GetModalType()|.  The modal type must be either
// ui::MODAL_TYPE_SYSTEM or ui::MODAL_TYPE_WINDOW.  This places the dialog
// appropriately if |parent| is a valid browser window. Currently, |parent| may
// be null for MODAL_TYPE_WINDOW, but that's a bug and callers shouldn't rely on
// that working. See http://crbug.com/657293.
views::Widget* CreateBrowserModalDialogViews(views::DialogDelegate* dialog,
                                             gfx::NativeWindow parent);

}  // namespace constrained_window

#endif  // COMPONENTS_CONSTRAINED_WINDOW_CONSTRAINED_WINDOW_VIEWS_H_
