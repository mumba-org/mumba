// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/application_contents_view_focus_helper.h"

#include "core/host/application/application_window_host_view.h"
#include "core/host/application/application_contents.h"
#include "ui/views/focus/focus_manager.h"
#include "ui/views/widget/widget.h"

namespace host {

DEFINE_WEB_CONTENTS_USER_DATA_KEY(ApplicationContentsViewFocusHelper);

// static
void ApplicationContentsViewFocusHelper::CreateForApplicationContents(
    ApplicationContents* app_contents) {
  if (!ApplicationContentsViewFocusHelper::FromApplicationContents(app_contents)) {
    app_contents->SetUserData(
        ApplicationContentsViewFocusHelper::UserDataKey(),
        base::WrapUnique(new ApplicationContentsViewFocusHelper(app_contents)));
  }
}

ApplicationContentsViewFocusHelper::ApplicationContentsViewFocusHelper(
    ApplicationContents* app_contents)
    : application_contents_(app_contents) {}

bool ApplicationContentsViewFocusHelper::Focus() {
//  const web_modal::WebContentsModalDialogManager* manager =
//      web_modal::WebContentsModalDialogManager::FromWebContents(web_contents_);
//  if (manager && manager->IsDialogActive())
//    manager->FocusTopmostDialog();
  return false;
}

bool ApplicationContentsViewFocusHelper::TakeFocus(bool reverse) {
  views::FocusManager* focus_manager = GetFocusManager();
  if (focus_manager) {
    focus_manager->AdvanceFocus(reverse);
    return true;
  }
  return false;
}

void ApplicationContentsViewFocusHelper::StoreFocus() {
  last_focused_view_tracker_.Clear();
  if (GetFocusManager())
    last_focused_view_tracker_.SetView(GetFocusManager()->GetFocusedView());
}

bool ApplicationContentsViewFocusHelper::RestoreFocus() {
  views::View* view_to_focus = GetStoredFocus();
  last_focused_view_tracker_.Clear();
  if (view_to_focus) {
    view_to_focus->RequestFocus();
    return true;
  }
  return false;
}

void ApplicationContentsViewFocusHelper::ResetStoredFocus() {
  last_focused_view_tracker_.Clear();
}

views::View* ApplicationContentsViewFocusHelper::GetStoredFocus() {
  views::View* last_focused_view = last_focused_view_tracker_.view();
  if (last_focused_view && last_focused_view->IsFocusable() &&
      GetFocusManager()->ContainsView(last_focused_view)) {
    return last_focused_view;
  }
  return nullptr;
}

gfx::NativeView ApplicationContentsViewFocusHelper::GetActiveNativeView() {
  return application_contents_->GetFullscreenApplicationWindowHostView() ?
      application_contents_->GetFullscreenApplicationWindowHostView()->GetNativeView() :
      application_contents_->GetNativeView();
}

views::Widget* ApplicationContentsViewFocusHelper::GetTopLevelWidget() {
  return views::Widget::GetTopLevelWidgetForNativeView(GetActiveNativeView());
}

views::FocusManager* ApplicationContentsViewFocusHelper::GetFocusManager() {
  views::Widget* toplevel_widget = GetTopLevelWidget();
  return toplevel_widget ? toplevel_widget->GetFocusManager() : NULL;
}

}
