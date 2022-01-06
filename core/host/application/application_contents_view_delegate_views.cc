// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/application_contents_view_delegate_views.h"

#include <utility>

#include "core/host/application/application_contents.h"
#include "core/host/application/application_contents_view_focus_helper.h"
#include "ui/views/widget/widget.h"

namespace host {

ApplicationContentsViewDelegateViews::ApplicationContentsViewDelegateViews(
    ApplicationContents* application_contents)
    : application_contents_(application_contents) {
  ApplicationContentsViewFocusHelper::CreateForApplicationContents(application_contents);
}

ApplicationContentsViewDelegateViews::~ApplicationContentsViewDelegateViews() =
    default;

gfx::NativeWindow ApplicationContentsViewDelegateViews::GetNativeWindow() {
  //Browser* browser = chrome::FindBrowserWithApplicationContents(application_contents_);
  //return application_contents_->GetApplicationWindowHost()->GetView()->GetNativeView();
  return //application_contents_->GetFullscreenApplicationWindowHostView() ?
    //application_contents_->GetFullscreenApplicationWindowHostView()->GetNativeView() :
    application_contents_->GetNativeView();
}

//ApplicationDragDestDelegate*
//    ApplicationContentsViewDelegateViews::GetDragDestDelegate() {
  // We install a chrome specific handler to intercept bookmark drags for the
  // bookmark manager/extension API.
  //bookmark_handler_.reset(new WebDragBookmarkHandlerAura);
  //return bookmark_handler_.get();
//}

ApplicationContentsViewFocusHelper*
ApplicationContentsViewDelegateViews::GetFocusHelper() const {
  ApplicationContentsViewFocusHelper* helper =
      ApplicationContentsViewFocusHelper::FromApplicationContents(application_contents_);
  DCHECK(helper);
  return helper;
}

bool ApplicationContentsViewDelegateViews::Focus() {
  return GetFocusHelper()->Focus();
}

bool ApplicationContentsViewDelegateViews::TakeFocus(bool reverse) {
  return GetFocusHelper()->TakeFocus(reverse);
}

void ApplicationContentsViewDelegateViews::StoreFocus() {
  GetFocusHelper()->StoreFocus();
}

bool ApplicationContentsViewDelegateViews::RestoreFocus() {
  return GetFocusHelper()->RestoreFocus();
}

void ApplicationContentsViewDelegateViews::ResetStoredFocus() {
  GetFocusHelper()->ResetStoredFocus();
}

// std::unique_ptr<RenderViewContextMenuBase>
// ApplicationContentsViewDelegateViews::BuildMenu(
//     content::ApplicationContents* application_contents,
//     const content::ContextMenuParams& params) {
//   std::unique_ptr<RenderViewContextMenuBase> menu;
//   content::RenderFrameHost* focused_frame = application_contents->GetFocusedFrame();
//   // If the frame tree does not have a focused frame at this point, do not
//   // bother creating RenderViewContextMenuViews.
//   // This happens if the frame has navigated to a different page before
//   // ContextMenu message was received by the current RenderFrameHost.
//   if (focused_frame) {
//     menu.reset(RenderViewContextMenuViews::Create(focused_frame, params));
//     menu->Init();
//   }
//   return menu;
// }

// void ApplicationContentsViewDelegateViews::ShowMenu(
//     std::unique_ptr<RenderViewContextMenuBase> menu) {
//   context_menu_ = std::move(menu);
//   if (!context_menu_)
//     return;

//   context_menu_->Show();
// }

void ApplicationContentsViewDelegateViews::ShowContextMenu(
    ApplicationWindowHost* app_window_host,
    const common::ContextMenuParams& params) {
  //ShowMenu(
  //    BuildMenu(ApplicationContents::FromApplicationWindowHost(app_window_host),
  //              params));
}

ApplicationContentsViewDelegate* CreateApplicationContentsViewDelegate(
    ApplicationContents* application_contents) {
  return new ApplicationContentsViewDelegateViews(application_contents);
}

}
