// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_APPLICATION_CONTENTS_VIEW_DELEGATE_VIEWS_H_
#define MUMBA_HOST_APPLICATION_APPLICATION_CONTENTS_VIEW_DELEGATE_VIEWS_H_

#include <memory>

#include "base/compiler_specific.h"
#include "base/macros.h"
//#include "components/renderer_context_menu/context_menu_delegate.h"
#include "core/host/application/application_contents_view_delegate.h"

namespace host {
class ApplicationContents;
class ApplicationDragDestDelegate;
class ApplicationWindowHost;
class ApplicationContentsViewFocusHelper;

// A chrome specific class that extends WebContentsViewWin with features like
// focus management, which live in chrome.
class ApplicationContentsViewDelegateViews
    : public ApplicationContentsViewDelegate { //,
      //public ContextMenuDelegate {
 public:
  explicit ApplicationContentsViewDelegateViews(
      ApplicationContents* app_contents);
  ~ApplicationContentsViewDelegateViews() override;

  // Overridden from WebContentsViewDelegate:
  gfx::NativeWindow GetNativeWindow() override;
  //ApplicationDragDestDelegate* GetDragDestDelegate() override;
  void StoreFocus() override;
  bool RestoreFocus() override;
  void ResetStoredFocus() override;
  bool Focus() override;
  bool TakeFocus(bool reverse) override;
  void ShowContextMenu(ApplicationWindowHost* app_window_host,
                       const common::ContextMenuParams& params) override;

  // Overridden from ContextMenuDelegate.
  //std::unique_ptr<RenderViewContextMenuBase> BuildMenu(
  //    content::WebContents* web_contents,
  //    const content::ContextMenuParams& params) override;
  //void ShowMenu(std::unique_ptr<RenderViewContextMenuBase> menu) override;

 private:
  // The context menu is reset every time we show it, but we keep a pointer to
  // between uses so that it won't go out of scope before we're done with it.
  //std::unique_ptr<RenderViewContextMenuBase> context_menu_;

  // The chrome specific delegate that receives events from WebDragDest.
  //std::unique_ptr<ApplicationDragDestDelegate> bookmark_handler_;

  ApplicationContents* application_contents_;

  ApplicationContentsViewFocusHelper* GetFocusHelper() const;

  DISALLOW_COPY_AND_ASSIGN(ApplicationContentsViewDelegateViews);
};

} // namespace host

#endif  // CHROME_BROWSER_UI_VIEWS_TAB_CONTENTS_CHROME_WEB_CONTENTS_VIEW_DELEGATE_VIEWS_H_
