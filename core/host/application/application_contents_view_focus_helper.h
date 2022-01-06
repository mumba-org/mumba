// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_APPLICATION_CONTENTS_VIEW_FOCUS_HELPER_H_
#define MUMBA_HOST_APPLICATION_APPLICATION_CONTENTS_VIEW_FOCUS_HELPER_H_

#include "base/supports_user_data.h"
#include "core/host/application/application_contents_user_data.h"
#include "ui/gfx/native_widget_types.h"
#include "ui/views/view_tracker.h"

namespace views {
class FocusManager;
class Widget;
class View;
}

namespace host {
class ApplicationContents;
// A chrome specific helper class that handles focus management.
class ApplicationContentsViewFocusHelper
    : public ApplicationContentsUserData<ApplicationContentsViewFocusHelper> {
 public:
  // Creates a ChromeWebContentsViewFocusHelper for the given
  // WebContents. If a ChromeWebContentsViewFocusHelper is already
  // associated with the WebContents, this method is a no-op.
  static void CreateForApplicationContents(ApplicationContents* app_contents);

  void StoreFocus();
  bool RestoreFocus();
  void ResetStoredFocus();
  bool Focus();
  bool TakeFocus(bool reverse);
  // Returns the View that will be focused if RestoreFocus() is called.
  views::View* GetStoredFocus();

 private:
  explicit ApplicationContentsViewFocusHelper(ApplicationContents* app_contents);
  friend class ApplicationContentsUserData<ApplicationContentsViewFocusHelper>;
  gfx::NativeView GetActiveNativeView();
  views::Widget* GetTopLevelWidget();
  views::FocusManager* GetFocusManager();

  // Used to store the last focused view.
  views::ViewTracker last_focused_view_tracker_;

  ApplicationContents* application_contents_;

  DISALLOW_COPY_AND_ASSIGN(ApplicationContentsViewFocusHelper);
};

}

#endif  // CHROME_BROWSER_UI_VIEWS_TAB_CONTENTS_CHROME_WEB_CONTENTS_VIEW_FOCUS_HELPER_H_
