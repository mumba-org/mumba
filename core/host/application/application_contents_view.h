// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_APPLICATION_CONTENTS_VIEW_H_
#define MUMBA_HOST_APPLICATION_APPLICATION_CONTENTS_VIEW_H_

#include <string>

#include "base/strings/string16.h"
#include "build/build_config.h"
#include "core/shared/common/content_export.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/gfx/geometry/size.h"
#include "ui/gfx/native_widget_types.h"

namespace common {
struct DropData;  
}

namespace host {
class ApplicationWindowHost;
class ApplicationWindowHostView;
struct ScreenInfo;

// The ApplicationContentsView is an interface that is implemented by the platform-
// dependent web contents views. The ApplicationContents uses this interface to talk to
// them.
class ApplicationContentsView {
 public:
  virtual ~ApplicationContentsView() {}

  // Returns the native widget that contains the contents of the tab.
  virtual gfx::NativeView GetNativeView() const = 0;

  // Returns the native widget with the main content of the tab (i.e. the main
  // render view host, though there may be many popups in the tab as children of
  // the container).
  virtual gfx::NativeView GetContentNativeView() const = 0;

  // Returns the outermost native view. This will be used as the parent for
  // dialog boxes.
  virtual gfx::NativeWindow GetTopLevelNativeWindow() const = 0;

  // The following static method is implemented by each platform.
  static void GetDefaultScreenInfo(ScreenInfo* results);

  // Computes the rectangle for the native widget that contains the contents of
  // the tab in the screen coordinate system.
  virtual void GetContainerBounds(gfx::Rect* out) const = 0;

  // TODO(brettw) this is a hack. It's used in two places at the time of this
  // writing: (1) when render view hosts switch, we need to size the replaced
  // one to be correct, since it wouldn't have known about sizes that happened
  // while it was hidden; (2) in constrained windows.
  //
  // (1) will be fixed once interstitials are cleaned up. (2) seems like it
  // should be cleaned up or done some other way, since this works for normal
  // ApplicationContents without the special code.
  virtual void SizeContents(const gfx::Size& size) = 0;

  // Sets focus to the native widget for this tab.
  virtual void Focus() = 0;

  // Sets focus to the appropriate element when the ApplicationContents is shown the
  // first time.
  virtual void SetInitialFocus() = 0;

  // Stores the currently focused view.
  virtual void StoreFocus() = 0;

  // Restores focus to the last focus view. If StoreFocus has not yet been
  // invoked, SetInitialFocus is invoked.
  virtual void RestoreFocus() = 0;

  // Focuses the first (last if |reverse| is true) element in the page.
  // Invoked when this tab is getting the focus through tab traversal (|reverse|
  // is true when using Shift-Tab).
  virtual void FocusThroughWindowTraversal(bool reverse) = 0;

  // Returns the current drop data, if any.
  virtual common::DropData* GetDropData() const = 0;

  // Get the bounds of the View, relative to the parent.
  virtual gfx::Rect GetViewBounds() const = 0;

  virtual void CreateView(
      const gfx::Size& initial_size, gfx::NativeView context) = 0;

  // Sets up the View that holds the rendered web page, receives messages for
  // it and contains page plugins. The host view should be sized to the current
  // size of the ApplicationContents.
  //
  // |is_guest_view_hack| is temporary hack and will be removed once
  // ApplicationWindowHostViewGuest is not dependent on platform view.
  // TODO(lazyboy): Remove |is_guest_view_hack| once http://crbug.com/330264 is
  // fixed.
  virtual ApplicationWindowHostView* CreateViewForWindow(
      ApplicationWindowHost* app_window_host) = 0;

  // Creates a new View that holds a popup and receives messages for it.
  virtual ApplicationWindowHostView* CreateViewForPopupWindow(
      ApplicationWindowHost* app_window_host) = 0;

  // Sets the page title for the native widgets corresponding to the view. This
  // is not strictly necessary and isn't expected to be displayed anywhere, but
  // can aid certain debugging tools such as Spy++ on Windows where you are
  // trying to find a specific window.
  virtual void SetPageTitle(const base::string16& title) = 0;

  // Invoked when the ApplicationContents is notified that the ApplicationWindow has been
  // fully created.
  virtual void ApplicationWindowCreated(ApplicationWindowHost* host) = 0;

  // Invoked when the ApplicationContents is notified that the ApplicationWindow has been
  // swapped in.
  virtual void ApplicationWindowSwappedIn(ApplicationWindowHost* host) = 0;

  // Invoked to enable/disable overscroll gesture navigation.
  virtual void SetOverscrollControllerEnabled(bool enabled) = 0;

#if defined(OS_MACOSX)
  // Allowing other views disables optimizations which assume that only a single
  // ApplicationContents is present.
  virtual void SetAllowOtherViews(bool allow) = 0;

  // Returns true if other views are allowed, false otherwise.
  virtual bool GetAllowOtherViews() const = 0;

  // If we close the tab while a UI control is in an event-tracking
  // loop, the control may message freed objects and crash.
  // ApplicationContents::Close() calls IsEventTracking(), and if it returns
  // true CloseTabAfterEventTracking() is called and the close is not
  // completed.
  virtual bool IsEventTracking() const = 0;
  virtual void CloseTabAfterEventTracking() = 0;
#endif
};

}  // namespace host

#endif  // CONTENT_BROWSER_WEB_CONTENTS_WEB_CONTENTS_VIEW_H_
