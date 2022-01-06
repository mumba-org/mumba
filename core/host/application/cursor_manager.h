// Copyright (c) 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_CURSOR_MANAGER_H_
#define MUMBA_HOST_APPLICATION_CURSOR_MANAGER_H_

#include <map>

#include "core/shared/common/content_export.h"
#include "core/shared/common/cursors/webcursor.h"

namespace host {

class ApplicationWindowHostView;

// CursorManager coordinates mouse cursors for multiple ApplicationWindowHostViews
// on a single page. It is owned by the top-level ApplicationWindowHostView and
// calls back to its DisplayCursor method when the cursor needs to change,
// either because the mouse moved over a different view or because a cursor
// update was received for the current view.
class CONTENT_EXPORT CursorManager {
 public:
  class TooltipObserver {
   public:
    virtual ~TooltipObserver() {}

    virtual void OnSetTooltipTextForView(
        const ApplicationWindowHostView* view,
        const base::string16& tooltip_text) = 0;
  };

  CursorManager(ApplicationWindowHostView* root);
  ~CursorManager();

  // Called for any ApplicationWindowHostView that received an UpdateCursor message
  // from its renderer process.
  void UpdateCursor(ApplicationWindowHostView*, const common::WebCursor&);

  // Called when the mouse moves over a different ApplicationWindowHostView.
  void UpdateViewUnderCursor(ApplicationWindowHostView*);

  // Accepts TooltipText updates from views, but only updates what's displayed
  // if the requesting view is currently under the mouse cursor.
  void SetTooltipTextForView(const ApplicationWindowHostView* view,
                             const base::string16& tooltip_text);

  // Notification of a ApplicationWindowHostView being destroyed, so that its
  // cursor map entry can be removed if it has one. If it is the current
  // view_under_cursor_, then the root_view_'s cursor will be displayed.
  void ViewBeingDestroyed(ApplicationWindowHostView*);

  // Accessor for browser tests, enabling verification of the cursor_map_.
  // Returns false if the provided View is not in the map, and outputs
  // the cursor otherwise.
  bool GetCursorForTesting(ApplicationWindowHostView*, common::WebCursor&);

  void SetTooltipObserverForTesting(TooltipObserver* observer);

 private:
  // Stores the last received cursor from each ApplicationWindowHostView.
  std::map<ApplicationWindowHostView*, common::WebCursor> cursor_map_;

  // The view currently underneath the cursor, which corresponds to the cursor
  // currently displayed.
  ApplicationWindowHostView* view_under_cursor_;

  // The root view is the target for DisplayCursor calls whenever the active
  // cursor needs to change.
  ApplicationWindowHostView* root_view_;

  TooltipObserver* tooltip_observer_for_testing_;
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_CURSOR_MANAGER_H_
