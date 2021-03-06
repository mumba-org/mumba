// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_RENDERER_HOST_INPUT_TOUCH_SELECTION_CONTROLLER_CLIENT_MANAGER_H_
#define CONTENT_BROWSER_RENDERER_HOST_INPUT_TOUCH_SELECTION_CONTROLLER_CLIENT_MANAGER_H_

#include "core/shared/common/content_export.h"

namespace gfx {
class SelectionBound;
}

namespace ui {
class TouchSelectionController;
class TouchSelectionControllerClient;
class TouchSelectionMenuClient;
}  // namespace ui

namespace host {

// This class defines an interface for a manager class that allows multiple
// TouchSelectionControllerClients to work together with a single
// TouchSelectionController.
class CONTENT_EXPORT TouchSelectionControllerClientManager {
 public:
  virtual ~TouchSelectionControllerClientManager() {}

  virtual void DidStopFlinging() = 0;

  // The manager uses this class' methods to notify observers about important
  // events.
  class CONTENT_EXPORT Observer {
   public:
    virtual ~Observer() {}

    // Warns observers the manager is shutting down. The manager's view may not
    // be rigidly defined with respect to the lifetime of the client's views.
    virtual void OnManagerWillDestroy(
        TouchSelectionControllerClientManager* manager) = 0;
  };

  // Clients call this method when their selection bounds change, so that the
  // manager can determine which client should be considered the active client,
  // i.e. receive the selection handles and (possibly) a quickmenu.
  virtual void UpdateClientSelectionBounds(
      const gfx::SelectionBound& start,
      const gfx::SelectionBound& end,
      ui::TouchSelectionControllerClient* client,
      ui::TouchSelectionMenuClient* menu_client) = 0;

  // Used by clients to inform the manager that the client no longer wants to
  // participate in touch selection editing, usually because the client's view
  // is being destroyed or detached.
  virtual void InvalidateClient(ui::TouchSelectionControllerClient* client) = 0;

  // Provides direct access to the TouchSelectionController that will be used
  // with all clients accessing this manager. May return null values on Android.
  virtual ui::TouchSelectionController* GetTouchSelectionController() = 0;

  // The following two functions allow clients (or their owners, etc.) to
  // monitor the manager's lifetime.
  virtual void AddObserver(Observer* observer) = 0;
  virtual void RemoveObserver(Observer* observer) = 0;
};

}  // namespace host

#endif  // CONTENT_BROWSER_RENDERER_HOST_INPUT_TOUCH_SELECTION_CONTROLLER_CLIENT_MANAGER_H_
