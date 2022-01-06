// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/scoped_tabbed_dock_displayer.h"

#include "core/host/ui/dock.h"
#include "core/host/ui/dock_finder.h"
#include "core/host/ui/dock_window.h"
#include "core/host/workspace/workspace.h"

namespace host {

ScopedTabbedDockDisplayer::ScopedTabbedDockDisplayer(scoped_refptr<Workspace> workspace) {
  dock_ = FindTabbedDock(workspace, GURL(), false);
  if (!dock_)
    dock_ = new Dock(Dock::CreateParams(workspace, GURL(), true));
}

ScopedTabbedDockDisplayer::~ScopedTabbedDockDisplayer() {
  // Make sure to restore the window, since window()->Show() will not unminimize
  // it.
  if (dock_->window()->IsMinimized())
    dock_->window()->Restore();

  dock_->window()->Show();
}

}  // namespace chrome
