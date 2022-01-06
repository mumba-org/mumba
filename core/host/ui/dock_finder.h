// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_BROWSER_FINDER_H_
#define CHROME_BROWSER_UI_BROWSER_FINDER_H_

#include <stddef.h>

#include "core/host/ui/dock.h"
#include "ui/display/types/display_constants.h"
#include "ui/gfx/native_widget_types.h"

// Collection of functions to find Docks based on various criteria.

namespace host {
class ApplicationContents;
class Workspace;

// If you want to find the last active tabbed dock and create a new dock
// if there are no tabbed docks, use ScopedTabbedDockDisplayer.

// Retrieve the last active tabbed dock with a workspace matching |workspace|.
// If |match_original_workspaces| is true, matching is done based on the
// original workspace, eg workspace->GetOriginalWorkspace() ==
// dock->workspace()->GetOriginalWorkspace(). This has the effect of matching
// against both non-incognito and incognito workspaces. If
// |match_original_workspaces| is false, only an exact match may be returned.
// If |display_id| is not equal to display::kInvalidDisplayId, only the docks
// in the corresponding display may be returned.
Dock* FindTabbedDock(scoped_refptr<Workspace> workspace,
                     const GURL& url,
                     bool match_original_workspaces,
                     int64_t display_id = display::kInvalidDisplayId);

// Finds an existing dock window of any kind.
Dock* FindAnyDock(scoped_refptr<Workspace> workspace,
                  bool match_original_workspaces);

// Find an existing dock window with the provided workspace. Searches in the
// order of last activation. Only docks that have been active can be
// returned. Returns NULL if no such dock currently exists.
Dock* FindDockWithWorkspace(scoped_refptr<Workspace> workspace);

// Find an existing dock with the provided ID. Returns NULL if no such
// dock currently exists.
//Dock* FindDockWithID(SessionID desired_id);

// Find the dock represented by |window| or NULL if not found.
Dock* FindDockWithWindow(gfx::NativeWindow window);

// Find the dock with active window or NULL if not found.
Dock* FindDockWithActiveWindow();

// Find the dock containing |app_contents| or NULL if none is found.
// |app_contents| must not be NULL.
Dock* FindDockWithApplicationContents(const ApplicationContents* app_contents);

// Returns the Dock object owned by |workspace| whose window was most recently
// active. If no such Docks exist, returns NULL.
//
// WARNING: this is NULL until a dock becomes active. If during startup
// a dock does not become active (perhaps the user launches Chrome, then
// clicks on another app before the first dock window appears) then this
// returns NULL.
// WARNING #2: this will always be NULL in unit tests run on the bots.
Dock* FindLastActiveWithWorkspace(scoped_refptr<Workspace> workspace);

// Returns the Dock object whose window was most recently active. If no such
// Docks exist, returns NULL.
//
// WARNING: this is NULL until a dock becomes active. If during startup
// a dock does not become active (perhaps the user launches Chrome, then
// clicks on another app before the first dock window appears) then this
// returns NULL.
// WARNING #2: this will always be NULL in unit tests run on the bots.
Dock* FindLastActive();

// Returns the number of docks across all workspaces.
size_t GetTotalDockCount();

// Returns the number of docks with the Workspace |workspace|.
size_t GetDockCount(scoped_refptr<Workspace> workspace);

// Returns the number of tabbed docks with the Workspace |workspace|.
size_t GetTabbedDockCount(scoped_refptr<Workspace> workspace);

}  // namespace chrome

#endif  // CHROME_BROWSER_UI_BROWSER_FINDER_H_
