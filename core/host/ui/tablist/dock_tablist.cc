// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/tablist/dock_tablist.h"

#include "base/command_line.h"
#include "core/host/workspace/workspace.h"
#include "core/host/ui/dock.h"
#include "core/host/ui/navigator_params.h"
//#include "core/host/ui/browser_navigator.h"
//#include "core/host/ui/browser_navigator_params.h"
#include "core/host/ui/tablist/core_tab_helper.h"
#include "core/host/ui/tablist/tablist_model.h"
#include "core/shared/common/switches.h"
//#include "core/common/url_constants.h"
//#include "core/host/navigation_entry.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/application_contents.h"

namespace host {

void AddTabAt(Dock* dock, const GURL& url, Application* app, int idx, bool foreground, TabStyle style) {
  // Time new tab page creation time.  We keep track of the timing data in
  // ApplicationContents, but we want to include the time it takes to create the
  // ApplicationContents object too.
  base::TimeTicks new_tab_start_time = base::TimeTicks::Now();
  NavigateParams params(dock,
                        url,
                        ui::PAGE_TRANSITION_TYPED);
  params.window_action = NavigateParams::SHOW_WINDOW;
  params.disposition = WindowOpenDisposition::NEW_FOREGROUND_TAB;//foreground ? WindowOpenDisposition::NEW_FOREGROUND_TAB
                       //           : WindowOpenDisposition::NEW_BACKGROUND_TAB;
  params.tablist_index = idx;
  params.application = app;
  params.tab_style = style;
  Navigate(&params);
  CoreTabHelper* core_tab_helper =
      CoreTabHelper::FromApplicationContents(params.target_contents);
  core_tab_helper->set_new_tab_start_time(new_tab_start_time);
}

ApplicationContents* AddSelectedTabWithURL(
    Dock* dock,
    const GURL& url,
    ui::PageTransition transition) {
  NavigateParams params(dock, url, transition);
  params.disposition = WindowOpenDisposition::NEW_FOREGROUND_TAB;
  Navigate(&params);
  return params.target_contents;
}

void AddApplicationContents(
  Dock* dock,
  ApplicationContents* source_contents,
  ApplicationContents* new_contents,
  WindowOpenDisposition disposition,
  const gfx::Rect& initial_rect,
  bool user_gesture) {

  // No code for this yet.
  DCHECK(disposition != WindowOpenDisposition::SAVE_TO_DISK);
  // Can't create a new contents for the current tab - invalid case.
  DCHECK(disposition != WindowOpenDisposition::CURRENT_TAB);

  NavigateParams params(dock, new_contents);
  params.source_contents = source_contents;
  params.disposition = disposition;
  params.window_bounds = initial_rect;
  params.window_action = NavigateParams::SHOW_WINDOW;
  params.application = new_contents->GetApplication();
  // At this point, we're already beyond the popup blocker. Even if the popup
  // was created without a user gesture, we have to set |user_gesture| to true,
  // so it gets correctly focused.
  params.user_gesture = true;
  Navigate(&params);
}

void CloseApplicationContents(Dock* dock,
                      ApplicationContents* contents,
                      bool add_to_history) {
  int index = dock->tablist_model()->GetIndexOfApplicationContents(contents);
  if (index == TablistModel::kNoTab) {
    NOTREACHED() << "CloseApplicationContents called for tab not in our strip";
    return;
  }

  dock->tablist_model()->CloseApplicationContentsAt(
      index,
      add_to_history ? TablistModel::CLOSE_CREATE_HISTORICAL_TAB
                     : TablistModel::CLOSE_NONE);
}

}  // namespace chrome
