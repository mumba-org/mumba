// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/tablist/dock_tablist_model_delegate.h"

#include <stddef.h>

#include "base/bind.h"
#include "base/command_line.h"
#include "base/message_loop/message_loop.h"
#include "core/host/workspace/workspace.h"
//#include "chrome/dock/sessions/tab_restore_service_factory.h"
//#include "chrome/dock/task_manager/app_contents_tags.h"
#include "core/host/ui/dock.h"
#include "core/host/ui/dock_commands.h"
#include "core/host/ui/dock_window.h"
#include "core/host/application/application_contents.h"
#include "core/host/application/application_contents_delegate.h"
#include "core/host/ui/tablist/dock_tablist.h"
#include "core/host/favicon/favicon_utils.h"
#include "core/host/ui/tablist/core_tab_helper.h"
//#include "core/host/ui/tab_dialogs.h"
#include "core/host/ui/tab_ui_helper.h"

//#include "core/host/ui/tablist/tab_helpers.h"
#include "core/host/ui/tablist/tablist_model.h"
//#include "core/host/ui/fast_unload_controller.h"
//#include "chrome/dock/ui/unload_controller.h"
#include "core/shared/common/switches.h"
//#include "components/sessions/content/content_live_tab.h"
//#include "components/sessions/core/tab_restore_service.h"
#include "ipc/ipc_message.h"

namespace host {

////////////////////////////////////////////////////////////////////////////////
// DockTablistModelDelegate, public:

DockTablistModelDelegate::DockTablistModelDelegate(Dock* dock)
    : dock_(dock),
      weak_factory_(this) {
}

DockTablistModelDelegate::~DockTablistModelDelegate() {
}

////////////////////////////////////////////////////////////////////////////////
// DockTablistModelDelegate, TablistModelDelegate implementation:

void DockTablistModelDelegate::AddTabAt(const GURL& url,
                                        Application* app,
                                        int index,
                                        bool foreground,
                                        TabStyle style) {
  host::AddTabAt(dock_, url, app, index, foreground, style);
}

Dock* DockTablistModelDelegate::CreateNewListWithContents(
    const std::vector<NewListContents>& contentses,
    const gfx::Rect& window_bounds,
    bool maximize) {
  //DCHECK(dock_->CanSupportWindowFeature(Dock::FEATURE_TABSTRIP));

  // Create an empty new dock window the same size as the old one.
  Dock::CreateParams params(dock_->workspace(), GURL(), true);
  params.initial_bounds = window_bounds;
  params.initial_show_state =
      maximize ? ui::SHOW_STATE_MAXIMIZED : ui::SHOW_STATE_NORMAL;
  Dock* dock = new Dock(params);
  TablistModel* new_model = dock->tablist_model();

  for (size_t i = 0; i < contentses.size(); ++i) {
    NewListContents item = contentses[i];

    // Enforce that there is an active tab in the strip at all times by forcing
    // the first web contents to be marked as active.
    if (i == 0)
      item.add_types |= TablistModel::ADD_ACTIVE;

    new_model->InsertApplicationContentsAt(
      static_cast<int>(i),
      base::WrapUnique(item.app_contents),
      item.add_types);
    // Make sure the loading state is updated correctly, otherwise the throbber
    // won't start if the page is loading.
    // TODO(beng): find a better way of doing this.
    static_cast<ApplicationContentsDelegate*>(dock)->
        LoadingStateChanged(item.app_contents, true);
  }

  return dock;
}

void DockTablistModelDelegate::WillAddApplicationContents(
    ApplicationContents* contents) {
  
  // extracted from TabHelpers::AttachTabHelpers(contents)
  // we just the things we care about
  Dock::AttachTabHelpers(contents);
  //TabDialogs::CreateForApplicationContents(contents);
  // Make the tab show up in the task manager.
  //task_manager::ApplicationContentsTags::CreateForTabContents(contents);
}

int DockTablistModelDelegate::GetDragActions() const {
  return TablistModelDelegate::TAB_TEAROFF_ACTION |
      (dock_->tablist_model()->count() > 1
          ? TablistModelDelegate::TAB_MOVE_ACTION : 0);
}

bool DockTablistModelDelegate::CanDuplicateContentsAt(int index) {
  return false;
  //return CanDuplicateTabAt(dock_, index);
}

void DockTablistModelDelegate::DuplicateContentsAt(int index) {
  DCHECK(false);
  //DuplicateTabAt(dock_, index);
}

// void DockTablistModelDelegate::CreateHistoricalTab(
//     ApplicationContents* contents) {
//   // We don't create historical tabs for incognito windows or windows without
//   // profiles.
//   if (!dock_->profile() || dock_->profile()->IsOffTheRecord())
//     return;

//   sessions::TabRestoreService* service =
//       TabRestoreServiceFactory::GetForProfile(dock_->profile());

//   // We only create historical tab entries for tabbed dock windows.
//   if (service && dock_->CanSupportWindowFeature(Dock::FEATURE_TABSTRIP)) {
//     service->CreateHistoricalTab(
//         sessions::ContentLiveTab::GetForApplicationContents(contents),
//         dock_->tablist_model()->GetIndexOfApplicationContents(contents));
//   }
// }

bool DockTablistModelDelegate::RunUnloadListenerBeforeClosing(
    ApplicationContents* contents) {
  //return dock_->RunUnloadListenerBeforeClosing(contents);
  return true;
}

bool DockTablistModelDelegate::ShouldRunUnloadListenerBeforeClosing(
    ApplicationContents* contents) {
  //return dock_->ShouldRunUnloadListenerBeforeClosing(contents);
  return false;
}

// bool DockTablistModelDelegate::CanBookmarkAllTabs() const {
//   return chrome::CanBookmarkAllTabs(dock_);
// }

// void DockTablistModelDelegate::BookmarkAllTabs() {
//   chrome::BookmarkAllTabs(dock_);
// }

 TablistModelDelegate::RestoreTabType
 DockTablistModelDelegate::GetRestoreTabType() {
   //return chrome::GetRestoreTabType(dock_);
  return RESTORE_NONE;
 }

 void DockTablistModelDelegate::RestoreTab() {
   //chrome::RestoreTab(dock_);
 }

////////////////////////////////////////////////////////////////////////////////
// DockTablistModelDelegate, private:

void DockTablistModelDelegate::CloseFrame() {
  dock_->window()->Close();
}

}  // namespace chrome
