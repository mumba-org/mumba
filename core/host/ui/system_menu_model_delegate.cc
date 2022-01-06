// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/system_menu_model_delegate.h"

#include "build/build_config.h"
#include "mumba/app/mumba_command_ids.h"
#include "core/host/ui/command_updater.h"
#include "core/host/ui/dock_commands.h"
#include "core/host/ui/dock_window.h"
#include "mumba/grit/generated_resources.h"
#include "ui/base/l10n/l10n_util.h"

namespace host {

SystemMenuModelDelegate::SystemMenuModelDelegate(
    ui::AcceleratorProvider* provider,
    Dock* dock)
    : provider_(provider),
      dock_(dock) {
}

SystemMenuModelDelegate::~SystemMenuModelDelegate() {}

bool SystemMenuModelDelegate::IsCommandIdChecked(int command_id) const {
#if defined(OS_LINUX) && !defined(OS_CHROMEOS)
  if (command_id == IDC_USE_SYSTEM_TITLE_BAR) {
    //PrefService* prefs = browser_->profile()->GetPrefs();
    return true;//!prefs->GetBoolean(prefs::kUseCustomChromeFrame);
  }
#endif
  return false;
}

bool SystemMenuModelDelegate::IsCommandIdEnabled(int command_id) const {
  //if (!host::IsCommandEnabled(browser_, command_id))
    return false;

  //if (command_id != IDC_RESTORE_TAB)
  //  return true;

  //sessions::TabRestoreService* trs =
  //    TabRestoreServiceFactory::GetForProfile(browser_->profile());

  // The Service is not available in Guest Profiles or Incognito mode.
  //if (!trs)
//    return false;

  // chrome::IsCommandEnabled(IDC_RESTORE_TAB) returns true if TabRestoreService
  // hasn't been loaded yet. Return false if this is the case as we don't have
  // a good way to dynamically update the menu when TabRestoreService finishes
  // loading.
  // TODO(sky): add a way to update menu.
  //if (!trs->IsLoaded()) {
//    trs->LoadTabsFromLastSession();
  //  return false;
  //}
  //return true;
}

bool SystemMenuModelDelegate::IsCommandIdVisible(int command_id) const {
#if defined(OS_LINUX) && !defined(OS_CHROMEOS)
  bool is_maximized = dock_->window()->IsMaximized();
  switch (command_id) {
    case IDC_MAXIMIZE_WINDOW:
      return !is_maximized;
    case IDC_RESTORE_WINDOW:
      return is_maximized;
  }
#endif
  return true;
}

bool SystemMenuModelDelegate::GetAcceleratorForCommandId(
    int command_id,
    ui::Accelerator* accelerator) const {
  return provider_->GetAcceleratorForCommandId(command_id, accelerator);
}

bool SystemMenuModelDelegate::IsItemForCommandIdDynamic(int command_id) const {
  return command_id == IDC_RESTORE_TAB;
}

base::string16 SystemMenuModelDelegate::GetLabelForCommandId(
    int command_id) const {
  DCHECK_EQ(command_id, IDC_RESTORE_TAB);

  int string_id = IDS_RESTORE_WINDOW;//IDS_RESTORE_TAB;
  // if (IsCommandIdEnabled(command_id)) {
  //   sessions::TabRestoreService* trs =
  //       TabRestoreServiceFactory::GetForProfile(browser_->profile());
  //   DCHECK(trs);
  //   trs->LoadTabsFromLastSession();
  //   if (!trs->entries().empty() &&
  //       trs->entries().front()->type == sessions::TabRestoreService::WINDOW)
  //     string_id = IDS_RESTORE_WINDOW;
  // }
  return l10n_util::GetStringUTF16(string_id);
}

void SystemMenuModelDelegate::ExecuteCommand(int command_id, int event_flags) {
  host::ExecuteCommand(dock_, command_id);
}

}