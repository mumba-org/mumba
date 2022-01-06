// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/tablist/tab_menu_model.h"

#include "base/command_line.h"
#include "core/host/ui/tablist/tablist_model.h"
#include "core/host/ui/tablist/tablist_model_delegate.h"
#include "core/host/ui/tablist/tab_utils.h"
#include "mumba/grit/generated_resources.h"

namespace host {

TabMenuModel::TabMenuModel(ui::SimpleMenuModel::Delegate* delegate,
                           TablistModel* tablist,
                           int index)
    : ui::SimpleMenuModel(delegate) {
  Build(tablist, index);
}

void TabMenuModel::Build(TablistModel* tablist, int index) {
  bool affects_multiple_tabs =
      (tablist->IsTabSelected(index) &&
       tablist->selection_model().selected_indices().size() > 1);
  AddItemWithStringId(TablistModel::CommandNewTab, IDS_TAB_CXMENU_NEWTAB);
  AddSeparator(ui::NORMAL_SEPARATOR);
  AddItemWithStringId(TablistModel::CommandReload, IDS_TAB_CXMENU_RELOAD);
  AddItemWithStringId(TablistModel::CommandDuplicate,
                      IDS_TAB_CXMENU_DUPLICATE);
  bool will_pin = tablist->WillContextMenuPin(index);
  if (affects_multiple_tabs) {
    AddItemWithStringId(
        TablistModel::CommandTogglePinned,
        will_pin ? IDS_TAB_CXMENU_PIN_TABS : IDS_TAB_CXMENU_UNPIN_TABS);
  } else {
    AddItemWithStringId(
        TablistModel::CommandTogglePinned,
        will_pin ? IDS_TAB_CXMENU_PIN_TAB : IDS_TAB_CXMENU_UNPIN_TAB);
  }
  // if (base::FeatureList::IsEnabled(features::kSoundContentSetting)) {
  //   if (affects_multiple_tabs) {
  //     const bool will_mute = !chrome::AreAllSitesMuted(
  //         *tablist, tablist->selection_model().selected_indices());
  //     AddItemWithStringId(TablistModel::CommandToggleSiteMuted,
  //                         will_mute ? IDS_TAB_CXMENU_SOUND_MUTE_SITES
  //                                   : IDS_TAB_CXMENU_SOUND_UNMUTE_SITES);
  //   } else {
  //     const bool will_mute = !chrome::IsSiteMuted(*tablist, index);
  //     AddItemWithStringId(TablistModel::CommandToggleSiteMuted,
  //                         will_mute ? IDS_TAB_CXMENU_SOUND_MUTE_SITE
  //                                   : IDS_TAB_CXMENU_SOUND_UNMUTE_SITE);
  //   }
  // } else {
  //   if (affects_multiple_tabs) {
  //     const bool will_mute = !chrome::AreAllTabsMuted(
  //         *tablist, tablist->selection_model().selected_indices());
  //     AddItemWithStringId(TablistModel::CommandToggleTabAudioMuted,
  //                         will_mute ? IDS_TAB_CXMENU_AUDIO_MUTE_TABS
  //                                   : IDS_TAB_CXMENU_AUDIO_UNMUTE_TABS);
  //   } else {
  //     const bool will_mute =
  //         !tablist->GetWebContentsAt(index)->IsAudioMuted();
  //     AddItemWithStringId(TablistModel::CommandToggleTabAudioMuted,
  //                         will_mute ? IDS_TAB_CXMENU_AUDIO_MUTE_TAB
  //                                   : IDS_TAB_CXMENU_AUDIO_UNMUTE_TAB);
  //   }
  // }
  AddSeparator(ui::NORMAL_SEPARATOR);
  if (affects_multiple_tabs) {
    AddItemWithStringId(TablistModel::CommandCloseTab,
                        IDS_TAB_CXMENU_CLOSETABS);
  } else {
    AddItemWithStringId(TablistModel::CommandCloseTab,
                        IDS_TAB_CXMENU_CLOSETAB);
  }
  AddItemWithStringId(TablistModel::CommandCloseOtherTabs,
                      IDS_TAB_CXMENU_CLOSEOTHERTABS);
  AddItemWithStringId(TablistModel::CommandCloseTabsToRight,
                      IDS_TAB_CXMENU_CLOSETABSTORIGHT);
  AddSeparator(ui::NORMAL_SEPARATOR);
  const bool is_window = tablist->delegate()->GetRestoreTabType() ==
      TablistModelDelegate::RESTORE_WINDOW;
  AddItemWithStringId(TablistModel::CommandRestoreTab,
                      is_window ? IDS_RESTORE_WINDOW : IDS_RESTORE_TAB);
  AddItemWithStringId(TablistModel::CommandBookmarkAllTabs,
                      IDS_TAB_CXMENU_BOOKMARK_ALL_TABS);
}

}