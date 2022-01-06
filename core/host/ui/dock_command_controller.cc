// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/dock_command_controller.h"

#include <stddef.h>

#include <string>

#include "base/command_line.h"
#include "base/debug/debugging_buildflags.h"
#include "base/debug/profiler.h"
#include "base/macros.h"
#include "base/metrics/user_metrics.h"
#include "build/build_config.h"
#include "mumba/app/mumba_command_ids.h"
#include "core/host/host.h"
#include "core/host/notification_types.h"
//#include "chrome/dock/defaults.h"
//#include "chrome/dock/extensions/extension_service.h"
//#include "chrome/dock/extensions/extension_util.h"
//#include "chrome/dock/lifetime/application_lifetime.h"
//#include "chrome/dock/prefs/incognito_mode_prefs.h"
//#include "chrome/dock/profiles/profile.h"
//#include "chrome/dock/profiles/profile_manager.h"
//#include "chrome/dock/sessions/tab_restore_service_factory.h"
#include "core/host/shell_integration.h"
//#include "chrome/dock/signin/signin_promo.h"
//#include "chrome/dock/sync/profile_sync_service_factory.h"
//#include "core/host/ui/apps/app_info_dialog.h"
//#include "core/host/ui/bookmarks/bookmark_tab_helper.h"
#include "core/host/ui/dock.h"
#include "core/host/ui/dock_commands.h"
#include "core/host/ui/dock_window.h"
//#include "core/host/ui/chrome_pages.h"
//#include "core/host/ui/extensions/application_launch.h"
//#include "core/host/ui/extensions/hosted_app_dock_controller.h"
//#include "core/host/ui/page_info/page_info_dialog.h"
#include "core/host/ui/tablist/tablist_model.h"
//#include "core/host/ui/webui/inspect_ui.h"
//#include "core/common/content_restriction.h"
//#include "core/common/pref_names.h"
//#include "core/common/profiling.h"
//#include "components/bookmarks/common/bookmark_pref_names.h"
//#include "components/dock_sync/profile_sync_service.h"
//#include "components/dom_distiller/core/dom_distiller_switches.h"
//#include "components/feature_engagement/buildflags.h"
//#include "components/prefs/pref_service.h"
//#include "components/sessions/core/tab_restore_service.h"
//#include "components/signin/core/dock/signin_pref_names.h"
#include "core/host/application/native_web_keyboard_event.h"
//#include "content/public/dock/navigation_controller.h"
//#include "content/public/dock/navigation_entry.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/application_contents.h"
#include "core/host/application/application_contents_observer.h"
#include "core/shared/common/service_manager_connection.h"
//#include "core/common/url_constants.h"
//#include "extensions/dock/extension_system.h"
//#include "printing/buildflags/buildflags.h"
#include "ui/events/keycodes/keyboard_codes.h"

#if defined(OS_MACOSX)
#include "core/host/ui/dock_commands_mac.h"
#endif

#if defined(OS_WIN)
#include "base/win/windows_version.h"
#include "core/host/gpu_data_manager.h"
#endif

#if defined(OS_CHROMEOS)
#include "ash/public/cpp/window_pin_type.h"
#include "core/host/ui/ash/multi_user/multi_user_context_menu.h"
#include "core/host/ui/dock_commands_chromeos.h"
#endif

#if defined(OS_LINUX) && !defined(OS_CHROMEOS)
#include "ui/base/ime/linux/text_edit_key_bindings_delegate_auralinux.h"
#endif

namespace host {

///////////////////////////////////////////////////////////////////////////////
// DockCommandController, public:

DockCommandController::DockCommandController(Dock* dock)
    : dock_(dock),
      command_updater_(nullptr) {
  dock_->tablist_model()->AddObserver(this);

  InitCommandState();
}

DockCommandController::~DockCommandController() {
  // TabRestoreService may have been shutdown by the time we get here. Don't
  // trigger creating it.
  dock_->tablist_model()->RemoveObserver(this);
}

bool DockCommandController::IsReservedCommandOrKey(
    int command_id,
    const NativeWebKeyboardEvent& event) {
  DLOG(INFO) << "DockCommandController::IsReservedCommandOrKey";
  // In Apps mode, no keys are reserved.
  //if (dock_->is_app())
  //  return false;

#if defined(OS_CHROMEOS)
  // On Chrome OS, the top row of keys are mapped to dock actions like
  // back/forward or refresh. We don't want web pages to be able to change the
  // behavior of these keys.  Ash handles F4 and up; this leaves us needing to
  // reserve dock back/forward and refresh here.
  ui::KeyboardCode key_code =
      static_cast<ui::KeyboardCode>(event.windows_key_code);
  if ((key_code == ui::VKEY_BROWSER_BACK && command_id == IDC_BACK) ||
      (key_code == ui::VKEY_BROWSER_FORWARD && command_id == IDC_FORWARD) ||
      (key_code == ui::VKEY_BROWSER_REFRESH && command_id == IDC_RELOAD)) {
    return true;
  }
#endif

  if (window()->IsFullscreen()) {
    // In fullscreen, all commands except for IDC_FULLSCREEN and IDC_EXIT should
    // be delivered to the web page. The intent to implement and ship can be
    // found in http://crbug.com/680809.
    const bool is_exit_fullscreen =
        (command_id == IDC_EXIT || command_id == IDC_FULLSCREEN);
#if defined(OS_MACOSX)
    // This behavior is different on Mac OS, which has a unique user-initiated
    // full-screen mode. According to the discussion in http://crbug.com/702251,
    // the commands should be reserved for dock-side handling if the dock
    // window's toolbar is visible.
    //if (window()->IsToolbarShowing()) {
    //  if (command_id == IDC_FULLSCREEN)
    //    return true;
    //} else {
    //  return is_exit_fullscreen;
    //}
#else
    return is_exit_fullscreen;
#endif
  }

#if defined(OS_LINUX) && !defined(OS_CHROMEOS)
  // If this key was registered by the user as a content editing hotkey, then
  // it is not reserved.
  ui::TextEditKeyBindingsDelegateAuraLinux* delegate =
      ui::GetTextEditKeyBindingsDelegate();
  if (delegate && event.os_event && delegate->MatchEvent(*event.os_event, NULL))
    return false;
#endif

  return command_id == IDC_CLOSE_TAB ||
         command_id == IDC_CLOSE_WINDOW ||
         command_id == IDC_NEW_INCOGNITO_WINDOW ||
         command_id == IDC_NEW_TAB ||
         command_id == IDC_NEW_WINDOW ||
         command_id == IDC_RESTORE_TAB ||
         command_id == IDC_SELECT_NEXT_TAB ||
         command_id == IDC_SELECT_PREVIOUS_TAB ||
         command_id == IDC_EXIT;
}

void DockCommandController::TabStateChanged() {
  UpdateCommandsForTabState();
}

void DockCommandController::ZoomStateChanged() {
  UpdateCommandsForZoomState();
}

//void DockCommandController::ContentRestrictionsChanged() {
//  UpdateCommandsForContentRestrictionState();
//}

void DockCommandController::FullscreenStateChanged() {
  UpdateCommandsForFullscreenMode();
}

#if defined(OS_CHROMEOS)
void DockCommandController::LockedFullscreenStateChanged() {
  UpdateCommandsForLockedFullscreenMode();
}
#endif

//void DockCommandController::PrintingStateChanged() {
//  UpdatePrintingState();
//}

void DockCommandController::LoadingStateChanged(bool is_loading,
                                                bool force) {
  UpdateReloadStopState(is_loading, force);
}

//void DockCommandController::ExtensionStateChanged() {
  // Extensions may disable the bookmark editing commands.
//  UpdateCommandsForBookmarkEditing();
//}

////////////////////////////////////////////////////////////////////////////////
// DockCommandController, CommandUpdater implementation:

bool DockCommandController::SupportsCommand(int id) const {
  return command_updater_.SupportsCommand(id);
}

bool DockCommandController::IsCommandEnabled(int id) const {
  return command_updater_.IsCommandEnabled(id);
}

bool DockCommandController::ExecuteCommand(int id) {
  return ExecuteCommandWithDisposition(id, WindowOpenDisposition::CURRENT_TAB);
}

bool DockCommandController::ExecuteCommandWithDisposition(
    int id, WindowOpenDisposition disposition) {
  DLOG(INFO) << "DockCommandController::ExecuteCommandWithDisposition";
  // Doesn't go through the command_updater_ to avoid dealing with having a
  // naming collision for ExecuteCommandWithDisposition (both
  // CommandUpdaterDelegate and CommandUpdater declare this function so we
  // choose to not implement CommandUpdaterDelegate inside this class and
  // therefore command_updater_ doesn't have the delegate set).
  if (!SupportsCommand(id) || !IsCommandEnabled(id))
    return false;

  // No commands are enabled if there is not yet any selected tab.
  // TODO(pkasting): It seems like we should not need this, because either
  // most/all commands should not have been enabled yet anyway or the ones that
  // are enabled should be global, or safe themselves against having no selected
  // tab.  However, Ben says he tried removing this before and got lots of
  // crashes, e.g. from Windows sending WM_COMMANDs at random times during
  // window construction.  This probably could use closer examination someday.
  if (dock_->tablist_model()->active_index() == TablistModel::kNoTab)
    return true;

  DCHECK(command_updater_.IsCommandEnabled(id)) << "Invalid/disabled command "
                                                << id;

  // The order of commands in this switch statement must match the function
  // declaration order in dock.h!
  switch (id) {
    // Navigation commands
    case IDC_BACK:
      //GoBack(dock_, disposition);
      DLOG(INFO) << "a BACK command which does not exist, was called";
      break;
    case IDC_FORWARD:
      //GoForward(dock_, disposition);
    DLOG(INFO) << "a FORWARD command which does not exist, was called";
      break;
    case IDC_RELOAD:
      //Reload(dock_, disposition);
      DLOG(INFO) << "a RELOAD command which does not exist, was called";
      break;
    case IDC_RELOAD_CLEARING_CACHE:
      DLOG(INFO) << "a CLEAR CACHE command which does not exist, was called";
      //ClearCache(dock_);
      FALLTHROUGH;
    case IDC_RELOAD_BYPASSING_CACHE:
      DLOG(INFO) << "a RELOAD_BYPASSING_CACHE command which does not exist, was called";
      //ReloadBypassingCache(dock_, disposition);
      break;
    case IDC_HOME:
      DLOG(INFO) << "a HOME command which does not exist, was called";
      //Home(dock_, disposition);
      break;
    case IDC_OPEN_CURRENT_URL:
      DLOG(INFO) << "a OPEN_CURRENT_URL command which does not exist, was called";
      //OpenCurrentURL(dock_);
      break;
    case IDC_STOP:
      DLOG(INFO) << "a STOP command which does not exist, was called";
      //Stop(dock_);
      break;

     // Window management commands
    case IDC_NEW_WINDOW:
      NewWindow(dock_);
      break;
    case IDC_NEW_INCOGNITO_WINDOW:
      DLOG(INFO) << "a NEW INCOGNITO WINDOW command which does not exist, was called";
      //NewIncognitoWindow(dock_);
      break;
    case IDC_CLOSE_WINDOW:
      base::RecordAction(base::UserMetricsAction("CloseWindowByKey"));
      CloseWindow(dock_);
      break;
    case IDC_NEW_TAB: {
      NewTab(dock_);
      break;
    }
    case IDC_CLOSE_TAB:
      base::RecordAction(base::UserMetricsAction("CloseTabByKey"));
      CloseTab(dock_);
      break;
    case IDC_SELECT_NEXT_TAB:
      base::RecordAction(base::UserMetricsAction("Accel_SelectNextTab"));
      SelectNextTab(dock_);
      break;
    case IDC_SELECT_PREVIOUS_TAB:
      base::RecordAction(base::UserMetricsAction("Accel_SelectPreviousTab"));
      SelectPreviousTab(dock_);
      break;
    case IDC_MOVE_TAB_NEXT:
      MoveTabNext(dock_);
      break;
    case IDC_MOVE_TAB_PREVIOUS:
      MoveTabPrevious(dock_);
      break;
    case IDC_SELECT_TAB_0:
    case IDC_SELECT_TAB_1:
    case IDC_SELECT_TAB_2:
    case IDC_SELECT_TAB_3:
    case IDC_SELECT_TAB_4:
    case IDC_SELECT_TAB_5:
    case IDC_SELECT_TAB_6:
    case IDC_SELECT_TAB_7:
      base::RecordAction(base::UserMetricsAction("Accel_SelectNumberedTab"));
      SelectNumberedTab(dock_, id - IDC_SELECT_TAB_0);
      break;
    case IDC_SELECT_LAST_TAB:
      base::RecordAction(base::UserMetricsAction("Accel_SelectNumberedTab"));
      SelectLastTab(dock_);
      break;
    case IDC_DUPLICATE_TAB:
      DuplicateTab(dock_);
      break;
    case IDC_RESTORE_TAB:
      RestoreTab(dock_);
      break;
    case IDC_SHOW_AS_TAB:
      ConvertPopupToTabbedDock(dock_);
      break;
    case IDC_FULLSCREEN:
      ToggleFullscreenMode(dock_);
      break;
    case IDC_OPEN_IN_PWA_WINDOW:
      //base::RecordAction(base::UserMetricsAction("OpenActiveTabInPwaWindow"));
      //ReparentSecureActiveTabIntoPwaWindow(dock_);
      DLOG(INFO) << "a OPEN_IN_PWA_WINDOW command which does not exist, was called";
      break;

#if defined(OS_LINUX) && !defined(OS_CHROMEOS)
    case IDC_MINIMIZE_WINDOW:
      dock_->window()->Minimize();
      break;
    case IDC_MAXIMIZE_WINDOW:
      dock_->window()->Maximize();
      break;
    case IDC_RESTORE_WINDOW:
      dock_->window()->Restore();
      break;
    case IDC_USE_SYSTEM_TITLE_BAR: {
      DLOG(INFO) << "a USE_SYSTEM_TITLE_BAR command which does not exist, was called";
//      PrefService* prefs = profile()->GetPrefs();
//      prefs->SetBoolean(prefs::kUseCustomChromeFrame,
//                        !prefs->GetBoolean(prefs::kUseCustomChromeFrame));
      break;
    }
#endif

#if defined(OS_MACOSX)
    case IDC_TOGGLE_FULLSCREEN_TOOLBAR:
      chrome::ToggleFullscreenToolbar(dock_);
      break;
    case IDC_TOGGLE_JAVASCRIPT_APPLE_EVENTS: {
      PrefService* prefs = profile()->GetPrefs();
      prefs->SetBoolean(prefs::kAllowJavascriptAppleEvents,
                        !prefs->GetBoolean(prefs::kAllowJavascriptAppleEvents));
      break;
    }
#endif
    case IDC_EXIT:
      Exit();
      break;

    // Page-related commands
    case IDC_SAVE_PAGE:
      //SavePage(dock_);
      break;
    case IDC_BOOKMARK_PAGE:
//      BookmarkCurrentPageAllowingExtensionOverrides(dock_);
      break;
    case IDC_BOOKMARK_ALL_TABS:
//      BookmarkAllTabs(dock_);
      break;
    case IDC_VIEW_SOURCE:
//      dock_->tablist_model()
//          ->GetActiveApplicationContents()
//          ->GetMainFrame()
//          ->ViewSource();
      break;
    case IDC_EMAIL_PAGE_LOCATION:
//      EmailPageLocation(dock_);
      break;
    case IDC_PRINT:
//      Print(dock_);
      break;
    case IDC_SAVE_CREDIT_CARD_FOR_PAGE:
//      SaveCreditCard(dock_);
      break;
    case IDC_TRANSLATE_PAGE:
//      Translate(dock_);
      break;
    case IDC_MANAGE_PASSWORDS_FOR_PAGE:
//      ManagePasswordsForPage(dock_);
      break;

    // Clipboard commands
    case IDC_CUT:
    case IDC_COPY:
    case IDC_PASTE:
      CutCopyPaste(dock_, id);
      break;

    // Find-in-page
    case IDC_FIND:
//      Find(dock_);
      break;
    case IDC_FIND_NEXT:
//      FindNext(dock_);
      break;
    case IDC_FIND_PREVIOUS:
//      FindPrevious(dock_);
      break;

    // Zoom
    case IDC_ZOOM_PLUS:
      //Zoom(dock_, PAGE_ZOOM_IN);
      break;
    case IDC_ZOOM_NORMAL:
      //Zoom(dock_, PAGE_ZOOM_RESET);
      break;
    case IDC_ZOOM_MINUS:
      //Zoom(dock_, PAGE_ZOOM_OUT);
      break;

    // Focus various bits of UI
    case IDC_FOCUS_TOOLBAR:
//      base::RecordAction(base::UserMetricsAction("Accel_Focus_Toolbar"));
//      FocusToolbar(dock_);
      break;
    case IDC_FOCUS_LOCATION:
//      base::RecordAction(base::UserMetricsAction("Accel_Focus_Location"));
//      FocusLocationBar(dock_);
      break;
    case IDC_FOCUS_SEARCH:
//      base::RecordAction(base::UserMetricsAction("Accel_Focus_Search"));
//      FocusSearch(dock_);
      break;
    case IDC_FOCUS_MENU_BAR:
//      FocusAppMenu(dock_);
      break;
    case IDC_FOCUS_BOOKMARKS:
//      base::RecordAction(base::UserMetricsAction("Accel_Focus_Bookmarks"));
//      FocusBookmarksToolbar(dock_);
      break;
    case IDC_FOCUS_INACTIVE_POPUP_FOR_ACCESSIBILITY:
//      FocusInactivePopupForAccessibility(dock_);
      break;
    case IDC_FOCUS_NEXT_PANE:
//      FocusNextPane(dock_);
      break;
    case IDC_FOCUS_PREVIOUS_PANE:
//      FocusPreviousPane(dock_);
      break;

    // Show various bits of UI
    case IDC_OPEN_FILE:
//      dock_->OpenFile();
      break;
    case IDC_CREATE_HOSTED_APP:
//      CreateBookmarkAppFromCurrentApplicationContents(dock_);
      break;
    case IDC_DEV_TOOLS:
      ToggleDevToolsWindow(dock_, DevToolsToggleAction::Show());
      break;
    case IDC_DEV_TOOLS_CONSOLE:
      ToggleDevToolsWindow(dock_, DevToolsToggleAction::ShowConsolePanel());
      break;
    case IDC_DEV_TOOLS_DEVICES:
//      InspectUI::InspectDevices(dock_);
      break;
    case IDC_DEV_TOOLS_INSPECT:
      ToggleDevToolsWindow(dock_, DevToolsToggleAction::Inspect());
      break;
    case IDC_DEV_TOOLS_TOGGLE:
      ToggleDevToolsWindow(dock_, DevToolsToggleAction::Toggle());
      break;
    case IDC_TASK_MANAGER:
//      OpenTaskManager(dock_);
      break;
    case IDC_SHOW_BOOKMARK_BAR:
//      ToggleBookmarkBar(dock_);
      break;
    case IDC_PROFILING_ENABLED:
//    Profiling::Toggle();
      break;
    case IDC_SHOW_BOOKMARK_MANAGER:
//    ShowBookmarkManager(dock_);
      break;
    case IDC_SHOW_APP_MENU:
//      base::RecordAction(base::UserMetricsAction("Accel_Show_App_Menu"));
//      ShowAppMenu(dock_);
      break;
    case IDC_SHOW_AVATAR_MENU:
//      ShowAvatarMenu(dock_);
      break;
    case IDC_SHOW_HISTORY:
//      ShowHistory(dock_);
      break;
    case IDC_SHOW_DOWNLOADS:
//      ShowDownloads(dock_);
      break;
    case IDC_MANAGE_EXTENSIONS:
//      ShowExtensions(dock_, std::string());
      break;
    case IDC_OPTIONS:
//      ShowSettings(dock_);
      break;
    case IDC_EDIT_SEARCH_ENGINES:
//      ShowSearchEngineSettings(dock_);
      break;
    case IDC_VIEW_PASSWORDS:
//      ShowPasswordManager(dock_);
      break;
    case IDC_CLEAR_BROWSING_DATA:
//      ShowClearBrowsingDataDialog(dock_);
      break;
    case IDC_IMPORT_SETTINGS:
//      ShowImportDialog(dock_);
      break;
    case IDC_TOGGLE_REQUEST_TABLET_SITE:
//      ToggleRequestTabletSite(dock_);
      break;
    case IDC_ABOUT:
//      ShowAboutChrome(dock_);
      break;
    case IDC_UPGRADE_DIALOG:
//      OpenUpdateChromeDialog(dock_);
      break;
    case IDC_VIEW_INCOMPATIBILITIES:
//      ShowConflicts(dock_);
      break;
    case IDC_HELP_PAGE_VIA_KEYBOARD:
      //ShowHelp(dock_, HELP_SOURCE_KEYBOARD);
      break;
    case IDC_HELP_PAGE_VIA_MENU:
      //ShowHelp(dock_, HELP_SOURCE_MENU);
      break;
    case IDC_SHOW_BETA_FORUM:
      //ShowBetaForum(dock_);
      break;
    case IDC_SHOW_SIGNIN:
      //ShowDockSigninOrSettings(
      //    dock_, signin_metrics::AccessPoint::ACCESS_POINT_MENU);
      break;
    case IDC_DISTILL_PAGE:
      //DistillCurrentPage(dock_);
      break;
    case IDC_ROUTE_MEDIA:
      //RouteMedia(dock_);
      break;
    case IDC_WINDOW_MUTE_SITE:
      //MuteSite(dock_);
      break;
    case IDC_WINDOW_PIN_TAB:
      PinTab(dock_);
      break;

    // Hosted App commands
    case IDC_COPY_URL:
      CopyURL(dock_);
      break;
    case IDC_OPEN_IN_CHROME:
      //OpenInChrome(dock_);
      break;
    case IDC_SITE_SETTINGS:
      //ShowSiteSettings(
          //dock_,
          //dock_->tablist_model()->GetActiveApplicationContents()->GetVisibleURL());
      break;
    case IDC_HOSTED_APP_MENU_APP_INFO:
      //ShowEntryInfoDialog(dock_->tablist_model()->GetActiveApplicationContents(),
      //                   bubble_anchor_util::kAppMenuButton);
      break;

    default:
      LOG(WARNING) << "Received Unimplemented Command: " << id;
      break;
  }

  return true;
}

void DockCommandController::AddCommandObserver(int id,
                                                  CommandObserver* observer) {
  command_updater_.AddCommandObserver(id, observer);
}

void DockCommandController::RemoveCommandObserver(
    int id, CommandObserver* observer) {
  command_updater_.RemoveCommandObserver(id, observer);
}

void DockCommandController::RemoveCommandObserver(
    CommandObserver* observer) {
  command_updater_.RemoveCommandObserver(observer);
}

bool DockCommandController::UpdateCommandEnabled(int id, bool state) {
  if (is_locked_fullscreen_)
    return false;

  return command_updater_.UpdateCommandEnabled(id, state);
}

////////////////////////////////////////////////////////////////////////////////
// DockCommandController, SigninPrefObserver implementation:

//void DockCommandController::OnSigninAllowedPrefChange() {
  // For unit tests, we don't have a window.
//  if (!window())
//    return;
//  UpdateShowSyncState(IsShowingMainUI());
//}

// DockCommandController, TablistModelObserver implementation:

void DockCommandController::TabInsertedAt(TablistModel* tablist_model,
                                             ApplicationContents* contents,
                                             int index,
                                             bool foreground) {
  AddInterstitialObservers(contents);
}

void DockCommandController::TabDetachedAt(ApplicationContents* contents, int index) {
  RemoveInterstitialObservers(contents);
}

void DockCommandController::TabReplacedAt(TablistModel* tablist_model,
                                             ApplicationContents* old_contents,
                                             ApplicationContents* new_contents,
                                             int index) {
  RemoveInterstitialObservers(old_contents);
  AddInterstitialObservers(new_contents);
}

void DockCommandController::TabBlockedStateChanged(
    ApplicationContents* contents,
    int index) {
  //PrintingStateChanged();
  FullscreenStateChanged();
  //UpdateCommandsForFind();
  //UpdateCommandsForMediaRouter();
}

void DockCommandController::TablistColorChanged(TablistModel* tablist_model, SkColor color, int tab_index) {
  
}

////////////////////////////////////////////////////////////////////////////////
// DockCommandController, private:

class DockCommandController::InterstitialObserver
    : public ApplicationContentsObserver {
 public:
  InterstitialObserver(DockCommandController* controller,
                       ApplicationContents* web_contents)
      : ApplicationContentsObserver(web_contents),
        controller_(controller) {
    
  }

  ~InterstitialObserver() override {
    
  }

  void DidAttachInterstitialPage() override {
    controller_->UpdateCommandsForTabState();
  }

  void DidDetachInterstitialPage() override {
    controller_->UpdateCommandsForTabState();
  }

 private:
  DockCommandController* controller_;

  DISALLOW_COPY_AND_ASSIGN(InterstitialObserver);
};

bool DockCommandController::IsShowingMainUI() {
  bool should_hide_ui = window() && window()->ShouldHideUIForFullscreen();
  return dock_->is_type_tabbed() && !should_hide_ui;
}

void DockCommandController::InitCommandState() {
  // All dock commands whose state isn't set automagically some other way
  // (like Back & Forward with initial page load) must have their state
  // initialized here, otherwise they will be forever disabled.

  if (is_locked_fullscreen_)
    return;

  // Navigation commands
  //command_updater_.UpdateCommandEnabled(IDC_RELOAD, true);
  //command_updater_.UpdateCommandEnabled(IDC_RELOAD_BYPASSING_CACHE, true);
  //command_updater_.UpdateCommandEnabled(IDC_RELOAD_CLEARING_CACHE, true);

  // Window management commands
  command_updater_.UpdateCommandEnabled(IDC_CLOSE_WINDOW, true);
  command_updater_.UpdateCommandEnabled(IDC_NEW_TAB, true);
  command_updater_.UpdateCommandEnabled(IDC_CLOSE_TAB, true);
  command_updater_.UpdateCommandEnabled(IDC_DUPLICATE_TAB, true);
  //UpdateTabRestoreCommandState();
  command_updater_.UpdateCommandEnabled(IDC_EXIT, true);
  //command_updater_.UpdateCommandEnabled(IDC_DEBUG_FRAME_TOGGLE, true);
//#if defined(OS_CHROMEOS)
//  command_updater_.UpdateCommandEnabled(IDC_MINIMIZE_WINDOW, true);
//  command_updater_.UpdateCommandEnabled(IDC_VISIT_DESKTOP_OF_LRU_USER_2, true);
//  command_updater_.UpdateCommandEnabled(IDC_VISIT_DESKTOP_OF_LRU_USER_3, true);
//#endif
#if defined(OS_LINUX) && !defined(OS_CHROMEOS)
  command_updater_.UpdateCommandEnabled(IDC_MINIMIZE_WINDOW, true);
  command_updater_.UpdateCommandEnabled(IDC_MAXIMIZE_WINDOW, true);
  command_updater_.UpdateCommandEnabled(IDC_RESTORE_WINDOW, true);
  command_updater_.UpdateCommandEnabled(IDC_USE_SYSTEM_TITLE_BAR, true);
#endif
  //command_updater_.UpdateCommandEnabled(IDC_OPEN_IN_PWA_WINDOW, true);

  // Page-related commands
  //command_updater_.UpdateCommandEnabled(IDC_EMAIL_PAGE_LOCATION, true);
  //command_updater_.UpdateCommandEnabled(IDC_MANAGE_PASSWORDS_FOR_PAGE, true);

  // Zoom
  command_updater_.UpdateCommandEnabled(IDC_ZOOM_MENU, true);
  command_updater_.UpdateCommandEnabled(IDC_ZOOM_PLUS, true);
  command_updater_.UpdateCommandEnabled(IDC_ZOOM_NORMAL, false);
  command_updater_.UpdateCommandEnabled(IDC_ZOOM_MINUS, true);

  // Show various bits of UI
  const bool normal_window = dock_->is_type_tabbed();
  //UpdateOpenFileState(&command_updater_);
  UpdateCommandsForDevTools();
  //command_updater_.UpdateCommandEnabled(IDC_TASK_MANAGER, CanOpenTaskManager());
  //command_updater_.UpdateCommandEnabled(IDC_SHOW_HISTORY, !guest_session);
  //command_updater_.UpdateCommandEnabled(IDC_SHOW_DOWNLOADS, true);
  //command_updater_.UpdateCommandEnabled(IDC_HELP_MENU, true);
  //command_updater_.UpdateCommandEnabled(IDC_HELP_PAGE_VIA_KEYBOARD, true);
//  command_updater_.UpdateCommandEnabled(IDC_HELP_PAGE_VIA_MENU, true);
//  command_updater_.UpdateCommandEnabled(IDC_SHOW_BETA_FORUM, true);
//  command_updater_.UpdateCommandEnabled(IDC_BOOKMARKS_MENU, !guest_session);
  //command_updater_.UpdateCommandEnabled(IDC_RECENT_TABS_MENU,
                                        //!guest_session &&
                                        //!profile()->IsOffTheRecord());
  //command_updater_.UpdateCommandEnabled(IDC_CLEAR_BROWSING_DATA,
                                        //!guest_session);
//#if defined(OS_CHROMEOS)
//  command_updater_.UpdateCommandEnabled(IDC_TAKE_SCREENSHOT, true);
//#else
  // Chrome OS uses the system tray menu to handle multi-profiles.
//  if (normal_window && (guest_session || !profile()->IsOffTheRecord())) {
//    command_updater_.UpdateCommandEnabled(IDC_SHOW_AVATAR_MENU, true);
//  }
//#endif

//  UpdateShowSyncState(true);

  // Navigation commands
  //command_updater_.UpdateCommandEnabled(
  //    IDC_HOME,
  //    normal_window);

  //const bool is_experimental_hosted_app =
  //    extensions::HostedAppDockController::IsForExperimentalHostedAppDock(
  //        dock_);
  // Hosted app dock commands.
  command_updater_.UpdateCommandEnabled(IDC_COPY_URL,
                                        false);
  //command_updater_.UpdateCommandEnabled(IDC_OPEN_IN_CHROME,
  //                                      is_experimental_hosted_app);
  //command_updater_.UpdateCommandEnabled(IDC_SITE_SETTINGS,
  //                                      is_experimental_hosted_app);
  //command_updater_.UpdateCommandEnabled(IDC_HOSTED_APP_MENU_APP_INFO,
  //                                      is_experimental_hosted_app);

  // Window management commands
  command_updater_.UpdateCommandEnabled(IDC_SELECT_NEXT_TAB, normal_window);
  command_updater_.UpdateCommandEnabled(IDC_SELECT_PREVIOUS_TAB,
                                        normal_window);
  command_updater_.UpdateCommandEnabled(IDC_MOVE_TAB_NEXT, normal_window);
  command_updater_.UpdateCommandEnabled(IDC_MOVE_TAB_PREVIOUS, normal_window);
  command_updater_.UpdateCommandEnabled(IDC_SELECT_TAB_0, normal_window);
  command_updater_.UpdateCommandEnabled(IDC_SELECT_TAB_1, normal_window);
  command_updater_.UpdateCommandEnabled(IDC_SELECT_TAB_2, normal_window);
  command_updater_.UpdateCommandEnabled(IDC_SELECT_TAB_3, normal_window);
  command_updater_.UpdateCommandEnabled(IDC_SELECT_TAB_4, normal_window);
  command_updater_.UpdateCommandEnabled(IDC_SELECT_TAB_5, normal_window);
  command_updater_.UpdateCommandEnabled(IDC_SELECT_TAB_6, normal_window);
  command_updater_.UpdateCommandEnabled(IDC_SELECT_TAB_7, normal_window);
  command_updater_.UpdateCommandEnabled(IDC_SELECT_LAST_TAB, normal_window);

  // These are always enabled; the menu determines their menu item visibility.
  //command_updater_.UpdateCommandEnabled(IDC_UPGRADE_DIALOG, true);
  //command_updater_.UpdateCommandEnabled(IDC_VIEW_INCOMPATIBILITIES, true);

  // Distill current page.
  //command_updater_.UpdateCommandEnabled(
      //IDC_DISTILL_PAGE, base::CommandLine::ForCurrentProcess()->HasSwitch(
                            //switches::kEnableDomDistiller));

  //command_updater_.UpdateCommandEnabled(IDC_WINDOW_MUTE_SITE, normal_window);
  command_updater_.UpdateCommandEnabled(IDC_WINDOW_PIN_TAB, normal_window);

  // Initialize other commands whose state changes based on various conditions.
  UpdateCommandsForFullscreenMode();
  //UpdateCommandsForContentRestrictionState();
  //UpdateCommandsForBookmarkEditing();
  //UpdateCommandsForIncognitoAvailability();
}

// static
//void DockCommandController::UpdateSharedCommandsForIncognitoAvailability(
    //CommandUpdater* command_updater,
    //scoped_refptr<Workspace> workspace) {
  //const bool guest_session = profile->IsGuestSession();
  // TODO(mlerman): Make GetAvailability account for profile->IsGuestSession().
  //IncognitoModePrefs::Availability incognito_availability =
      //IncognitoModePrefs::GetAvailability(profile->GetPrefs());
  //command_updater->UpdateCommandEnabled(
      //IDC_NEW_WINDOW,
  //    false)//incognito_availability != IncognitoModePrefs::FORCED);
  //command_updater->UpdateCommandEnabled(
      //IDC_NEW_INCOGNITO_WINDOW,
      //incognito_availability != IncognitoModePrefs::DISABLED && !guest_session);

  //const bool forced_incognito =
      //incognito_availability == IncognitoModePrefs::FORCED ||
      //guest_session;  // Guest always runs in Incognito mode.
  //command_updater->UpdateCommandEnabled(
      //IDC_SHOW_BOOKMARK_MANAGER,
      //dock_defaults::bookmarks_enabled && !forced_incognito);
  //ExtensionService* extension_service =
  //    extensions::ExtensionSystem::Get(profile)->extension_service();
  //const bool enable_extensions =
  //    extension_service && extension_service->extensions_enabled();
//
  // Bookmark manager and settings page/subpages are forced to open in normal
  // mode. For this reason we disable these commands when incognito is forced.
  //command_updater->UpdateCommandEnabled(IDC_MANAGE_EXTENSIONS,
  //                                      enable_extensions && !forced_incognito);

  //command_updater->UpdateCommandEnabled(IDC_IMPORT_SETTINGS, !forced_incognito);
  //command_updater->UpdateCommandEnabled(IDC_OPTIONS,
  //                                      !forced_incognito || guest_session);
  //command_updater->UpdateCommandEnabled(IDC_SHOW_SIGNIN, !forced_incognito);
//}

//void DockCommandController::UpdateCommandsForIncognitoAvailability() {
//  if (is_locked_fullscreen_)
//    return;
//
//  UpdateSharedCommandsForIncognitoAvailability(&command_updater_, profile());
//
//  if (!IsShowingMainUI()) {
//    command_updater_.UpdateCommandEnabled(IDC_IMPORT_SETTINGS, false);
//    command_updater_.UpdateCommandEnabled(IDC_OPTIONS, false);
//  }
//}

void DockCommandController::UpdateCommandsForTabState() {
  if (is_locked_fullscreen_)
    return;

  ApplicationContents* current_web_contents =
      dock_->tablist_model()->GetActiveApplicationContents();
  if (!current_web_contents)  // May be NULL during tab restore.
    return;

  // Navigation commands
  //command_updater_.UpdateCommandEnabled(IDC_BACK, CanGoBack(dock_));
  //command_updater_.UpdateCommandEnabled(IDC_FORWARD, CanGoForward(dock_));
  //command_updater_.UpdateCommandEnabled(IDC_RELOAD, CanReload(dock_));
  //command_updater_.UpdateCommandEnabled(IDC_RELOAD_BYPASSING_CACHE,
                                        //CanReload(dock_));
  //command_updater_.UpdateCommandEnabled(IDC_RELOAD_CLEARING_CACHE,
                                        //CanReload(dock_));

  // Window management commands
  command_updater_.UpdateCommandEnabled(IDC_DUPLICATE_TAB,
      CanDuplicateTab(dock_));
  //command_updater_.UpdateCommandEnabled(IDC_WINDOW_MUTE_SITE,
                                        //!dock_->is_app());
  command_updater_.UpdateCommandEnabled(IDC_WINDOW_PIN_TAB,
                                        true);

  // Page-related commands
  //window()->SetStarredState(
      //BookmarkTabHelper::FromApplicationContents(current_web_contents)->is_starred());
  window()->ZoomChangedForActiveTab(false);
  //command_updater_.UpdateCommandEnabled(IDC_VIEW_SOURCE,
                                        //CanViewSource(dock_));
  //command_updater_.UpdateCommandEnabled(IDC_EMAIL_PAGE_LOCATION,
                                        //CanEmailPageLocation(dock_));
  //if (dock_->is_devtools())
//    command_updater_.UpdateCommandEnabled(IDC_OPEN_FILE, false);

  //command_updater_.UpdateCommandEnabled(IDC_CREATE_HOSTED_APP,
  //                                      CanCreateBookmarkApp(dock_));

  //command_updater_.UpdateCommandEnabled(
      //IDC_TOGGLE_REQUEST_TABLET_SITE,
      //CanRequestTabletSite(current_web_contents));

  //UpdateCommandsForContentRestrictionState();
  //UpdateCommandsForBookmarkEditing();
  //UpdateCommandsForFind();
  //UpdateCommandsForMediaRouter();
  // Update the zoom commands when an active tab is selected.
  UpdateCommandsForZoomState();
}

void DockCommandController::UpdateCommandsForZoomState() {
  ApplicationContents* contents =
      dock_->tablist_model()->GetActiveApplicationContents();
  if (!contents)
    return;
  command_updater_.UpdateCommandEnabled(IDC_ZOOM_PLUS,
                                        CanZoomIn(contents));
  command_updater_.UpdateCommandEnabled(IDC_ZOOM_NORMAL,
                                        CanResetZoom(contents));
  command_updater_.UpdateCommandEnabled(IDC_ZOOM_MINUS,
                                        CanZoomOut(contents));
}

// void DockCommandController::UpdateCommandsForContentRestrictionState() {
//   int restrictions = GetContentRestrictions(dock_);

//   command_updater_.UpdateCommandEnabled(
//       IDC_COPY, !(restrictions & CONTENT_RESTRICTION_COPY));
//   command_updater_.UpdateCommandEnabled(
//       IDC_CUT, !(restrictions & CONTENT_RESTRICTION_CUT));
//   command_updater_.UpdateCommandEnabled(
//       IDC_PASTE, !(restrictions & CONTENT_RESTRICTION_PASTE));
//   UpdateSaveAsState();
//   UpdatePrintingState();
// }

void DockCommandController::UpdateCommandsForDevTools() {
  if (is_locked_fullscreen_)
    return;

  bool dev_tools_enabled = true;
      //!profile()->GetPrefs()->GetBoolean(prefs::kDevToolsDisabled);
  command_updater_.UpdateCommandEnabled(IDC_DEV_TOOLS,
                                        dev_tools_enabled);
  command_updater_.UpdateCommandEnabled(IDC_DEV_TOOLS_CONSOLE,
                                        dev_tools_enabled);
  command_updater_.UpdateCommandEnabled(IDC_DEV_TOOLS_DEVICES,
                                        dev_tools_enabled);
  command_updater_.UpdateCommandEnabled(IDC_DEV_TOOLS_INSPECT,
                                        dev_tools_enabled);
  command_updater_.UpdateCommandEnabled(IDC_DEV_TOOLS_TOGGLE,
                                        dev_tools_enabled);
#if defined(OS_MACOSX)
  command_updater_.UpdateCommandEnabled(IDC_TOGGLE_JAVASCRIPT_APPLE_EVENTS,
                                        dev_tools_enabled);
#endif
}

// void DockCommandController::UpdateCommandsForBookmarkEditing() {
//   if (is_locked_fullscreen_)
//     return;

//   command_updater_.UpdateCommandEnabled(IDC_BOOKMARK_PAGE,
//                                         CanBookmarkCurrentPage(dock_));
//   command_updater_.UpdateCommandEnabled(IDC_BOOKMARK_ALL_TABS,
//                                         CanBookmarkAllTabs(dock_));
// #if defined(OS_WIN)
//   command_updater_.UpdateCommandEnabled(IDC_PIN_TO_START_SCREEN, true);
// #endif
// }

// void DockCommandController::UpdateCommandsForBookmarkBar() {
//   if (is_locked_fullscreen_)
//     return;

//   command_updater_.UpdateCommandEnabled(
//       IDC_SHOW_BOOKMARK_BAR,
//       dock_defaults::bookmarks_enabled && !profile()->IsGuestSession() &&
//           !profile()->IsSystemProfile() &&
//           !profile()->GetPrefs()->IsManagedPreference(
//               bookmarks::prefs::kShowBookmarkBar) &&
//           IsShowingMainUI());
// }

// void DockCommandController::UpdateCommandsForFileSelectionDialogs() {
//   if (is_locked_fullscreen_)
//     return;

//   UpdateSaveAsState();
//   UpdateOpenFileState(&command_updater_);
// }

void DockCommandController::UpdateCommandsForFullscreenMode() {
  if (is_locked_fullscreen_)
    return;

  const bool is_fullscreen = window() && window()->IsFullscreen();
  const bool show_main_ui = IsShowingMainUI();
  //const bool main_not_fullscreen = show_main_ui && !is_fullscreen;

  // Navigation commands
  command_updater_.UpdateCommandEnabled(IDC_OPEN_CURRENT_URL, show_main_ui);

  // Window management commands
  command_updater_.UpdateCommandEnabled(
      IDC_SHOW_AS_TAB,
      !dock_->is_type_tabbed() && !is_fullscreen);

  // Focus various bits of UI
  //command_updater_.UpdateCommandEnabled(IDC_FOCUS_TOOLBAR, show_main_ui);
  //command_updater_.UpdateCommandEnabled(IDC_FOCUS_LOCATION, show_main_ui);
  //command_updater_.UpdateCommandEnabled(IDC_FOCUS_SEARCH, show_main_ui);
  //command_updater_.UpdateCommandEnabled(
      //IDC_FOCUS_MENU_BAR, main_not_fullscreen);
  //command_updater_.UpdateCommandEnabled(
      //IDC_FOCUS_NEXT_PANE, main_not_fullscreen);
  //command_updater_.UpdateCommandEnabled(
      //IDC_FOCUS_PREVIOUS_PANE, main_not_fullscreen);
  //command_updater_.UpdateCommandEnabled(
      //IDC_FOCUS_BOOKMARKS, main_not_fullscreen);
  //command_updater_.UpdateCommandEnabled(
      //IDC_FOCUS_INACTIVE_POPUP_FOR_ACCESSIBILITY, main_not_fullscreen);

  // Show various bits of UI
  //command_updater_.UpdateCommandEnabled(IDC_DEVELOPER_MENU, show_main_ui);
//#if defined(GOOGLE_CHROME_BUILD)
//  command_updater_.UpdateCommandEnabled(IDC_FEEDBACK, show_main_ui);
//#endif
//  UpdateShowSyncState(show_main_ui);

  //command_updater_.UpdateCommandEnabled(IDC_EDIT_SEARCH_ENGINES, show_main_ui);
  //command_updater_.UpdateCommandEnabled(IDC_VIEW_PASSWORDS, show_main_ui);
  //command_updater_.UpdateCommandEnabled(IDC_ABOUT, show_main_ui);
  //command_updater_.UpdateCommandEnabled(IDC_SHOW_APP_MENU, show_main_ui);

  //if (base::debug::IsProfilingSupported())
//    command_updater_.UpdateCommandEnabled(IDC_PROFILING_ENABLED, show_main_ui);

//#if !defined(OS_MACOSX)
  // Disable toggling into fullscreen mode if disallowed by pref.
//  const bool fullscreen_enabled = is_fullscreen ||
      //profile()->GetPrefs()->GetBoolean(prefs::kFullscreenAllowed);
//#else
  const bool fullscreen_enabled = true;
//#endif

  command_updater_.UpdateCommandEnabled(IDC_FULLSCREEN, fullscreen_enabled);
  command_updater_.UpdateCommandEnabled(IDC_TOGGLE_FULLSCREEN_TOOLBAR,
                                        fullscreen_enabled);

  //UpdateCommandsForBookmarkBar();
  //UpdateCommandsForIncognitoAvailability();
  //UpdateCommandsForHostedAppAvailability();
}

// void DockCommandController::UpdateCommandsForHostedAppAvailability() {
//   bool has_toolbar =
//       dock_->is_type_tabbed() ||
//       extensions::HostedAppDockController::IsForExperimentalHostedAppDock(
//           dock_);
//   if (window() && window()->ShouldHideUIForFullscreen())
//     has_toolbar = false;
//   command_updater_.UpdateCommandEnabled(IDC_FOCUS_TOOLBAR, has_toolbar);
//   command_updater_.UpdateCommandEnabled(IDC_FOCUS_NEXT_PANE, has_toolbar);
//   command_updater_.UpdateCommandEnabled(IDC_FOCUS_PREVIOUS_PANE, has_toolbar);
//   command_updater_.UpdateCommandEnabled(IDC_SHOW_APP_MENU, has_toolbar);
// }

#if defined(OS_CHROMEOS)
namespace {

#if DCHECK_IS_ON()
// Makes sure that all commands that are not whitelisted are disabled. DCHECKs
// otherwise. Compiled only in debug mode.
void NonWhitelistedCommandsAreDisabled(CommandUpdaterImpl* command_updater) {
  constexpr int kWhitelistedIds[] = {
    IDC_CUT, IDC_COPY, IDC_PASTE,
    IDC_FIND, IDC_FIND_NEXT, IDC_FIND_PREVIOUS,
    IDC_ZOOM_PLUS, IDC_ZOOM_NORMAL, IDC_ZOOM_MINUS,
  };

  // Go through all the command ids, skip the whitelisted ones.
  for (int id : command_updater->GetAllIds()) {
    if (std::find(std::begin(kWhitelistedIds), std::end(kWhitelistedIds), id)
            != std::end(kWhitelistedIds)) {
      continue;
    }
    DCHECK(!command_updater->IsCommandEnabled(id));
  }
}
#endif

}  // namespace

void DockCommandController::UpdateCommandsForLockedFullscreenMode() {
  bool is_locked_fullscreen = ash::IsWindowTrustedPinned(dock_->window());
  // Sanity check to make sure this function is called only on state change.
  DCHECK_NE(is_locked_fullscreen, is_locked_fullscreen_);
  if (is_locked_fullscreen == is_locked_fullscreen_)
    return;
  is_locked_fullscreen_ = is_locked_fullscreen;

  if (is_locked_fullscreen_) {
    command_updater_.DisableAllCommands();
    // Update the state of whitelisted commands:
    // IDC_CUT/IDC_COPY/IDC_PASTE,
    //UpdateCommandsForContentRestrictionState();
    // IDC_FIND/IDC_FIND_NEXT/IDC_FIND_PREVIOUS,
    //UpdateCommandsForFind();
    // IDC_ZOOM_PLUS/IDC_ZOOM_NORMAL/IDC_ZOOM_MINUS.
    UpdateCommandsForZoomState();
    // All other commands will be disabled (there is an early return in their
    // corresponding UpdateCommandsFor* functions).
//#if DCHECK_IS_ON()
    //NonWhitelistedCommandsAreDisabled(&command_updater_);
//#endif
  } else {
    // Do an init call to re-initialize command state after the
    // DisableAllCommands.
    InitCommandState();
  }
}
#endif

// void DockCommandController::UpdatePrintingState() {
//   if (is_locked_fullscreen_)
//     return;

//   bool print_enabled = CanPrint(dock_);
//   command_updater_.UpdateCommandEnabled(IDC_PRINT, print_enabled);
// #if BUILDFLAG(ENABLE_PRINTING)
//   command_updater_.UpdateCommandEnabled(IDC_BASIC_PRINT,
//                                         CanBasicPrint(dock_));
// #endif
// }

// void DockCommandController::UpdateSaveAsState() {
//   if (is_locked_fullscreen_)
//     return;

//   command_updater_.UpdateCommandEnabled(IDC_SAVE_PAGE, CanSavePage(dock_));
// }

// void DockCommandController::UpdateShowSyncState(bool show_main_ui) {
//   if (is_locked_fullscreen_)
//     return;

//   command_updater_.UpdateCommandEnabled(
//       IDC_SHOW_SYNC_SETUP, show_main_ui && pref_signin_allowed_.GetValue());
// }

// // static
// void DockCommandController::UpdateOpenFileState(
//     CommandUpdater* command_updater) {
//   bool enabled = true;
//   PrefService* local_state = g_dock_process->local_state();
//   if (local_state)
//     enabled = local_state->GetBoolean(prefs::kAllowFileSelectionDialogs);

//   command_updater->UpdateCommandEnabled(IDC_OPEN_FILE, enabled);
// }

 void DockCommandController::UpdateReloadStopState(bool is_loading,
                                                   bool force) {
   if (is_locked_fullscreen_)
     return;

   window()->UpdateReloadStopState(is_loading, force);
   //command_updater_.UpdateCommandEnabled(IDC_STOP, is_loading);
 }

// void DockCommandController::UpdateCommandsForFind() {
//   TablistModel* model = dock_->tablist_model();
//   bool enabled = !model->IsTabBlocked(model->active_index()) &&
//                  !dock_->is_devtools();

//   command_updater_.UpdateCommandEnabled(IDC_FIND, enabled);
//   command_updater_.UpdateCommandEnabled(IDC_FIND_NEXT, enabled);
//   command_updater_.UpdateCommandEnabled(IDC_FIND_PREVIOUS, enabled);
// }

// void DockCommandController::UpdateCommandsForMediaRouter() {
//   if (is_locked_fullscreen_)
//     return;

//   command_updater_.UpdateCommandEnabled(IDC_ROUTE_MEDIA,
//                                         CanRouteMedia(dock_));
// }

void DockCommandController::AddInterstitialObservers(ApplicationContents* contents) {
  interstitial_observers_.push_back(new InterstitialObserver(this, contents));
}

void DockCommandController::RemoveInterstitialObservers(
    ApplicationContents* contents) {
  for (size_t i = 0; i < interstitial_observers_.size(); i++) {
    if (interstitial_observers_[i]->application_contents() != contents)
      continue;

    delete interstitial_observers_[i];
    interstitial_observers_.erase(interstitial_observers_.begin() + i);
    return;
  }
}

DockWindow* DockCommandController::window() {
  return dock_->window();
}

scoped_refptr<Workspace> DockCommandController::workspace() {
  return dock_->workspace();
}

}  // namespace chrome
