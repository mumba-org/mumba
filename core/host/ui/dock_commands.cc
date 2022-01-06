// Copyright 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/dock_commands.h"

#include <vector>

#include "base/command_line.h"
#include "base/metrics/histogram_macros.h"
#include "base/metrics/user_metrics.h"
#include "base/strings/utf_string_conversions.h"
#include "build/build_config.h"
#include "mumba/app/mumba_command_ids.h"
#include "core/host/ui/dock.h"
// #include "chrome/dock/bookmarks/bookmark_model_factory.h"
 #include "core/host/host.h"
// #include "chrome/dock/browsing_data/browsing_data_helper.h"
// #include "chrome/dock/browsing_data/chrome_browsing_data_remover_delegate.h"
// #include "chrome/dock/devtools/devtools_window.h"
// #include "chrome/dock/dom_distiller/tab_utils.h"
// #include "chrome/dock/lifetime/application_lifetime.h"
 //#include "core/host/media/router/media_router_dialog_controller.h"  // nogncheck
 //#include "core/host/media/router/media_router_feature.h"
// #include "chrome/dock/platform_util.h"
// #include "chrome/dock/prefs/incognito_mode_prefs.h"
 #include "core/host/workspace/workspace.h"
// #include "chrome/dock/sessions/session_service_factory.h"
// #include "chrome/dock/sessions/tab_restore_service_factory.h"
// #include "chrome/dock/translate/chrome_translate_client.h"
// #include "chrome/dock/ui/accelerator_utils.h"
// #include "chrome/dock/ui/autofill/save_card_bubble_controller_impl.h"
// #include "chrome/dock/ui/bookmarks/bookmark_utils.h"
// #include "chrome/dock/ui/bookmarks/bookmark_utils_desktop.h"
 #include "core/host/ui/dock.h"
 #include "core/host/ui/dock_command_controller.h"
 #include "core/host/ui/devtools/devtools_window.h"
// #include "chrome/dock/ui/dock_dialogs.h"
// #include "chrome/dock/ui/dock_live_tab_context.h"
 #include "core/host/ui/navigator_params.h"
 #include "core/host/ui/tablist/dock_tablist.h"
 #include "core/host/ui/dock_window.h"
// #include "chrome/dock/ui/chrome_pages.h"
 #include "core/host/ui/exclusive_access/fullscreen_controller.h"
// #include "chrome/dock/ui/find_bar/find_bar.h"
// #include "chrome/dock/ui/find_bar/find_bar_controller.h"
// #include "chrome/dock/ui/find_bar/find_tab_helper.h"
// #include "chrome/dock/ui/location_bar/location_bar.h"
// #include "chrome/dock/ui/passwords/manage_passwords_ui_controller.h"
 #include "core/host/ui/scoped_tabbed_dock_displayer.h"
 #include "core/host/ui/status_bubble.h"
 #include "core/host/ui/tablist/core_tab_helper.h"
// #include "chrome/dock/ui/tab_dialogs.h"
 #include "core/host/ui/tablist/tablist_model.h"
// #include "chrome/dock/ui/translate/translate_bubble_view_state_transition.h"
// #include "chrome/dock/upgrade_detector.h"
// #include "chrome/common/buildflags.h"
// #include "chrome/common/chrome_features.h"
// #include "chrome/common/content_restriction.h"
// #include "chrome/common/pref_names.h"
// #include "components/bookmarks/dock/bookmark_model.h"
// #include "components/bookmarks/dock/bookmark_utils.h"
// #include "components/bookmarks/common/bookmark_pref_names.h"
#include "components/favicon/content/content_favicon_driver.h"
// #include "components/feature_engagement/buildflags.h"
// #include "components/google/core/dock/google_util.h"
// #include "components/prefs/pref_service.h"
// #include "components/sessions/core/live_tab_context.h"
// #include "components/sessions/core/tab_restore_service.h"
// #include "components/signin/core/dock/signin_header_helper.h"
// #include "components/translate/core/dock/language_state.h"
// #include "components/version_info/version_info.h"
// #include "components/web_modal/web_contents_modal_dialog_manager.h"
 #include "components/zoom/page_zoom.h"
 #include "components/zoom/zoom_controller.h"
// #include "content/public/dock/browsing_data_remover.h"
// #include "content/public/dock/devtools_agent_host.h"
// #include "content/public/dock/navigation_controller.h"
// #include "content/public/dock/navigation_entry.h"
// #include "content/public/dock/page_navigator.h"
 #include "core/host/application/application_window_host.h"
 #include "core/host/application/application_window_host_view.h"
 #include "core/host/application/application_contents.h"
// #include "core/shared/common/page_state.h"
// #include "core/shared/common/renderer_preferences.h"
// #include "core/shared/common/url_constants.h"
// #include "core/shared/common/url_utils.h"
// #include "core/shared/common/user_agent.h"
// #include "extensions/buildflags/buildflags.h"
 #include "net/base/escape.h"
// #include "printing/buildflags/buildflags.h"
// #include "rlz/buildflags/buildflags.h"
 #include "ui/base/clipboard/clipboard_types.h"
 #include "ui/base/clipboard/scoped_clipboard_writer.h"
 #include "ui/events/keycodes/keyboard_codes.h"
 #include "url/gurl.h"

// #if BUILDFLAG(ENABLE_EXTENSIONS)
// #include "chrome/dock/extensions/api/commands/command_service.h"
// #include "chrome/dock/extensions/api/extension_action/extension_action_api.h"
// #include "chrome/dock/extensions/tab_helper.h"
// #include "chrome/dock/ui/extensions/settings_api_bubble_helpers.h"
// #include "chrome/dock/web_applications/web_app.h"
// #include "chrome/common/extensions/extension_metrics.h"
// #include "chrome/common/extensions/manifest_handlers/app_launch_info.h"
// #include "extensions/dock/extension_registry.h"
// #include "extensions/dock/extension_system.h"
// #include "extensions/common/extension.h"
// #include "extensions/common/extension_set.h"
// #endif

// #if BUILDFLAG(ENABLE_PRINTING)
// #include "chrome/dock/printing/print_view_manager_common.h"
// #if BUILDFLAG(ENABLE_PRINT_PREVIEW)
// #include "chrome/dock/printing/print_preview_dialog_controller.h"
// #endif  // BUILDFLAG(ENABLE_PRINT_PREVIEW)
// #endif  // BUILDFLAG(ENABLE_PRINTING)

// #if BUILDFLAG(ENABLE_RLZ)
// #include "components/rlz/rlz_tracker.h"  // nogncheck
// #endif

// #if BUILDFLAG(ENABLE_DESKTOP_IN_PRODUCT_HELP)
// #include "chrome/dock/feature_engagement/incognito_window/incognito_window_tracker.h"
// #include "chrome/dock/feature_engagement/incognito_window/incognito_window_tracker_factory.h"
// #endif

// namespace {

// const char kOsOverrideForTabletSite[] = "Linux; Android 4.0.3";

// translate::TranslateBubbleUiEvent TranslateBubbleResultToUiEvent(
//     ShowTranslateBubbleResult result) {
//   switch (result) {
//     default:
//       NOTREACHED();
//       FALLTHROUGH;
//     case ShowTranslateBubbleResult::SUCCESS:
//       return translate::TranslateBubbleUiEvent::BUBBLE_SHOWN;
//     case ShowTranslateBubbleResult::BROWSER_WINDOW_NOT_VALID:
//       return translate::TranslateBubbleUiEvent::
//           BUBBLE_NOT_SHOWN_WINDOW_NOT_VALID;
//     case ShowTranslateBubbleResult::BROWSER_WINDOW_MINIMIZED:
//       return translate::TranslateBubbleUiEvent::
//           BUBBLE_NOT_SHOWN_WINDOW_MINIMIZED;
//     case ShowTranslateBubbleResult::BROWSER_WINDOW_NOT_ACTIVE:
//       return translate::TranslateBubbleUiEvent::
//           BUBBLE_NOT_SHOWN_WINDOW_NOT_ACTIVE;
//     case ShowTranslateBubbleResult::WEB_CONTENTS_NOT_ACTIVE:
//       return translate::TranslateBubbleUiEvent::
//           BUBBLE_NOT_SHOWN_WEB_CONTENTS_NOT_ACTIVE;
//     case ShowTranslateBubbleResult::EDITABLE_FIELD_IS_ACTIVE:
//       return translate::TranslateBubbleUiEvent::
//           BUBBLE_NOT_SHOWN_EDITABLE_FIELD_IS_ACTIVE;
//   }
// }

// }  // namespace

// using base::UserMetricsAction;
// using bookmarks::BookmarkModel;
// using content::NavigationController;
// using content::NavigationEntry;
// using content::OpenURLParams;
// using content::Referrer;
// using content::ApplicationContents;

namespace host {
// namespace {

// bool CanBookmarkCurrentPageInternal(const Dock* dock,
//                                     bool check_remove_bookmark_ui) {
//   BookmarkModel* model =
//       BookmarkModelFactory::GetForDockContext(dock->profile());
//   return dock_defaults::bookmarks_enabled &&
//       dock->profile()->GetPrefs()->GetBoolean(
//           bookmarks::prefs::kEditBookmarksEnabled) &&
//       model && model->loaded() && dock->is_type_tabbed() &&
//       (!check_remove_bookmark_ui ||
//            !chrome::ShouldRemoveBookmarkThisPageUI(dock->profile()));
// }

// #if BUILDFLAG(ENABLE_EXTENSIONS)
// bool GetBookmarkOverrideCommand(Profile* profile,
//                                 const extensions::Extension** extension,
//                                 extensions::Command* command) {
//   DCHECK(extension);
//   DCHECK(command);

//   ui::Accelerator bookmark_page_accelerator =
//       chrome::GetPrimaryChromeAcceleratorForBookmarkPage();
//   if (bookmark_page_accelerator.key_code() == ui::VKEY_UNKNOWN)
//     return false;

//   extensions::CommandService* command_service =
//       extensions::CommandService::Get(profile);
//   const extensions::ExtensionSet& extension_set =
//       extensions::ExtensionRegistry::Get(profile)->enabled_extensions();
//   for (extensions::ExtensionSet::const_iterator i = extension_set.begin();
//        i != extension_set.end();
//        ++i) {
//     extensions::Command prospective_command;
//     if (command_service->GetSuggestedExtensionCommand(
//             (*i)->id(), bookmark_page_accelerator, &prospective_command)) {
//       *extension = i->get();
//       *command = prospective_command;
//       return true;
//     }
//   }
//   return false;
// }
// #endif

// Based on |disposition|, creates a new tab as necessary, and returns the
// appropriate tab to navigate.  If that tab is the current tab, reverts the
// location bar contents, since all dock-UI-triggered navigations should
// revert any omnibox edits in the current tab.
ApplicationContents* GetTabAndRevertIfNecessary(
  Dock* dock,
  WindowOpenDisposition disposition) {
  
  ApplicationContents* current_tab = dock->tablist_model()->GetActiveApplicationContents();
  switch (disposition) {
    case WindowOpenDisposition::NEW_FOREGROUND_TAB:
    case WindowOpenDisposition::NEW_BACKGROUND_TAB: {
      std::unique_ptr<ApplicationContents> new_tab =
          base::WrapUnique(current_tab->Clone());
      ApplicationContents* raw_new_tab = new_tab.get();
      if (disposition == WindowOpenDisposition::NEW_BACKGROUND_TAB)
        new_tab->WasHidden();
      dock->tablist_model()->AddApplicationContents(
          std::move(new_tab), -1, ui::PAGE_TRANSITION_LINK,
          (disposition == WindowOpenDisposition::NEW_FOREGROUND_TAB)
              ? TablistModel::ADD_ACTIVE
              : TablistModel::ADD_NONE);
      return raw_new_tab;
    }
    case WindowOpenDisposition::NEW_WINDOW: {
      std::unique_ptr<ApplicationContents> new_tab =
          base::WrapUnique(current_tab->Clone());
      ApplicationContents* raw_new_tab = new_tab.get();
      Dock* new_dock = new Dock(Dock::CreateParams(dock->workspace(), GURL(), false));
      new_dock->tablist_model()->AddApplicationContents(std::move(new_tab), -1,
                                                     ui::PAGE_TRANSITION_LINK,
                                                     TablistModel::ADD_ACTIVE);
      new_dock->window()->Show();
      return raw_new_tab;
    }
    default:
      //dock->window()->GetLocationBar()->Revert();
      return current_tab;
  }
}

void ReloadInternal(Dock* dock,
                    WindowOpenDisposition disposition,
                    bool bypass_cache) {
  // As this is caused by a user action, give the focus to the page.
  //
  // Also notify RenderViewHostDelegate of the user gesture; this is
  // normally done in Dock::Navigate, but a reload bypasses Navigate.
  ApplicationContents* new_tab = GetTabAndRevertIfNecessary(dock, disposition);
  new_tab->NavigatedByUser();
  //if (!new_tab->FocusLocationBarByDefault())
  new_tab->Focus();

  DevToolsWindow* devtools =
      DevToolsWindow::GetInstanceForInspectedApplicationContents(new_tab);
  if (devtools && devtools->ReloadInspectedApplicationContents(bypass_cache))
    return;

  //new_tab->GetController().Reload(bypass_cache
  //                                    ? content::ReloadType::BYPASSING_CACHE
  //                                    : content::ReloadType::NORMAL,
  //                                true);
}

// bool IsShowingApplicationContentsModalDialog(Dock* dock) {
//   ApplicationContents* web_contents =
//       dock->tablist_model()->GetActiveApplicationContents();
//   if (!web_contents)
//     return false;

//   // TODO(gbillock): This is currently called in production by the CanPrint
//   // method, and may be too restrictive if we allow print preview to overlap.
//   // Re-assess how to queue print preview after we know more about popup
//   // management policy.
//   const web_modal::ApplicationContentsModalDialogManager* manager =
//       web_modal::ApplicationContentsModalDialogManager::FromApplicationContents(web_contents);
//   return manager && manager->IsDialogActive();
// }

// #if BUILDFLAG(ENABLE_BASIC_PRINT_DIALOG)
// bool PrintPreviewShowing(const Dock* dock) {
// #if BUILDFLAG(ENABLE_PRINT_PREVIEW)
//   ApplicationContents* contents = dock->tablist_model()->GetActiveApplicationContents();
//   printing::PrintPreviewDialogController* controller =
//       printing::PrintPreviewDialogController::GetInstance();
//   return controller && (controller->GetPrintPreviewForContents(contents) ||
//                         controller->is_creating_print_preview_dialog());
// #else
//   return false;
// #endif
// }
// #endif  // BUILDFLAG(ENABLE_BASIC_PRINT_DIALOG)

// }  // namespace

bool IsCommandEnabled(Dock* dock, int command) {
  return dock->command_controller()->IsCommandEnabled(command);
}

bool SupportsCommand(Dock* dock, int command) {
  return dock->command_controller()->SupportsCommand(command);
}

bool ExecuteCommand(Dock* dock, int command) {
  return dock->command_controller()->ExecuteCommand(command);
}

 bool ExecuteCommandWithDisposition(Dock* dock,
                                    int command,
                                    WindowOpenDisposition disposition) {
  return dock->command_controller()->ExecuteCommandWithDisposition(
       command, disposition);
 }

 void UpdateCommandEnabled(Dock* dock, int command, bool enabled) {
   dock->command_controller()->UpdateCommandEnabled(command, enabled);
 }

 void AddCommandObserver(Dock* dock,
                         int command,
                         CommandObserver* observer) {
   dock->command_controller()->AddCommandObserver(command, observer);
 }

 void RemoveCommandObserver(Dock* dock,
                            int command,
                            CommandObserver* observer) {
   dock->command_controller()->RemoveCommandObserver(command, observer);
 }

// int GetContentRestrictions(const Dock* dock) {
//   int content_restrictions = 0;
//   ApplicationContents* current_tab = dock->tablist_model()->GetActiveApplicationContents();
//   if (current_tab) {
//     CoreTabHelper* core_tab_helper =
//         CoreTabHelper::FromApplicationContents(current_tab);
//     content_restrictions = core_tab_helper->content_restrictions();
//     NavigationEntry* last_committed_entry =
//         current_tab->GetController().GetLastCommittedEntry();
//     if (!content::IsSavableURL(
//             last_committed_entry ? last_committed_entry->GetURL() : GURL()) ||
//         current_tab->ShowingInterstitialPage())
//       content_restrictions |= CONTENT_RESTRICTION_SAVE;
//     if (current_tab->ShowingInterstitialPage())
//       content_restrictions |= CONTENT_RESTRICTION_PRINT;
//   }
//   return content_restrictions;
// }

 void NewEmptyWindow(scoped_refptr<Workspace> workspace) {
//   bool incognito = profile->IsOffTheRecord();
//   PrefService* prefs = profile->GetPrefs();
//   if (incognito) {
//     if (IncognitoModePrefs::GetAvailability(prefs) ==
//           IncognitoModePrefs::DISABLED) {
//       incognito = false;
//     }
//   } else if (profile->IsGuestSession() ||
//              (dock_defaults::kAlwaysOpenIncognitoWindow &&
//               IncognitoModePrefs::ShouldLaunchIncognito(
//                   *base::CommandLine::ForCurrentProcess(), prefs))) {
//     incognito = true;
//   }

//   if (incognito) {
//     base::RecordAction(UserMetricsAction("NewIncognitoWindow"));
//     OpenEmptyWindow(profile->GetOffTheRecordProfile());
//   } else {
    // base::RecordAction(UserMetricsAction("NewWindow"));
//     SessionService* session_service =
//         SessionServiceFactory::GetForProfileForSessionRestore(
//             profile->GetOriginalProfile());
//     if (!session_service ||
 //        !session_service->RestoreIfNecessary(std::vector<GURL>())) {
       OpenEmptyWindow(workspace);
//     }
 //  }
 }

 Dock* OpenEmptyWindow(scoped_refptr<Workspace> workspace) {
   TabStyle style = TabStyle::kAPP;
   Dock* dock =
       new Dock(Dock::CreateParams(Dock::TYPE_TABBED, workspace, GURL(), true));
   AddTabAt(dock, GURL(), nullptr, -1, true, style);
   dock->window()->Show();
   return dock;
 }

// void OpenWindowWithRestoredTabs(Profile* profile) {
//   sessions::TabRestoreService* service =
//       TabRestoreServiceFactory::GetForProfile(profile);
//   if (service)
//     service->RestoreMostRecentEntry(nullptr);
// }

// void OpenURLOffTheRecord(Profile* profile,
//                          const GURL& url) {
//   ScopedTabbedDockDisplayer displayer(profile->GetOffTheRecordProfile());
//   AddSelectedTabWithURL(displayer.dock(), url,
//       ui::PAGE_TRANSITION_LINK);
// }

// bool CanGoBack(const Dock* dock) {
//   return dock->tablist_model()->GetActiveApplicationContents()->
//       GetController().CanGoBack();
// }

// void GoBack(Dock* dock, WindowOpenDisposition disposition) {
//   base::RecordAction(UserMetricsAction("Back"));

//   if (CanGoBack(dock)) {
//     ApplicationContents* current_tab =
//         dock->tablist_model()->GetActiveApplicationContents();
//     ApplicationContents* new_tab = GetTabAndRevertIfNecessary(dock, disposition);
//     // If we are on an interstitial page and clone the tab, it won't be copied
//     // to the new tab, so we don't need to go back.
//     if ((new_tab == current_tab) || !current_tab->ShowingInterstitialPage())
//       new_tab->GetController().GoBack();
//   }
// }

// bool CanGoForward(const Dock* dock) {
//   return dock->tablist_model()->GetActiveApplicationContents()->
//       GetController().CanGoForward();
// }

// void GoForward(Dock* dock, WindowOpenDisposition disposition) {
//   base::RecordAction(UserMetricsAction("Forward"));
//   if (CanGoForward(dock)) {
//     GetTabAndRevertIfNecessary(dock, disposition)->
//         GetController().GoForward();
//   }
// }

// bool NavigateToIndexWithDisposition(Dock* dock,
//                                     int index,
//                                     WindowOpenDisposition disposition) {
//   NavigationController* controller =
//       &GetTabAndRevertIfNecessary(dock, disposition)->GetController();
//   if (index < 0 || index >= controller->GetEntryCount())
//     return false;
//   controller->GoToIndex(index);
//   return true;
// }

// void Reload(Dock* dock, WindowOpenDisposition disposition) {
//   base::RecordAction(UserMetricsAction("Reload"));
//   ReloadInternal(dock, disposition, false);
// }

// void ReloadBypassingCache(Dock* dock, WindowOpenDisposition disposition) {
//   base::RecordAction(UserMetricsAction("ReloadBypassingCache"));
//   ReloadInternal(dock, disposition, true);
// }

// bool CanReload(const Dock* dock) {
//   return !dock->is_devtools();
// }

// void Home(Dock* dock, WindowOpenDisposition disposition) {
//   base::RecordAction(UserMetricsAction("Home"));

//   std::string extra_headers;
// #if BUILDFLAG(ENABLE_RLZ)
//   // If the home page is a Google home page, add the RLZ header to the request.
//   PrefService* pref_service = dock->profile()->GetPrefs();
//   if (pref_service) {
//     if (google_util::IsGoogleHomePageUrl(
//         GURL(pref_service->GetString(prefs::kHomePage)))) {
//       extra_headers = rlz::RLZTracker::GetAccessPointHttpHeader(
//           rlz::RLZTracker::ChromeHomePage());
//     }
//   }
// #endif  // BUILDFLAG(ENABLE_RLZ)

//   GURL url = dock->profile()->GetHomePage();

// #if BUILDFLAG(ENABLE_EXTENSIONS)
//   // With bookmark apps enabled, hosted apps should return to their launch page
//   // when the home button is pressed.
//   if (dock->is_app()) {
//     const extensions::Extension* extension =
//         extensions::ExtensionRegistry::Get(dock->profile())
//             ->GetExtensionById(
//                 web_app::GetExtensionIdFromApplicationName(dock->app_name()),
//                 extensions::ExtensionRegistry::EVERYTHING);
//     if (!extension)
//       return;

//     url = extensions::AppLaunchInfo::GetLaunchWebURL(extension);
//   }

//   if (disposition == WindowOpenDisposition::CURRENT_TAB ||
//       disposition == WindowOpenDisposition::NEW_FOREGROUND_TAB)
//     extensions::MaybeShowExtensionControlledHomeNotification(dock);
// #endif

//   OpenURLParams params(
//       url, Referrer(), disposition,
//       ui::PageTransitionFromInt(
//           ui::PAGE_TRANSITION_AUTO_BOOKMARK |
//           ui::PAGE_TRANSITION_HOME_PAGE),
//       false);
//   params.extra_headers = extra_headers;
//   dock->OpenURL(params);
// }

 void OpenCurrentURL(Dock* dock) {
//    base::RecordAction(UserMetricsAction("LoadURL"));
//    LocationBar* location_bar = dock->window()->GetLocationBar();
//    if (!location_bar)
//      return;

//    GURL url(location_bar->GetDestinationURL());

//    NavigateParams params(dock, url, location_bar->GetPageTransition());
//    params.disposition = location_bar->GetWindowOpenDisposition();
// //   // Use ADD_INHERIT_OPENER so that all pages opened by the omnibox at least
// //   // inherit the opener. In some cases the tabstrip will determine the group
// //   // should be inherited, in which case the group is inherited instead of the
// //   // opener.
//    params.tabstrip_add_types =
//        TablistModel::ADD_FORCE_INDEX | TablistModel::ADD_INHERIT_OPENER;
//    Navigate(&params);

// #if BUILDFLAG(ENABLE_EXTENSIONS)
//   DCHECK(extensions::ExtensionSystem::Get(
//       dock->profile())->extension_service());
//   const extensions::Extension* extension =
//       extensions::ExtensionRegistry::Get(dock->profile())
//           ->enabled_extensions().GetAppByURL(url);
//   if (extension) {
//     extensions::RecordAppLaunchType(extension_misc::APP_LAUNCH_OMNIBOX_LOCATION,
//                                     extension->GetType());
//   }
// #endif
 }

// void Stop(Dock* dock) {
//   base::RecordAction(UserMetricsAction("Stop"));
//   dock->tablist_model()->GetActiveApplicationContents()->Stop();
// }

 void NewWindow(Dock* dock) {
   NewEmptyWindow(dock->workspace());
 }

// void NewIncognitoWindow(Dock* dock) {
// #if BUILDFLAG(ENABLE_DESKTOP_IN_PRODUCT_HELP)
//   feature_engagement::IncognitoWindowTrackerFactory::GetInstance()
//       ->GetForProfile(dock->profile())
//       ->OnIncognitoWindowOpened();
// #endif
//   NewEmptyWindow(dock->profile()->GetOffTheRecordProfile());
// }

 void CloseWindow(Dock* dock) {
//   base::RecordAction(UserMetricsAction("CloseWindow"));
   dock->window()->Close();
 }

 void NewTab(Dock* dock) {
  // base::RecordAction(UserMetricsAction("NewTab"));
  // TODO(asvitkine): This is invoked programmatically from several places.
  // Audit the code and change it so that the histogram only gets collected for
  // user-initiated commands.
//  UMA_HISTOGRAM_ENUMERATION("Tab.NewTab", TablistModel::NEW_TAB_COMMAND,
//                            TablistModel::NEW_TAB_ENUM_COUNT);
  TabStyle style = TabStyle::kAPP;
  if (dock->is_type_tabbed()) {
    AddTabAt(dock, GURL(), nullptr, -1, true, style);
    dock->tablist_model()->GetActiveApplicationContents()->RestoreFocus();
  } else {
    ScopedTabbedDockDisplayer displayer(dock->workspace());
    Dock* b = displayer.dock();
    AddTabAt(b, GURL(), nullptr, -1, true, style);
    b->window()->Show();
    // The call to AddBlankTabAt above did not set the focus to the tab as its
    // window was not active, so we have to do it explicitly.
    // See http://crbug.com/6380.
    b->tablist_model()->GetActiveApplicationContents()->RestoreFocus();
  }
}

void CloseTab(Dock* dock) {
  //base::RecordAction(UserMetricsAction("CloseTab_Accelerator"));
  dock->tablist_model()->CloseSelectedTabs();
}

bool CanZoomIn(ApplicationContents* contents) {
  return contents && !contents->IsCrashed() &&
         zoom::ZoomController::FromApplicationContents(contents)->GetZoomPercent() !=
             contents->GetMaximumZoomPercent();
}

bool CanZoomOut(ApplicationContents* contents) {
  return contents && !contents->IsCrashed() &&
         zoom::ZoomController::FromApplicationContents(contents)->GetZoomPercent() !=
             contents->GetMinimumZoomPercent();
}

bool CanResetZoom(ApplicationContents* contents) {
  zoom::ZoomController* zoom_controller =
      zoom::ZoomController::FromApplicationContents(contents);
  return !zoom_controller->IsAtDefaultZoom() ||
         !zoom_controller->PageScaleFactorIsOne();
}

TablistModelDelegate::RestoreTabType GetRestoreTabType(
    const Dock* dock) {
  //sessions::TabRestoreService* service =
      //TabRestoreServiceFactory::GetForProfile(dock->profile());
  //if (!service || service->entries().empty())
    return TablistModelDelegate::RESTORE_NONE;
  //if (service->entries().front()->type == sessions::TabRestoreService::WINDOW)
//    return TablistModelDelegate::RESTORE_WINDOW;
//  return TablistModelDelegate::RESTORE_TAB;
}

void SelectNextTab(Dock* dock) {
  //base::RecordAction(UserMetricsAction("SelectNextTab"));
  dock->tablist_model()->SelectNextTab();
}

void SelectPreviousTab(Dock* dock) {
  //base::RecordAction(UserMetricsAction("SelectPrevTab"));
  dock->tablist_model()->SelectPreviousTab();
}

void MoveTabNext(Dock* dock) {
  //base::RecordAction(UserMetricsAction("MoveTabNext"));
  dock->tablist_model()->MoveTabNext();
}

void MoveTabPrevious(Dock* dock) {
  //base::RecordAction(UserMetricsAction("MoveTabPrevious"));
  dock->tablist_model()->MoveTabPrevious();
}

void SelectNumberedTab(Dock* dock, int index) {
  if (index < dock->tablist_model()->count()) {
    //base::RecordAction(UserMetricsAction("SelectNumberedTab"));
    dock->tablist_model()->ActivateTabAt(index, true);
  }
}

void SelectLastTab(Dock* dock) {
  //base::RecordAction(UserMetricsAction("SelectLastTab"));
  dock->tablist_model()->SelectLastTab();
}

void DuplicateTab(Dock* dock) {
  //base::RecordAction(UserMetricsAction("Duplicate"));
  DuplicateTabAt(dock, dock->tablist_model()->active_index());
}

bool CanDuplicateTab(Dock* dock) {
  return CanDuplicateTabAt(dock, dock->tablist_model()->active_index());
}

ApplicationContents* DuplicateTabAt(Dock* dock, int index) {
  ApplicationContents* contents = dock->tablist_model()->GetApplicationContentsAt(index);
  CHECK(contents);
  std::unique_ptr<ApplicationContents> contents_dupe =
      base::WrapUnique(contents->Clone());
  ApplicationContents* raw_contents_dupe = contents_dupe.get();

  bool pinned = false;
//  if (dock->CanSupportWindowFeature(Dock::FEATURE_TABSTRIP)) {
    // If this is a tabbed dock, just create a duplicate tab inside the same
    // window next to the tab being duplicated.
    int tab_index = dock->tablist_model()->GetIndexOfApplicationContents(contents);
    pinned = dock->tablist_model()->IsTabPinned(tab_index);
    int add_types = TablistModel::ADD_ACTIVE |
        TablistModel::ADD_INHERIT_GROUP |
        (pinned ? TablistModel::ADD_PINNED : 0);
    dock->tablist_model()->InsertApplicationContentsAt(
        tab_index + 1, std::move(contents_dupe), add_types);
  // } else {
  //   Dock* new_dock = NULL;
  //   if (dock->is_app() && !dock->is_type_popup()) {
  //     new_dock = new Dock(Dock::CreateParams::CreateForApp(
  //         dock->app_name(), dock->is_trusted_source(), gfx::Rect(),
  //         dock->profile(), true));
  //   } else {
  //     new_dock = new Dock(
  //         Dock::CreateParams(dock->type(), dock->profile(), true));
  //   }
  //   // Preserve the size of the original window. The new window has already
  //   // been given an offset by the OS, so we shouldn't copy the old bounds.
  //   DockWindow* new_window = new_dock->window();
  //   new_window->SetBounds(gfx::Rect(new_window->GetRestoredBounds().origin(),
  //                         dock->window()->GetRestoredBounds().size()));

  //   // We need to show the dock now.  Otherwise ContainerWin assumes the
  //   // ApplicationContents is invisible and won't size it.
  //   new_dock->window()->Show();

  //   // The page transition below is only for the purpose of inserting the tab.
  //   new_dock->tablist_model()->AddApplicationContents(std::move(contents_dupe), -1,
  //                                                  ui::PAGE_TRANSITION_LINK,
  //                                                  TablistModel::ADD_ACTIVE);
  // }

  //SessionService* session_service =
      //SessionServiceFactory::GetForProfileIfExisting(dock->profile());
  //if (session_service)
//    session_service->TabRestored(raw_contents_dupe, pinned);
  return raw_contents_dupe;
}

bool CanDuplicateTabAt(Dock* dock, int index) {
  ApplicationContents* contents = dock->tablist_model()->GetApplicationContentsAt(index);
  // If an interstitial is showing, do not allow tab duplication, since
  // the last committed entry is what would get duplicated and is not
  // what the user expects to duplicate.
  return contents && !contents->ShowingInterstitialPage();// &&
         //contents->GetController().GetLastCommittedEntry();
}

void PinTab(Dock* dock) {
  dock->tablist_model()->ExecuteContextMenuCommand(
      dock->tablist_model()->active_index(),
      TablistModel::ContextMenuCommand::CommandTogglePinned);
}

// void MuteSite(Dock* dock) {
//   TablistModel::ContextMenuCommand command_id =
//       base::FeatureList::IsEnabled(features::kSoundContentSetting)
//           ? TablistModel::ContextMenuCommand::CommandToggleSiteMuted
//           : TablistModel::ContextMenuCommand::CommandToggleTabAudioMuted;
//   dock->tablist_model()->ExecuteContextMenuCommand(
//       dock->tablist_model()->active_index(), command_id);
// }

 void ConvertPopupToTabbedDock(Dock* dock) {
  // base::RecordAction(UserMetricsAction("ShowAsTab"));
   TablistModel* tab_strip = dock->tablist_model();
   std::unique_ptr<ApplicationContents> contents =
       tab_strip->DetachApplicationContentsAt(tab_strip->active_index());
   Dock* b = new Dock(Dock::CreateParams(dock->workspace(), contents->GetURL(), true));
   b->tablist_model()->AppendApplicationContents(std::move(contents), true);
   b->window()->Show();
 }

 void Exit() {
   DLOG(INFO) << "DockCommands: Exit() called, but we didnt implemented it";
   //base::RecordAction(UserMetricsAction("Exit"));
   //chrome::AttemptUserExit();
 }

// void BookmarkCurrentPageIgnoringExtensionOverrides(Dock* dock) {
//   base::RecordAction(UserMetricsAction("Star"));

//   BookmarkModel* model =
//       BookmarkModelFactory::GetForDockContext(dock->profile());
//   if (!model || !model->loaded())
//     return;  // Ignore requests until bookmarks are loaded.

//   GURL url;
//   base::string16 title;
//   ApplicationContents* web_contents =
//       dock->tablist_model()->GetActiveApplicationContents();
//   // |web_contents| can be nullptr if the last tab in the dock was closed
//   // but the dock wasn't closed yet. https://crbug.com/799668
//   if (!web_contents)
//     return;
//   GetURLAndTitleToBookmark(web_contents, &url, &title);
//   bool is_bookmarked_by_any = model->IsBookmarked(url);
//   if (!is_bookmarked_by_any &&
//       web_contents->GetDockContext()->IsOffTheRecord()) {
//     // If we're incognito the favicon may not have been saved. Save it now
//     // so that bookmarks have an icon for the page.
//     favicon::ContentFaviconDriver::FromApplicationContents(web_contents)
//         ->SaveFaviconEvenIfInIncognito();
//   }
//   bool was_bookmarked_by_user = bookmarks::IsBookmarkedByUser(model, url);
//   bookmarks::AddIfNotBookmarked(model, url, title);
//   bool is_bookmarked_by_user = bookmarks::IsBookmarkedByUser(model, url);
//   // Make sure the model actually added a bookmark before showing the star. A
//   // bookmark isn't created if the url is invalid.
//   if (dock->window()->IsActive() && is_bookmarked_by_user) {
//     // Only show the bubble if the window is active, otherwise we may get into
//     // weird situations where the bubble is deleted as soon as it is shown.
//     dock->window()->ShowBookmarkBubble(url, was_bookmarked_by_user);
//   }
// }

// void BookmarkCurrentPageAllowingExtensionOverrides(Dock* dock) {
//   DCHECK(!chrome::ShouldRemoveBookmarkThisPageUI(dock->profile()));

// #if BUILDFLAG(ENABLE_EXTENSIONS)
//   const extensions::Extension* extension = NULL;
//   extensions::Command command;
//   if (GetBookmarkOverrideCommand(dock->profile(), &extension, &command)) {
//     switch (command.type()) {
//       case extensions::Command::Type::kNamed:
//         dock->window()->ExecuteExtensionCommand(extension, command);
//         break;
//       case extensions::Command::Type::kDockAction:
//       case extensions::Command::Type::kPageAction:
//         // BookmarkCurrentPage is called through a user gesture, so it is safe
//         // to grant the active tab permission.
//         extensions::ExtensionActionAPI::Get(dock->profile())->
//             ShowExtensionActionPopup(extension, dock, true);
//         break;
//     }
//     return;
//   }
// #endif
//   BookmarkCurrentPageIgnoringExtensionOverrides(dock);
// }

// bool CanBookmarkCurrentPage(const Dock* dock) {
//   return CanBookmarkCurrentPageInternal(dock, true);
// }

// void BookmarkAllTabs(Dock* dock) {
//   base::RecordAction(UserMetricsAction("BookmarkAllTabs"));
//   chrome::ShowBookmarkAllTabsDialog(dock);
// }

// bool CanBookmarkAllTabs(const Dock* dock) {
//   return dock->tablist_model()->count() > 1 &&
//              !chrome::ShouldRemoveBookmarkOpenPagesUI(dock->profile()) &&
//              CanBookmarkCurrentPageInternal(dock, false);
// }

// void SaveCreditCard(Dock* dock) {
//   ApplicationContents* web_contents =
//       dock->tablist_model()->GetActiveApplicationContents();
//   autofill::SaveCardBubbleControllerImpl* controller =
//       autofill::SaveCardBubbleControllerImpl::FromApplicationContents(web_contents);
//   controller->ReshowBubble();
// }

// void Translate(Dock* dock) {
//   if (!dock->window()->IsActive())
//     return;

//   ApplicationContents* web_contents =
//       dock->tablist_model()->GetActiveApplicationContents();
//   ChromeTranslateClient* chrome_translate_client =
//       ChromeTranslateClient::FromApplicationContents(web_contents);

//   translate::TranslateStep step = translate::TRANSLATE_STEP_BEFORE_TRANSLATE;
//   if (chrome_translate_client) {
//     if (chrome_translate_client->GetLanguageState().translation_pending())
//       step = translate::TRANSLATE_STEP_TRANSLATING;
//     else if (chrome_translate_client->GetLanguageState().translation_error())
//       step = translate::TRANSLATE_STEP_TRANSLATE_ERROR;
//     else if (chrome_translate_client->GetLanguageState().IsPageTranslated())
//       step = translate::TRANSLATE_STEP_AFTER_TRANSLATE;
//   }
//   ShowTranslateBubbleResult result = dock->window()->ShowTranslateBubble(
//       web_contents, step, translate::TranslateErrors::NONE, true);
//   if (result != ShowTranslateBubbleResult::SUCCESS)
//     translate::ReportUiAction(TranslateBubbleResultToUiEvent(result));
// }

// void ManagePasswordsForPage(Dock* dock) {
//   ApplicationContents* web_contents =
//       dock->tablist_model()->GetActiveApplicationContents();
//   ManagePasswordsUIController* controller =
//       ManagePasswordsUIController::FromApplicationContents(web_contents);
//   TabDialogs::FromApplicationContents(web_contents)->ShowManagePasswordsBubble(
//       !controller->IsAutomaticallyOpeningBubble());
// }

// void SavePage(Dock* dock) {
//   base::RecordAction(UserMetricsAction("SavePage"));
//   ApplicationContents* current_tab = dock->tablist_model()->GetActiveApplicationContents();
//   DCHECK(current_tab);
//   if (current_tab->GetContentsMimeType() == "application/pdf")
//     base::RecordAction(UserMetricsAction("PDF.SavePage"));
//   current_tab->OnSavePage();
// }

// bool CanSavePage(const Dock* dock) {
//   // LocalState can be NULL in tests.
//   if (g_dock_process->local_state() &&
//       !g_dock_process->local_state()->GetBoolean(
//       prefs::kAllowFileSelectionDialogs)) {
//     return false;
//   }
//   return !dock->is_devtools() &&
//       !(GetContentRestrictions(dock) & CONTENT_RESTRICTION_SAVE);
// }

// void ShowFindBar(Dock* dock) {
//   dock->GetFindBarController()->Show();
// }

// void Print(Dock* dock) {
// #if BUILDFLAG(ENABLE_PRINTING)
//   auto* web_contents = dock->tablist_model()->GetActiveApplicationContents();
//   printing::StartPrint(web_contents, dock->profile()->GetPrefs()->GetBoolean(
//                                          prefs::kPrintPreviewDisabled),
//                        false /* has_selection? */);
// #endif
// }

// bool CanPrint(Dock* dock) {
//   // Do not print when printing is disabled via pref or policy.
//   // Do not print when a page has crashed.
//   // Do not print when a constrained window is showing. It's confusing.
//   // TODO(gbillock): Need to re-assess the call to
//   // IsShowingApplicationContentsModalDialog after a popup management policy is
//   // refined -- we will probably want to just queue the print request, not
//   // block it.
//   ApplicationContents* current_tab = dock->tablist_model()->GetActiveApplicationContents();
//   return dock->profile()->GetPrefs()->GetBoolean(prefs::kPrintingEnabled) &&
//       (current_tab && !current_tab->IsCrashed()) &&
//       !(IsShowingApplicationContentsModalDialog(dock) ||
//         GetContentRestrictions(dock) & CONTENT_RESTRICTION_PRINT);
// }

// #if BUILDFLAG(ENABLE_PRINTING)
// void BasicPrint(Dock* dock) {
//   printing::StartBasicPrint(dock->tablist_model()->GetActiveApplicationContents());
// }

// bool CanBasicPrint(Dock* dock) {
// #if BUILDFLAG(ENABLE_BASIC_PRINT_DIALOG)
//   // If printing is not disabled via pref or policy, it is always possible to
//   // advanced print when the print preview is visible.
//   return dock->profile()->GetPrefs()->GetBoolean(prefs::kPrintingEnabled) &&
//          (PrintPreviewShowing(dock) || CanPrint(dock));
// #else
//   return false;  // The print dialog is disabled.
// #endif  // BUILDFLAG(ENABLE_BASIC_PRINT_DIALOG)
// }
// #endif  // BUILDFLAG(ENABLE_PRINTING)

// bool CanRouteMedia(Dock* dock) {
//   // Do not allow user to open Media Router dialog when there is already an
//   // active modal dialog. This avoids overlapping dialogs.
//   return media_router::MediaRouterEnabled(dock->profile()) &&
//          !IsShowingApplicationContentsModalDialog(dock);
// }

// void RouteMedia(Dock* dock) {
//   DCHECK(CanRouteMedia(dock));

//   media_router::MediaRouterDialogController* dialog_controller =
//       media_router::MediaRouterDialogController::GetOrCreateForApplicationContents(
//           dock->tablist_model()->GetActiveApplicationContents());
//   if (!dialog_controller)
//     return;

//   dialog_controller->ShowMediaRouterDialog();
// }

// void EmailPageLocation(Dock* dock) {
//   base::RecordAction(UserMetricsAction("EmailPageLocation"));
//   ApplicationContents* wc = dock->tablist_model()->GetActiveApplicationContents();
//   DCHECK(wc);

//   std::string title = net::EscapeQueryParamValue(
//       base::UTF16ToUTF8(wc->GetTitle()), false);
//   std::string page_url = net::EscapeQueryParamValue(wc->GetURL().spec(), false);
//   std::string mailto = std::string("mailto:?subject=Fwd:%20") +
//       title + "&body=%0A%0A" + page_url;
//   platform_util::OpenExternal(dock->profile(), GURL(mailto));
// }

// bool CanEmailPageLocation(const Dock* dock) {
//   return dock->toolbar_model()->ShouldDisplayURL() &&
//       dock->tablist_model()->GetActiveApplicationContents()->GetURL().is_valid();
// }

 void CutCopyPaste(Dock* dock, int command_id) {
//   if (command_id == IDC_CUT)
//     base::RecordAction(UserMetricsAction("Cut"));
//   else if (command_id == IDC_COPY)
//     base::RecordAction(UserMetricsAction("Copy"));
//   else
//     base::RecordAction(UserMetricsAction("Paste"));
   dock->window()->CutCopyPaste(command_id);
 }

void RestoreTab(Dock* dock) {
  LOG(INFO) << "host::RestoreTab: called, but not implemented";
}


// void Find(Dock* dock) {
//   base::RecordAction(UserMetricsAction("Find"));
//   FindInPage(dock, false, false);
// }

// void FindNext(Dock* dock) {
//   base::RecordAction(UserMetricsAction("FindNext"));
//   FindInPage(dock, true, true);
// }

// void FindPrevious(Dock* dock) {
//   base::RecordAction(UserMetricsAction("FindPrevious"));
//   FindInPage(dock, true, false);
// }

// void FindInPage(Dock* dock, bool find_next, bool forward_direction) {
//   ShowFindBar(dock);
//   if (find_next) {
//     base::string16 find_text;
//     FindTabHelper* find_helper = FindTabHelper::FromApplicationContents(
//         dock->tablist_model()->GetActiveApplicationContents());
// #if defined(OS_MACOSX)
//     // We always want to search for the current contents of the find bar on
//     // OS X. For regular profile it's always the current find pboard. For
//     // Incognito window it's the newest value of the find pboard content and
//     // user-typed text.
//     FindBar* find_bar = dock->GetFindBarController()->find_bar();
//     find_text = find_bar->GetFindText();
// #endif
//     find_helper->StartFinding(find_text, forward_direction, false);
//   }
// }

// void Zoom(Dock* dock, content::PageZoom zoom) {
//   zoom::PageZoom::Zoom(dock->tablist_model()->GetActiveApplicationContents(),
//                        zoom);
// }

// void FocusToolbar(Dock* dock) {
//   base::RecordAction(UserMetricsAction("FocusToolbar"));
//   dock->window()->FocusToolbar();
// }

// void FocusLocationBar(Dock* dock) {
//   base::RecordAction(UserMetricsAction("FocusLocation"));
//   dock->window()->SetFocusToLocationBar(true);
// }

// void FocusSearch(Dock* dock) {
//   // TODO(beng): replace this with FocusLocationBar
//   base::RecordAction(UserMetricsAction("FocusSearch"));
//   dock->window()->GetLocationBar()->FocusSearch();
// }

// void FocusAppMenu(Dock* dock) {
//   base::RecordAction(UserMetricsAction("FocusAppMenu"));
//   dock->window()->FocusAppMenu();
// }

// void FocusBookmarksToolbar(Dock* dock) {
//   base::RecordAction(UserMetricsAction("FocusBookmarksToolbar"));
//   dock->window()->FocusBookmarksToolbar();
// }

// void FocusInactivePopupForAccessibility(Dock* dock) {
//   base::RecordAction(UserMetricsAction("FocusInactivePopupForAccessibility"));
//   dock->window()->FocusInactivePopupForAccessibility();
// }

// void FocusNextPane(Dock* dock) {
//   base::RecordAction(UserMetricsAction("FocusNextPane"));
//   dock->window()->RotatePaneFocus(true);
// }

// void FocusPreviousPane(Dock* dock) {
//   base::RecordAction(UserMetricsAction("FocusPreviousPane"));
//   dock->window()->RotatePaneFocus(false);
// }

void ToggleDevToolsWindow(Dock* dock, DevToolsToggleAction action) {
  // if (action.type() == DevToolsToggleAction::kShowConsolePanel)
  //   base::RecordAction(UserMetricsAction("DevTools_ToggleConsole"));
  // else
  //   base::RecordAction(UserMetricsAction("DevTools_ToggleWindow"));
  DevToolsWindow::ToggleDevToolsWindow(dock, action);
}

// bool CanOpenTaskManager() {
// #if !defined(OS_ANDROID)
//   return true;
// #else
//   return false;
// #endif
// }

// void OpenTaskManager(Dock* dock) {
// #if !defined(OS_ANDROID)
//   base::RecordAction(UserMetricsAction("TaskManager"));
//   chrome::ShowTaskManager(dock);
// #else
//   NOTREACHED();
// #endif
// }

// void OpenFeedbackDialog(Dock* dock, FeedbackSource source) {
//   base::RecordAction(UserMetricsAction("Feedback"));
//   chrome::ShowFeedbackPage(
//       dock, source, std::string() /* description_template */,
//       std::string() /* description_placeholder_text */,
//       std::string() /* category_tag */, std::string() /* extra_diagnostics */);
// }

// void ToggleBookmarkBar(Dock* dock) {
//   base::RecordAction(UserMetricsAction("ShowBookmarksBar"));
//   ToggleBookmarkBarWhenVisible(dock->profile());
// }

// void ShowAppMenu(Dock* dock) {
//   // We record the user metric for this event in AppMenu::RunMenu.
//   dock->window()->ShowAppMenu();
// }

// void ShowAvatarMenu(Dock* dock) {
//   dock->window()->ShowAvatarBubbleFromAvatarButton(
//       DockWindow::AVATAR_BUBBLE_MODE_DEFAULT, signin::ManageAccountsParams(),
//       signin_metrics::AccessPoint::ACCESS_POINT_AVATAR_BUBBLE_SIGN_IN, true);
// }

// void OpenUpdateChromeDialog(Dock* dock) {
//   if (UpgradeDetector::GetInstance()->is_outdated_install()) {
//     UpgradeDetector::GetInstance()->NotifyOutdatedInstall();
//   } else if (UpgradeDetector::GetInstance()->is_outdated_install_no_au()) {
//     UpgradeDetector::GetInstance()->NotifyOutdatedInstallNoAutoUpdate();
//   } else {
//     base::RecordAction(UserMetricsAction("UpdateChrome"));
//     dock->window()->ShowUpdateChromeDialog();
//   }
// }

// void DistillCurrentPage(Dock* dock) {
//   DistillCurrentPageAndView(dock->tablist_model()->GetActiveApplicationContents());
// }

// bool CanRequestTabletSite(ApplicationContents* current_tab) {
//   return current_tab &&
//       current_tab->GetController().GetLastCommittedEntry() != NULL;
// }

// bool IsRequestingTabletSite(Dock* dock) {
//   ApplicationContents* current_tab = dock->tablist_model()->GetActiveApplicationContents();
//   if (!current_tab)
//     return false;
//   content::NavigationEntry* entry =
//       current_tab->GetController().GetLastCommittedEntry();
//   if (!entry)
//     return false;
//   return entry->GetIsOverridingUserAgent();
// }

// void ToggleRequestTabletSite(Dock* dock) {
//   ApplicationContents* current_tab = dock->tablist_model()->GetActiveApplicationContents();
//   if (!current_tab)
//     return;
//   NavigationController& controller = current_tab->GetController();
//   NavigationEntry* entry = controller.GetLastCommittedEntry();
//   if (!entry)
//     return;
//   if (entry->GetIsOverridingUserAgent()) {
//     entry->SetIsOverridingUserAgent(false);
//   } else {
//     entry->SetIsOverridingUserAgent(true);
//     std::string product = version_info::GetProductNameAndVersionForUserAgent();
//     current_tab->SetUserAgentOverride(content::BuildUserAgentFromOSAndProduct(
//                                           kOsOverrideForTabletSite, product),
//                                       false);
//   }
//   controller.Reload(content::ReloadType::ORIGINAL_REQUEST_URL, true);
// }

void ToggleFullscreenMode(Dock* dock) {
   DCHECK(dock);
   dock->exclusive_access_manager()
       ->fullscreen_controller()
       ->ToggleDockFullscreenMode();
}

// void ClearCache(Dock* dock) {
//   content::BrowsingDataRemover* remover =
//       content::DockContext::GetBrowsingDataRemover(dock->profile());
//   remover->Remove(base::Time(), base::Time::Max(),
//                   content::BrowsingDataRemover::DATA_TYPE_CACHE,
//                   content::BrowsingDataRemover::ORIGIN_TYPE_UNPROTECTED_WEB);
//   // BrowsingDataRemover takes care of deleting itself when done.
// }

// bool IsDebuggerAttachedToCurrentTab(Dock* dock) {
//   ApplicationContents* contents = dock->tablist_model()->GetActiveApplicationContents();
//   return contents ?
//       content::DevToolsAgentHost::IsDebuggerAttached(contents) : false;
// }

 void CopyURL(Dock* dock) {
   ui::ScopedClipboardWriter scw(ui::CLIPBOARD_TYPE_COPY_PASTE);
   scw.WriteText(base::UTF8ToUTF16(dock->tablist_model()
                                       ->GetActiveApplicationContents()
                                       ->GetVisibleURL()
                                       .spec()));
 }

// void OpenInChrome(Dock* dock) {
//   // Find a non-incognito dock.
//   Dock* target_dock =
//       chrome::FindTabbedDock(dock->profile(), false);

//   if (!target_dock) {
//     target_dock =
//         new Dock(Dock::CreateParams(dock->profile(), true));
//   }

//   TablistModel* source_tabstrip = dock->tablist_model();
//   target_dock->tablist_model()->AppendApplicationContents(
//       source_tabstrip->DetachApplicationContentsAt(source_tabstrip->active_index()),
//       true);
//   target_dock->window()->Show();
// }

// bool CanViewSource(const Dock* dock) {
//   return !dock->is_devtools() &&
//       dock->tablist_model()->GetActiveApplicationContents()->GetController().
//           CanViewSource();
// }

// #if BUILDFLAG(ENABLE_EXTENSIONS)
// void CreateBookmarkAppFromCurrentApplicationContents(Dock* dock) {
//   base::RecordAction(UserMetricsAction("CreateHostedApp"));
//   extensions::TabHelper::FromApplicationContents(
//       dock->tablist_model()->GetActiveApplicationContents())->
//           CreateHostedAppFromApplicationContents();
// }

// bool CanCreateBookmarkApp(const Dock* dock) {
//   return extensions::TabHelper::FromApplicationContents(
//              dock->tablist_model()->GetActiveApplicationContents())
//       ->CanCreateBookmarkApp();
// }
// #endif  // BUILDFLAG(ENABLE_EXTENSIONS)

// #if defined(OS_CHROMEOS)
// void ShowIntentPickerBubble(const Dock* dock,
//                             std::vector<chromeos::IntentPickerAppInfo> app_info,
//                             IntentPickerResponse callback) {
//   dock->window()->ShowIntentPickerBubble(std::move(app_info),
//                                             std::move(callback));
// }

// void SetIntentPickerViewVisibility(Dock* dock, bool visible) {
//   dock->window()->SetIntentPickerViewVisibility(visible);
// }
// #endif  // defined(OS_CHROMEOS)

}  // namespace chrome
