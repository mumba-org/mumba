// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_DOCK_COMMANDS_H_
#define CHROME_BROWSER_UI_DOCK_COMMANDS_H_

#include <string>
#include <vector>

#include "build/build_config.h"
#include "base/memory/ref_counted.h"
#include "core/host/ui/tablist/tablist_model_delegate.h"
#include "ui/base/window_open_disposition.h"
#include "core/host/ui/devtools/devtools_toggle_action.h"

namespace host {
class Dock;
class CommandObserver;
class Workspace;

// For all commands, where a tab is not specified, the active tab is assumed.

bool IsCommandEnabled(Dock* dock, int command);
bool SupportsCommand(Dock* dock, int command);
bool ExecuteCommand(Dock* dock, int command);
 bool ExecuteCommandWithDisposition(Dock* dock,
                                    int command,
                                    WindowOpenDisposition disposition);
 void UpdateCommandEnabled(Dock* dock, int command, bool enabled);
 void AddCommandObserver(Dock* dock, int command, CommandObserver* observer);
 void RemoveCommandObserver(Dock* dock, int command, CommandObserver* observer);

// int GetContentRestrictions(const Browser* browser);

// // Opens a new window with the default blank tab.
void NewEmptyWindow(scoped_refptr<Workspace> workspace);

// // Opens a new window with the default blank tab. This bypasses metrics and
// // various internal bookkeeping; NewEmptyWindow (above) is preferred.
Dock* OpenEmptyWindow(scoped_refptr<Workspace> workspace);

// // Opens a new window with the tabs from |profile|'s TabRestoreService.
// void OpenWindowWithRestoredTabs(Profile* profile);

// // Opens the specified URL in a new browser window in an incognito session. If
// // there is already an existing active incognito session for the specified
// // |profile|, that session is re- used.
// void OpenURLOffTheRecord(Profile* profile, const GURL& url);

// bool CanGoBack(const Browser* browser);
// void GoBack(Browser* browser, WindowOpenDisposition disposition);
// bool CanGoForward(const Browser* browser);
// void GoForward(Browser* browser, WindowOpenDisposition disposition);
// bool NavigateToIndexWithDisposition(Browser* browser,
//                                     int index,
//                                     WindowOpenDisposition disposition);
// void Reload(Browser* browser, WindowOpenDisposition disposition);
// void ReloadBypassingCache(Browser* browser, WindowOpenDisposition disposition);
// bool CanReload(const Browser* browser);
// void Home(Browser* browser, WindowOpenDisposition disposition);
void OpenCurrentURL(Dock* dock);
// void Stop(Browser* browser);
 void NewWindow(Dock* dock);
// void NewIncognitoWindow(Browser* browser);
 void CloseWindow(Dock* dock);
 void NewTab(Dock* dock);
 void CloseTab(Dock* dock);
 bool CanZoomIn(ApplicationContents* contents);
 bool CanZoomOut(ApplicationContents* contents);
 bool CanResetZoom(ApplicationContents* contents);
 void RestoreTab(Dock* dock);
 TablistModelDelegate::RestoreTabType GetRestoreTabType(const Dock* dock);
 void SelectNextTab(Dock* dock);
 void SelectPreviousTab(Dock* dock);
 void MoveTabNext(Dock* dock);
 void MoveTabPrevious(Dock* dock);
 void SelectNumberedTab(Dock* dock, int index);
 void SelectLastTab(Dock* dock);
 void DuplicateTab(Dock* dock);
 bool CanDuplicateTab(Dock* dock);
 ApplicationContents* DuplicateTabAt(Dock* dock, int index);
 bool CanDuplicateTabAt(Dock* dock, int index);
// void MuteSite(Browser* browser);
 void PinTab(Dock* dock);
 void ConvertPopupToTabbedDock(Dock* dock);
 void Exit();
// void BookmarkCurrentPageIgnoringExtensionOverrides(Browser* browser);
// void BookmarkCurrentPageAllowingExtensionOverrides(Browser* browser);
// bool CanBookmarkCurrentPage(const Browser* browser);
// void BookmarkAllTabs(Browser* browser);
// bool CanBookmarkAllTabs(const Browser* browser);
// void SaveCreditCard(Browser* browser);
// void Translate(Browser* browser);
// void ManagePasswordsForPage(Browser* browser);
// void SavePage(Browser* browser);
// bool CanSavePage(const Browser* browser);
// void ShowFindBar(Browser* browser);
// void Print(Browser* browser);
// bool CanPrint(Browser* browser);
// #if BUILDFLAG(ENABLE_PRINTING)
// void BasicPrint(Browser* browser);
// bool CanBasicPrint(Browser* browser);
// #endif  // ENABLE_PRINTING
// bool CanRouteMedia(Browser* browser);
// void RouteMedia(Browser* browser);
// void EmailPageLocation(Browser* browser);
// bool CanEmailPageLocation(const Browser* browser);
void CutCopyPaste(Dock* dock, int command_id);
// void Find(Browser* browser);
// void FindNext(Browser* browser);
// void FindPrevious(Browser* browser);
// void FindInPage(Browser* browser, bool find_next, bool forward_direction);
// void Zoom(Browser* browser, content::PageZoom zoom);
// void FocusToolbar(Browser* browser);
// void FocusLocationBar(Browser* browser);
// void FocusSearch(Browser* browser);
// void FocusAppMenu(Browser* browser);
// void FocusBookmarksToolbar(Browser* browser);
// void FocusInactivePopupForAccessibility(Browser* browser);
// void FocusNextPane(Browser* browser);
// void FocusPreviousPane(Browser* browser);
 void ToggleDevToolsWindow(Dock* dock, DevToolsToggleAction action);
// bool CanOpenTaskManager();
// void OpenTaskManager(Browser* browser);
// void OpenFeedbackDialog(Browser* browser, FeedbackSource source);
// void ToggleBookmarkBar(Browser* browser);
// void ShowAppMenu(Browser* browser);
// void ShowAvatarMenu(Browser* browser);
// void OpenUpdateChromeDialog(Browser* browser);
// void DistillCurrentPage(Browser* browser);
// bool CanRequestTabletSite(content::WebContents* current_tab);
// bool IsRequestingTabletSite(Browser* browser);
// void ToggleRequestTabletSite(Browser* browser);
 void ToggleFullscreenMode(Dock* dock);
// void ClearCache(Browser* browser);
// bool IsDebuggerAttachedToCurrentTab(Browser* browser);
void CopyURL(Dock* dock);
// void OpenInChrome(Browser* browser);
// #if defined(OS_CHROMEOS)
// void ShowIntentPickerBubble(const Browser* browser,
//                             std::vector<chromeos::IntentPickerAppInfo> app_info,
//                             IntentPickerResponse callback);
// void SetIntentPickerViewVisibility(Browser* browser, bool visible);
// #endif  // defined(OS_CHROMEOS)

// bool CanViewSource(const Browser* browser);

// void CreateBookmarkAppFromCurrentWebContents(Browser* browser);
// bool CanCreateBookmarkApp(const Browser* browser);

}  // namespace host

#endif  // CHROME_BROWSER_UI_BROWSER_COMMANDS_H_
