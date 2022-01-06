// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/exclusive_access/fullscreen_controller.h"

#include "base/bind.h"
#include "base/command_line.h"
#include "base/location.h"
#include "base/metrics/histogram_macros.h"
#include "base/metrics/user_metrics.h"
#include "base/single_thread_task_runner.h"
#include "base/threading/thread_task_runner_handle.h"
#include "build/build_config.h"
#include "core/host/notification_types.h"
#include "core/host/workspace/workspace.h"
#include "core/host/ui/exclusive_access/exclusive_access_context.h"
#include "core/host/ui/exclusive_access/exclusive_access_manager.h"
#include "core/host/ui/exclusive_access/fullscreen_within_tab_helper.h"
//#include "core/host/ui/status_bubble.h"
#include "core/host/ui/tablist/tablist_model.h"
#include "core/host/application/application_contents_sizer.h"
#include "core/shared/common/switches.h"
//#include "components/content_settings/core/browser/host_content_settings_map.h"
//#include "core/host/navigation_details.h"
//#include "core/host/navigation_entry.h"
#include "core/host/notification_service.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/application_window_host_view.h"
#include "core/host/application/application_contents.h"

#if defined(OS_MACOSX)
#include "base/feature_list.h"
//#include "chrome/common/chrome_features.h"
//#else
//#include "chrome/common/pref_names.h"
//#include "components/prefs/pref_service.h"
#endif

using base::UserMetricsAction;

namespace host {

namespace {

const char kFullscreenBubbleReshowsHistogramName[] =
    "ExclusiveAccess.BubbleReshowsPerSession.Fullscreen";

}  // namespace

FullscreenController::FullscreenController(ExclusiveAccessManager* manager)
    : ExclusiveAccessControllerBase(manager),
      state_prior_to_tab_fullscreen_(STATE_INVALID),
      tab_fullscreen_(false),
      toggled_into_fullscreen_(false),
      is_privileged_fullscreen_for_testing_(false),
      ptr_factory_(this) {
}

FullscreenController::~FullscreenController() {
}

bool FullscreenController::IsFullscreenForDock() const {
  return exclusive_access_manager()->context()->IsFullscreen() &&
         !IsFullscreenCausedByTab();
}

void FullscreenController::ToggleDockFullscreenMode() {
  extension_caused_fullscreen_ = GURL();
  ToggleFullscreenModeInternal(BROWSER);
}

void FullscreenController::ToggleDockFullscreenModeWithExtension(
    const GURL& extension_url) {
  // |extension_caused_fullscreen_| will be reset if this causes fullscreen to
  // exit.
  extension_caused_fullscreen_ = extension_url;
  ToggleFullscreenModeInternal(BROWSER);
}

bool FullscreenController::IsWindowFullscreenForTabOrPending() const {
  return exclusive_access_tab() != nullptr;
}

bool FullscreenController::IsExtensionFullscreenOrPending() const {
  return !extension_caused_fullscreen_.is_empty();
}

bool FullscreenController::IsControllerInitiatedFullscreen() const {
  return toggled_into_fullscreen_;
}

bool FullscreenController::IsTabFullscreen() const {
  return tab_fullscreen_;
}

bool FullscreenController::IsFullscreenForTabOrPending(
    const ApplicationContents* application_contents) const {
  if (IsFullscreenWithinTab(application_contents))
    return true;
  if (application_contents == exclusive_access_tab()) {
    DCHECK(application_contents ==
           exclusive_access_manager()->context()->GetActiveApplicationContents());
    return true;
  }
  return false;
}

bool FullscreenController::IsFullscreenCausedByTab() const {
  return state_prior_to_tab_fullscreen_ == STATE_NORMAL;
}

void FullscreenController::EnterFullscreenModeForTab(ApplicationContents* application_contents) {//,
                                                     //const GURL& origin) {
  DCHECK(application_contents);

  if (MaybeToggleFullscreenWithinTab(application_contents, true)) {
    // During tab capture of fullscreen-within-tab views, the browser window
    // fullscreen state is unchanged, so return now.
    return;
  }

  if (application_contents !=
          exclusive_access_manager()->context()->GetActiveApplicationContents() ||
      IsWindowFullscreenForTabOrPending()) {
      return;
  }

  SetTabWithExclusiveAccess(application_contents);
  fullscreened_origin_ = GURL();//origin;

  ExclusiveAccessContext* exclusive_access_context =
      exclusive_access_manager()->context();

  if (!exclusive_access_context->IsFullscreen()) {
    // Normal -> Tab Fullscreen.
    state_prior_to_tab_fullscreen_ = STATE_NORMAL;
    ToggleFullscreenModeInternal(TAB);
    return;
  }

  // Dock Fullscreen -> Tab Fullscreen.
  if (exclusive_access_context->IsFullscreen()) {
    exclusive_access_context->UpdateUIForTabFullscreen(
        ExclusiveAccessContext::STATE_ENTER_TAB_FULLSCREEN);
    state_prior_to_tab_fullscreen_ = STATE_BROWSER_FULLSCREEN;
  }

  // We need to update the fullscreen exit bubble, e.g., going from browser
  // fullscreen to tab fullscreen will need to show different content.
  tab_fullscreen_ = true;
  exclusive_access_manager()->UpdateExclusiveAccessExitBubbleContent(
      ExclusiveAccessBubbleHideCallback());

  // This is only a change between Dock and Tab fullscreen. We generate
  // a fullscreen notification now because there is no window change.
  PostFullscreenChangeNotification(true);
}

void FullscreenController::ExitFullscreenModeForTab(ApplicationContents* application_contents) {
  if (MaybeToggleFullscreenWithinTab(application_contents, false)) {
    // During tab capture of fullscreen-within-tab views, the browser window
    // fullscreen state is unchanged, so return now.
    return;
  }

  if (!IsWindowFullscreenForTabOrPending() ||
      application_contents != exclusive_access_tab()) {
    return;
  }

  ExclusiveAccessContext* exclusive_access_context =
      exclusive_access_manager()->context();

  if (!exclusive_access_context->IsFullscreen())
    return;

  if (IsFullscreenCausedByTab()) {
    // Tab Fullscreen -> Normal.
    ToggleFullscreenModeInternal(TAB);
    return;
  }

  // Tab Fullscreen -> Dock Fullscreen.
  if (state_prior_to_tab_fullscreen_ == STATE_BROWSER_FULLSCREEN)
    exclusive_access_context->UpdateUIForTabFullscreen(
        ExclusiveAccessContext::STATE_EXIT_TAB_FULLSCREEN);

  // If currently there is a tab in "tab fullscreen" mode and fullscreen
  // was not caused by it (i.e., previously it was in "browser fullscreen"
  // mode), we need to switch back to "browser fullscreen" mode. In this
  // case, all we have to do is notifying the tab that it has exited "tab
  // fullscreen" mode.
  NotifyTabExclusiveAccessLost();

  // This is only a change between Dock and Tab fullscreen. We generate
  // a fullscreen notification now because there is no window change.
  PostFullscreenChangeNotification(true);
}

void FullscreenController::OnTabDetachedFromView(ApplicationContents* old_contents) {
  if (!IsFullscreenWithinTab(old_contents))
    return;

  // A fullscreen-within-tab view undergoing screen capture has been detached
  // and is no longer visible to the user. Set it to exactly the ApplicationContents'
  // preferred size. See 'FullscreenWithinTab Note'.
  //
  // When the user later selects the tab to show |old_contents| again, UI code
  // elsewhere (e.g., views::WebView) will resize the view to fit within the
  // browser window once again.

  // If the view has been detached from the browser window (e.g., to drag a tab
  // off into a new browser window), return immediately to avoid an unnecessary
  // resize.
  if (!old_contents->GetDelegate())
    return;

  // Do nothing if tab capture ended after toggling fullscreen, or a preferred
  // size was never specified by the capturer.
  if (!old_contents->IsBeingCaptured() ||
      old_contents->GetPreferredSize().IsEmpty()) {
    return;
  }

  ApplicationWindowHostView* const current_fs_view =
      old_contents->GetFullscreenApplicationWindowHostView();
  if (current_fs_view)
    current_fs_view->SetSize(old_contents->GetPreferredSize());
  ResizeApplicationContents(old_contents, gfx::Rect(old_contents->GetPreferredSize()));
}

void FullscreenController::OnTabClosing(ApplicationContents* application_contents) {
  if (IsFullscreenWithinTab(application_contents))
    application_contents->ExitFullscreen(
        /* will_cause_resize */ IsFullscreenCausedByTab());
  else
    ExclusiveAccessControllerBase::OnTabClosing(application_contents);
}

void FullscreenController::WindowFullscreenStateWillChange() {
  //ExclusiveAccessContext* exclusive_access_context =
      //exclusive_access_manager()->context();
  //if (exclusive_access_context->IsFullscreen()) {
//    exclusive_access_context->HideDownloadShelf();
//  } else {
    //exclusive_access_context->UnhideDownloadShelf();
  //}
}

void FullscreenController::WindowFullscreenStateChanged() {
  ExclusiveAccessContext* const exclusive_access_context =
      exclusive_access_manager()->context();
  bool exiting_fullscreen = !exclusive_access_context->IsFullscreen();

  PostFullscreenChangeNotification(!exiting_fullscreen);
  if (exiting_fullscreen) {
    toggled_into_fullscreen_ = false;
    extension_caused_fullscreen_ = GURL();
    NotifyTabExclusiveAccessLost();
  }
}

bool FullscreenController::HandleUserPressedEscape() {
  ApplicationContents* const active_application_contents =
      exclusive_access_manager()->context()->GetActiveApplicationContents();
  if (IsFullscreenWithinTab(active_application_contents)) {
    active_application_contents->ExitFullscreen(
        /* will_cause_resize */ IsFullscreenCausedByTab());
    return true;
  }

  if (!IsWindowFullscreenForTabOrPending())
    return false;

  ExitExclusiveAccessIfNecessary();
  return true;
}

void FullscreenController::ExitExclusiveAccessToPreviousState() {
  if (IsWindowFullscreenForTabOrPending())
    ExitFullscreenModeForTab(exclusive_access_tab());
  else if (IsFullscreenForDock())
    ExitFullscreenModeInternal();
}

GURL FullscreenController::GetURLForExclusiveAccessBubble() const {
  if (exclusive_access_tab())
    return GetRequestingOrigin();
  return extension_caused_fullscreen_;
}

void FullscreenController::ExitExclusiveAccessIfNecessary() {
  if (IsWindowFullscreenForTabOrPending())
    ExitFullscreenModeForTab(exclusive_access_tab());
  else
    NotifyTabExclusiveAccessLost();
}

void FullscreenController::PostFullscreenChangeNotification(
    bool is_fullscreen) {
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::BindOnce(&FullscreenController::NotifyFullscreenChange,
                                ptr_factory_.GetWeakPtr(), is_fullscreen));
}

void FullscreenController::NotifyFullscreenChange(bool is_fullscreen) {
  NotificationService::current()->Notify(
      NOTIFICATION_FULLSCREEN_CHANGED,
      Source<FullscreenController>(this),
      Details<bool>(&is_fullscreen));
}

void FullscreenController::NotifyTabExclusiveAccessLost() {
  if (exclusive_access_tab()) {
    ApplicationContents* application_contents = exclusive_access_tab();
    SetTabWithExclusiveAccess(nullptr);
    fullscreened_origin_ = GURL();
    bool will_cause_resize = IsFullscreenCausedByTab();
    state_prior_to_tab_fullscreen_ = STATE_INVALID;
    tab_fullscreen_ = false;
    application_contents->ExitFullscreen(will_cause_resize);
    exclusive_access_manager()->UpdateExclusiveAccessExitBubbleContent(
        ExclusiveAccessBubbleHideCallback());
  }
}

void FullscreenController::RecordBubbleReshowsHistogram(
    int bubble_reshow_count) {
  UMA_HISTOGRAM_COUNTS_100(kFullscreenBubbleReshowsHistogramName,
                           bubble_reshow_count);
}

void FullscreenController::ToggleFullscreenModeInternal(
    FullscreenInternalOption option) {
  ExclusiveAccessContext* const exclusive_access_context =
      exclusive_access_manager()->context();
  bool enter_fullscreen = !exclusive_access_context->IsFullscreen();

  // In kiosk mode, we always want to be fullscreen. When the browser first
  // starts we're not yet fullscreen, so let the initial toggle go through.
  //if (chrome::IsRunningInAppMode() && exclusive_access_context->IsFullscreen())
  //  return;

  if (enter_fullscreen)
    EnterFullscreenModeInternal(option);
  else
    ExitFullscreenModeInternal();
}

void FullscreenController::EnterFullscreenModeInternal(
    FullscreenInternalOption option) {
  toggled_into_fullscreen_ = true;
  GURL url;
  if (option == TAB) {
    url = GetRequestingOrigin();
    tab_fullscreen_ = true;
  } else {
    if (!extension_caused_fullscreen_.is_empty())
      url = extension_caused_fullscreen_;
  }

  if (option == BROWSER)
    base::RecordAction(UserMetricsAction("ToggleFullscreen"));
  // TODO(scheib): Record metrics for WITH_TOOLBAR, without counting transitions
  // from tab fullscreen out to browser with toolbar.

  exclusive_access_manager()->context()->EnterFullscreen(
      url, exclusive_access_manager()->GetExclusiveAccessExitBubbleType());

  exclusive_access_manager()->UpdateExclusiveAccessExitBubbleContent(
      ExclusiveAccessBubbleHideCallback());

  // Once the window has become fullscreen it'll call back to
  // WindowFullscreenStateChanged(). We don't do this immediately as
  // DockWindow::EnterFullscreen() asks for bookmark_bar_state_, so we let
  // the DockWindow invoke WindowFullscreenStateChanged when appropriate.
}

void FullscreenController::ExitFullscreenModeInternal() {
  RecordExitingUMA();
  toggled_into_fullscreen_ = false;
#if defined(OS_MACOSX)
  // Mac windows report a state change instantly, and so we must also clear
  // state_prior_to_tab_fullscreen_ to match them else other logic using
  // state_prior_to_tab_fullscreen_ will be incorrect.
  NotifyTabExclusiveAccessLost();
#endif
  exclusive_access_manager()->context()->ExitFullscreen();
  extension_caused_fullscreen_ = GURL();

  exclusive_access_manager()->UpdateExclusiveAccessExitBubbleContent(
      ExclusiveAccessBubbleHideCallback());
}

bool FullscreenController::IsPrivilegedFullscreenForTab() const {
  const bool embedded_widget_present =
      exclusive_access_tab() &&
      exclusive_access_tab()->GetFullscreenApplicationWindowHostView();
  return embedded_widget_present || is_privileged_fullscreen_for_testing_;
}

void FullscreenController::SetPrivilegedFullscreenForTesting(
    bool is_privileged) {
  is_privileged_fullscreen_for_testing_ = is_privileged;
}

bool FullscreenController::MaybeToggleFullscreenWithinTab(
    ApplicationContents* application_contents,
    bool enter_fullscreen) {
  if (enter_fullscreen) {
    if (application_contents->IsBeingCaptured()
#if defined(OS_MACOSX)
        || base::FeatureList::IsEnabled(features::kContentFullscreen)
#endif
            ) {
      FullscreenWithinTabHelper::CreateForApplicationContents(application_contents);
      FullscreenWithinTabHelper::FromApplicationContents(application_contents)
          ->SetIsFullscreenWithinTab(true);
      return true;
    }
  } else {
    if (IsFullscreenWithinTab(application_contents)) {
      FullscreenWithinTabHelper::RemoveForApplicationContents(application_contents);
      return true;
    }
  }

  return false;
}

bool FullscreenController::IsFullscreenWithinTab(
    const ApplicationContents* application_contents) const {
  // Note: On Mac, some of the OnTabXXX() methods get called with a nullptr
  // value
  // for application_contents. Check for that here.
  const FullscreenWithinTabHelper* const helper =
      application_contents ? FullscreenWithinTabHelper::FromApplicationContents(application_contents)
                   : nullptr;
  if (helper && helper->is_fullscreen_within_tab()) {
    DCHECK_NE(exclusive_access_tab(), application_contents);
    return true;
  }
  return false;
}

GURL FullscreenController::GetRequestingOrigin() const {
  DCHECK(exclusive_access_tab());

  if (!fullscreened_origin_.is_empty())
    return fullscreened_origin_;

  return exclusive_access_tab()->GetLastCommittedURL();
}

GURL FullscreenController::GetEmbeddingOrigin() const {
  DCHECK(exclusive_access_tab());

  return exclusive_access_tab()->GetLastCommittedURL();
}

}