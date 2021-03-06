// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/exclusive_access/exclusive_access_controller_base.h"

#include "core/host/notification_types.h"
#include "core/host/workspace/workspace.h"
#include "core/host/application/application_contents.h"
#include "core/host/ui/exclusive_access/exclusive_access_manager.h"
//#include "core/host/navigation_details.h"
//#include "core/host/navigation_entry.h"
#include "core/host/notification_service.h"

namespace host {

ExclusiveAccessControllerBase::ExclusiveAccessControllerBase(
    ExclusiveAccessManager* manager)
    : manager_(manager) {}

ExclusiveAccessControllerBase::~ExclusiveAccessControllerBase() {
}

GURL ExclusiveAccessControllerBase::GetExclusiveAccessBubbleURL() const {
  return manager_->GetExclusiveAccessBubbleURL();
}

GURL ExclusiveAccessControllerBase::GetURLForExclusiveAccessBubble() const {
  if (tab_with_exclusive_access_)
    return tab_with_exclusive_access_->GetURL();
  return GURL();
}

void ExclusiveAccessControllerBase::OnTabDeactivated(
    ApplicationContents* application_contents) {
  if (application_contents == tab_with_exclusive_access_)
    ExitExclusiveAccessIfNecessary();
}

void ExclusiveAccessControllerBase::OnTabDetachedFromView(
    ApplicationContents* old_contents) {
  // Derived class will have to implement if necessary.
}

void ExclusiveAccessControllerBase::OnTabClosing(ApplicationContents* application_contents) {
  if (application_contents == tab_with_exclusive_access_) {
    ExitExclusiveAccessIfNecessary();

    // The call to exit exclusive access may result in asynchronous notification
    // of state change (e.g. fullscreen change on Linux). We don't want to rely
    // on it to call NotifyTabExclusiveAccessLost(), because at that point
    // |tab_with_exclusive_access_| may not be valid. Instead, we call it here
    // to clean up exclusive access tab related state.
    NotifyTabExclusiveAccessLost();
  }
}

void ExclusiveAccessControllerBase::Observe(
    int type,
    const NotificationSource& source,
    const NotificationDetails& details) {
  DCHECK_EQ(NOTIFICATION_NAV_ENTRY_COMMITTED, type);
  //if (Details<LoadCommittedDetails>(details)
  //        ->is_navigation_to_different_page())
  //  ExitExclusiveAccessIfNecessary();
}

void ExclusiveAccessControllerBase::RecordBubbleReshownUMA() {
  ++bubble_reshow_count_;
}

void ExclusiveAccessControllerBase::RecordExitingUMA() {
  // Record the number of bubble reshows during this session. Only if simplified
  // fullscreen is enabled.
  if (ExclusiveAccessManager::IsSimplifiedFullscreenUIEnabled())
    RecordBubbleReshowsHistogram(bubble_reshow_count_);

  bubble_reshow_count_ = 0;
}

void ExclusiveAccessControllerBase::SetTabWithExclusiveAccess(
    ApplicationContents* tab) {
  // Tab should never be replaced with another tab, or
  // UpdateNotificationRegistrations would need updating.
  DCHECK(tab_with_exclusive_access_ == tab ||
         tab_with_exclusive_access_ == nullptr || tab == nullptr);
  tab_with_exclusive_access_ = tab;
  UpdateNotificationRegistrations();
}

void ExclusiveAccessControllerBase::UpdateNotificationRegistrations() {
  //if (tab_with_exclusive_access_ && registrar_.IsEmpty()) {
  //  registrar_.Add(this, NOTIFICATION_NAV_ENTRY_COMMITTED,
  //                 Source<NavigationController>(
  //                     &tab_with_exclusive_access_->GetController()));
  //} else if (!tab_with_exclusive_access_ && !registrar_.IsEmpty()) {
  //  registrar_.RemoveAll();
  //}

  if (!tab_with_exclusive_access_ && !registrar_.IsEmpty()) {
    registrar_.RemoveAll();
  }
}

}