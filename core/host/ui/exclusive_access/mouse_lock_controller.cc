// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/exclusive_access/mouse_lock_controller.h"

#include "base/metrics/histogram_macros.h"
#include "core/host/notification_types.h"
#include "core/host/workspace/workspace.h"
#include "core/host/ui/dock.h"
#include "core/host/ui/exclusive_access/exclusive_access_context.h"
#include "core/host/ui/exclusive_access/exclusive_access_manager.h"
#include "core/host/ui/exclusive_access/fullscreen_controller.h"
#include "core/host/notification_service.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/application_window_host_view.h"
#include "core/host/application/application_contents.h"

namespace host {

namespace {

const char kMouseLockBubbleReshowsHistogramName[] =
    "ExclusiveAccess.BubbleReshowsPerSession.MouseLock";

}  // namespace

MouseLockController::MouseLockController(ExclusiveAccessManager* manager)
    : ExclusiveAccessControllerBase(manager),
      mouse_lock_state_(MOUSELOCK_UNLOCKED),
      fake_mouse_lock_for_test_(false),
      bubble_hide_callback_for_test_(),
      weak_ptr_factory_(this) {}

MouseLockController::~MouseLockController() {
}

bool MouseLockController::IsMouseLocked() const {
  return mouse_lock_state_ == MOUSELOCK_LOCKED ||
         mouse_lock_state_ == MOUSELOCK_LOCKED_SILENTLY;
}

bool MouseLockController::IsMouseLockedSilently() const {
  return mouse_lock_state_ == MOUSELOCK_LOCKED_SILENTLY;
}

void MouseLockController::RequestToLockMouse(ApplicationContents* application_contents,
                                             bool user_gesture,
                                             bool last_unlocked_by_target) {
  DCHECK(!IsMouseLocked());
  NotifyMouseLockChange();

  // Must have a user gesture to prevent misbehaving sites from constantly
  // re-locking the mouse. Exceptions are when the page has unlocked
  // (i.e. not the user), or if we're in tab fullscreen (user gesture required
  // for that)
  if (!last_unlocked_by_target && !user_gesture &&
      !exclusive_access_manager()
           ->fullscreen_controller()
           ->IsFullscreenForTabOrPending(application_contents)) {
    application_contents->GotResponseToLockMouseRequest(false);
    return;
  }
  SetTabWithExclusiveAccess(application_contents);

  // Lock mouse.
  if (fake_mouse_lock_for_test_ ||
      application_contents->GotResponseToLockMouseRequest(true)) {
    if (last_unlocked_by_target &&
        application_contents_granted_silent_mouse_lock_permission_ == application_contents) {
      mouse_lock_state_ = MOUSELOCK_LOCKED_SILENTLY;
    } else {
      mouse_lock_state_ = MOUSELOCK_LOCKED;
    }
  } else {
    SetTabWithExclusiveAccess(nullptr);
    mouse_lock_state_ = MOUSELOCK_UNLOCKED;
  }

  exclusive_access_manager()->UpdateExclusiveAccessExitBubbleContent(
      base::BindOnce(&MouseLockController::OnBubbleHidden,
                     weak_ptr_factory_.GetWeakPtr(), application_contents));
}

void MouseLockController::ExitExclusiveAccessIfNecessary() {
  NotifyTabExclusiveAccessLost();
}

void MouseLockController::NotifyTabExclusiveAccessLost() {
  ApplicationContents* tab = exclusive_access_tab();
  if (tab) {
    UnlockMouse();
    SetTabWithExclusiveAccess(nullptr);
    mouse_lock_state_ = MOUSELOCK_UNLOCKED;
    exclusive_access_manager()->UpdateExclusiveAccessExitBubbleContent(
        ExclusiveAccessBubbleHideCallback());
  }
}

void MouseLockController::RecordBubbleReshowsHistogram(
    int bubble_reshow_count) {
  UMA_HISTOGRAM_COUNTS_100(kMouseLockBubbleReshowsHistogramName,
                           bubble_reshow_count);
}

bool MouseLockController::HandleUserPressedEscape() {
  if (IsMouseLocked()) {
    ExitExclusiveAccessIfNecessary();
    return true;
  }

  return false;
}

void MouseLockController::ExitExclusiveAccessToPreviousState() {
  // Nothing to do for mouse lock.
}

void MouseLockController::LostMouseLock() {
  RecordExitingUMA();
  mouse_lock_state_ = MOUSELOCK_UNLOCKED;
  SetTabWithExclusiveAccess(nullptr);
  NotifyMouseLockChange();
  exclusive_access_manager()->UpdateExclusiveAccessExitBubbleContent(
      ExclusiveAccessBubbleHideCallback());
}

void MouseLockController::NotifyMouseLockChange() {
  NotificationService::current()->Notify(
      NOTIFICATION_MOUSE_LOCK_CHANGED,
      Source<MouseLockController>(this),
      NotificationService::NoDetails());
}

void MouseLockController::UnlockMouse() {
  ApplicationContents* tab = exclusive_access_tab();

  if (!tab)
    return;

  ApplicationWindowHostView* mouse_lock_view = nullptr;
  FullscreenController* fullscreen_controller =
      exclusive_access_manager()->fullscreen_controller();
  if ((fullscreen_controller->exclusive_access_tab() == tab) &&
      fullscreen_controller->IsPrivilegedFullscreenForTab()) {
    mouse_lock_view =
        exclusive_access_tab()->GetFullscreenApplicationWindowHostView();
  }

  if (!mouse_lock_view) {
    ApplicationWindowHost* const awh = exclusive_access_tab()->GetApplicationWindowHost();
    if (awh)
      mouse_lock_view = awh->GetView();
  }

  if (mouse_lock_view)
    mouse_lock_view->UnlockMouse();
}

void MouseLockController::OnBubbleHidden(
    ApplicationContents* application_contents,
    ExclusiveAccessBubbleHideReason reason) {
  if (bubble_hide_callback_for_test_)
    bubble_hide_callback_for_test_.Run(reason);

  // Allow silent mouse lock if the bubble has been display for a period of
  // time and dismissed due to timeout.
  if (reason == ExclusiveAccessBubbleHideReason::kTimeout)
    application_contents_granted_silent_mouse_lock_permission_ = application_contents;
}

}