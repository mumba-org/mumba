// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/exclusive_access/keyboard_lock_controller.h"

#include "base/feature_list.h"
#include "base/metrics/histogram_macros.h"
#include "base/time/time.h"
#include "core/host/notification_types.h"
#include "core/host/ui/exclusive_access/exclusive_access_bubble_hide_callback.h"
#include "core/host/ui/exclusive_access/exclusive_access_manager.h"
#include "core/host/ui/exclusive_access/fullscreen_controller.h"
//#include "core/common/chrome_features.h"
#include "core/host/notification_service.h"
#include "core/host/application/native_web_keyboard_event.h"
#include "core/host/application/application_contents.h"
//#include "core/shared/common/content_features.h"
#include "ui/events/keycodes/keyboard_codes.h"

using base::TimeDelta;

namespace host {

namespace {

const char kBubbleReshowsHistogramName[] =
    "ExclusiveAccess.BubbleReshowsPerSession.KeyboardLock";

// Amount of time the user must hold ESC to exit full screen.
constexpr TimeDelta kHoldEscapeTime = TimeDelta::FromMilliseconds(1500);

bool IsExperimentalKeyboardLockUIEnabled() {
  //return base::FeatureList::IsEnabled(features::kExperimentalKeyboardLockUI);
  return true;
}

bool IsExperimentalKeyboardLockApiEnabled() {
  //return base::FeatureList::IsEnabled(features::kKeyboardLockAPI);
  return true;
}

}  // namespace

KeyboardLockController::KeyboardLockController(ExclusiveAccessManager* manager)
    : ExclusiveAccessControllerBase(manager) {}

KeyboardLockController::~KeyboardLockController() = default;

bool KeyboardLockController::HandleUserPressedEscape() {
  if (!IsKeyboardLockActive())
    return false;

  // TODO(joedow): Add a timer and counter to re-display the exit instructions
  // if the user rapidly presses the ESC key.

  UnlockKeyboard();
  return true;
}

void KeyboardLockController::ExitExclusiveAccessToPreviousState() {
  UnlockKeyboard();
}

void KeyboardLockController::ExitExclusiveAccessIfNecessary() {
  UnlockKeyboard();
}

void KeyboardLockController::NotifyTabExclusiveAccessLost() {
  UnlockKeyboard();
}

void KeyboardLockController::RecordBubbleReshowsHistogram(int reshow_count) {
  UMA_HISTOGRAM_COUNTS_100(kBubbleReshowsHistogramName, reshow_count);
}

bool KeyboardLockController::IsKeyboardLockActive() const {
  DCHECK_EQ(keyboard_lock_state_ == KeyboardLockState::kUnlocked,
            exclusive_access_tab() == nullptr);
  return keyboard_lock_state_ != KeyboardLockState::kUnlocked;
}

bool KeyboardLockController::RequiresPressAndHoldEscToExit() const {
  DCHECK_EQ(keyboard_lock_state_ == KeyboardLockState::kUnlocked,
            exclusive_access_tab() == nullptr);
  return IsExperimentalKeyboardLockUIEnabled() ||
         keyboard_lock_state_ == KeyboardLockState::kLockedWithEsc;
}

void KeyboardLockController::RequestKeyboardLock(ApplicationContents* application_contents,
                                                 bool esc_key_locked) {
  if (!IsExperimentalKeyboardLockApiEnabled() ||
      !exclusive_access_manager()
           ->fullscreen_controller()
           ->IsFullscreenForTabOrPending(application_contents)) {
    return;
  }

  DCHECK(!exclusive_access_tab() || exclusive_access_tab() == application_contents);

  LockKeyboard(application_contents, esc_key_locked);
}

bool KeyboardLockController::HandleKeyEvent(
    const NativeWebKeyboardEvent& event) {
  DCHECK_EQ(ui::VKEY_ESCAPE, event.windows_key_code);
  // This method handles the press and hold gesture used for exiting fullscreen.
  // If we don't have a feature which requires press and hold, or there isn't an
  // active keyboard lock request which requires press and hold, then we just
  // return as the simple 'press esc to exit' case is handled by the caller
  // (which is the ExclusiveAccessManager in this case).
  if (!RequiresPressAndHoldEscToExit())
    return false;

  // Note: This logic handles exiting fullscreen but the UI feedback element is
  // created and managed by the FullscreenControlHost class.
  if (event.GetType() == NativeWebKeyboardEvent::kKeyUp &&
      hold_timer_.IsRunning()) {
    // Seeing a key up event on Esc with the hold timer running cancels the
    // timer and doesn't exit. This means the user pressed Esc, but not long
    // enough to trigger an exit
    hold_timer_.Stop();
  } else if (event.GetType() == NativeWebKeyboardEvent::kRawKeyDown &&
             !hold_timer_.IsRunning()) {
    // Seeing a key down event on Esc when the hold timer is stopped starts
    // the timer. When the timer fires, the callback will trigger an exit from
    // fullscreen/mouselock/keyboardlock.
    hold_timer_.Start(
        FROM_HERE, kHoldEscapeTime,
        base::BindRepeating(&KeyboardLockController::HandleUserHeldEscape,
                            base::Unretained(this)));
  }

  return true;
}

void KeyboardLockController::CancelKeyboardLockRequest(ApplicationContents* tab) {
  if (tab == exclusive_access_tab())
    UnlockKeyboard();
}

void KeyboardLockController::LostKeyboardLock() {
  UnlockKeyboard();
}

void KeyboardLockController::LockKeyboard(ApplicationContents* application_contents,
                                          bool esc_key_locked) {
  if (fake_keyboard_lock_for_test_ ||
      application_contents->GotResponseToKeyboardLockRequest(true)) {
    KeyboardLockState new_lock_state =
        esc_key_locked ? KeyboardLockState::kLockedWithEsc
                       : KeyboardLockState::kLockedWithoutEsc;
    // Only re-show the exit bubble if the requesting application_contents has changed
    // (or is new) or if the esc key lock state has changed.
    bool reshow_exit_bubble = exclusive_access_tab() != application_contents ||
                              new_lock_state != keyboard_lock_state_;
    keyboard_lock_state_ = new_lock_state;
    SetTabWithExclusiveAccess(application_contents);
    if (reshow_exit_bubble) {
      exclusive_access_manager()->UpdateExclusiveAccessExitBubbleContent(
          bubble_hide_callback_for_test_
              ? base::BindOnce(bubble_hide_callback_for_test_)
              : ExclusiveAccessBubbleHideCallback());
    }
  } else {
    UnlockKeyboard();
  }
}

void KeyboardLockController::UnlockKeyboard() {
  if (!exclusive_access_tab())
    return;

  RecordExitingUMA();
  keyboard_lock_state_ = KeyboardLockState::kUnlocked;

  if (!fake_keyboard_lock_for_test_) {
    exclusive_access_tab()->GotResponseToKeyboardLockRequest(false);
  }

  SetTabWithExclusiveAccess(nullptr);
  exclusive_access_manager()->UpdateExclusiveAccessExitBubbleContent(
      ExclusiveAccessBubbleHideCallback());
}

void KeyboardLockController::HandleUserHeldEscape() {
  ExclusiveAccessManager* const manager = exclusive_access_manager();
  manager->fullscreen_controller()->HandleUserPressedEscape();
  manager->mouse_lock_controller()->HandleUserPressedEscape();
  HandleUserPressedEscape();
}

}