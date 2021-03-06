// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/screen_orientation/screen_orientation_provider.h"

#include <utility>

#include "base/callback_helpers.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/application_contents.h"
//#include "core/host/navigation_handle.h"
#include "core/host/screen_orientation/screen_orientation_delegate.h"

namespace host {

using device::mojom::ScreenOrientationLockResult;

ScreenOrientationDelegate* ScreenOrientationProvider::delegate_ = nullptr;

ScreenOrientationProvider::ScreenOrientationProvider(ApplicationContents* app_contents)
    : ApplicationContentsObserver(app_contents),
      lock_applied_(false),
      bindings_(app_contents, this) {
}

ScreenOrientationProvider::~ScreenOrientationProvider() {
  //DLOG(INFO) << "~ScreenOrientationProvider: " << this;
}

void ScreenOrientationProvider::LockOrientation(
    blink::WebScreenOrientationLockType orientation,
    LockOrientationCallback callback) {
  // Cancel any pending lock request.
  NotifyLockResult(ScreenOrientationLockResult::
                       SCREEN_ORIENTATION_LOCK_RESULT_ERROR_CANCELED);
  // Record new pending lock request.
  pending_callback_ = std::move(callback);

  if (!delegate_ || !delegate_->ScreenOrientationProviderSupported()) {
    NotifyLockResult(ScreenOrientationLockResult::
                         SCREEN_ORIENTATION_LOCK_RESULT_ERROR_NOT_AVAILABLE);
    return;
  }

  if (delegate_->FullScreenRequired(application_contents())) {
    ApplicationWindowHost* rvhi = application_contents()->GetApplicationWindowHost();    
    if (!rvhi) {
      NotifyLockResult(ScreenOrientationLockResult::
                           SCREEN_ORIENTATION_LOCK_RESULT_ERROR_CANCELED);
      return;
    }
    if (!application_contents()->IsFullscreen()) {
      NotifyLockResult(
          ScreenOrientationLockResult::
              SCREEN_ORIENTATION_LOCK_RESULT_ERROR_FULLSCREEN_REQUIRED);
      return;
    }
  }

  if (orientation == blink::kWebScreenOrientationLockNatural) {
    orientation = GetNaturalLockType();
    if (orientation == blink::kWebScreenOrientationLockDefault) {
      // We are in a broken state, let's pretend we got canceled.
      NotifyLockResult(ScreenOrientationLockResult::
                           SCREEN_ORIENTATION_LOCK_RESULT_ERROR_CANCELED);
      return;
    }
  }

  lock_applied_ = true;
  delegate_->Lock(application_contents(), orientation);

  // If the orientation we are locking to matches the current orientation, we
  // should succeed immediately.
  if (LockMatchesCurrentOrientation(orientation)) {
    NotifyLockResult(
        ScreenOrientationLockResult::SCREEN_ORIENTATION_LOCK_RESULT_SUCCESS);
    return;
  }

  pending_lock_orientation_ = orientation;
}

void ScreenOrientationProvider::UnlockOrientation() {
  // Cancel any pending lock request.
  NotifyLockResult(ScreenOrientationLockResult::
                       SCREEN_ORIENTATION_LOCK_RESULT_ERROR_CANCELED);

  if (!lock_applied_ || !delegate_)
    return;

  delegate_->Unlock(application_contents());

  lock_applied_ = false;
}

void ScreenOrientationProvider::OnOrientationChange() {
  if (!pending_lock_orientation_.has_value())
    return;

  if (LockMatchesCurrentOrientation(pending_lock_orientation_.value())) {
    DCHECK(!pending_callback_.is_null());
    NotifyLockResult(
        ScreenOrientationLockResult::SCREEN_ORIENTATION_LOCK_RESULT_SUCCESS);
  }
}

void ScreenOrientationProvider::NotifyLockResult(
    ScreenOrientationLockResult result) {
  if (!pending_callback_.is_null())
    base::ResetAndReturn(&pending_callback_).Run(result);

  pending_lock_orientation_.reset();
}

void ScreenOrientationProvider::SetDelegate(
    ScreenOrientationDelegate* delegate) {
  delegate_ = delegate;
}

void ScreenOrientationProvider::DidToggleFullscreenMode(
    bool entered_fullscreen,
    bool will_cause_resize) {
  if (!lock_applied_ || !delegate_)
    return;

  // If fullscreen is not required in order to lock orientation, don't unlock
  // when fullscreen state changes.
  if (!delegate_->FullScreenRequired(application_contents()))
    return;

  DCHECK(!entered_fullscreen);
  UnlockOrientation();
}

// void ScreenOrientationProvider::DidFinishNavigation(
//     NavigationHandle* navigation_handle) {
//   if (!navigation_handle->IsInMainFrame() ||
//       !navigation_handle->HasCommitted() ||
//       navigation_handle->IsSameDocument()) {
//     return;
//   }
//   UnlockOrientation();
// }

blink::WebScreenOrientationLockType
ScreenOrientationProvider::GetNaturalLockType() const {
  ApplicationWindowHost* rwh = application_contents()->GetApplicationWindowHost();
  if (!rwh)
    return blink::kWebScreenOrientationLockDefault;

  common::ScreenInfo screen_info;
  rwh->GetScreenInfo(&screen_info);

  switch (screen_info.orientation_type) {
    case common::SCREEN_ORIENTATION_VALUES_PORTRAIT_PRIMARY:
    case common::SCREEN_ORIENTATION_VALUES_PORTRAIT_SECONDARY:
      if (screen_info.orientation_angle == 0 ||
          screen_info.orientation_angle == 180) {
        return blink::kWebScreenOrientationLockPortraitPrimary;
      }
      return blink::kWebScreenOrientationLockLandscapePrimary;
    case common::SCREEN_ORIENTATION_VALUES_LANDSCAPE_PRIMARY:
    case common::SCREEN_ORIENTATION_VALUES_LANDSCAPE_SECONDARY:
      if (screen_info.orientation_angle == 0 ||
          screen_info.orientation_angle == 180) {
        return blink::kWebScreenOrientationLockLandscapePrimary;
      }
      return blink::kWebScreenOrientationLockPortraitPrimary;
    default:
      break;
  }

  NOTREACHED();
  return blink::kWebScreenOrientationLockDefault;
}

bool ScreenOrientationProvider::LockMatchesCurrentOrientation(
    blink::WebScreenOrientationLockType lock) {
  ApplicationWindowHost* rwh = application_contents()->GetApplicationWindowHost();
  if (!rwh)
    return false;

  common::ScreenInfo screen_info;
  rwh->GetScreenInfo(&screen_info);

  switch (lock) {
    case blink::kWebScreenOrientationLockPortraitPrimary:
      return screen_info.orientation_type ==
             common::SCREEN_ORIENTATION_VALUES_PORTRAIT_PRIMARY;
    case blink::kWebScreenOrientationLockPortraitSecondary:
      return screen_info.orientation_type ==
             common::SCREEN_ORIENTATION_VALUES_PORTRAIT_SECONDARY;
    case blink::kWebScreenOrientationLockLandscapePrimary:
      return screen_info.orientation_type ==
             common::SCREEN_ORIENTATION_VALUES_LANDSCAPE_PRIMARY;
    case blink::kWebScreenOrientationLockLandscapeSecondary:
      return screen_info.orientation_type ==
             common::SCREEN_ORIENTATION_VALUES_LANDSCAPE_SECONDARY;
    case blink::kWebScreenOrientationLockLandscape:
      return screen_info.orientation_type ==
                 common::SCREEN_ORIENTATION_VALUES_LANDSCAPE_PRIMARY ||
             screen_info.orientation_type ==
                 common::SCREEN_ORIENTATION_VALUES_LANDSCAPE_SECONDARY;
    case blink::kWebScreenOrientationLockPortrait:
      return screen_info.orientation_type ==
                 common::SCREEN_ORIENTATION_VALUES_PORTRAIT_PRIMARY ||
             screen_info.orientation_type ==
                 common::SCREEN_ORIENTATION_VALUES_PORTRAIT_SECONDARY;
    case blink::kWebScreenOrientationLockAny:
      return true;
    case blink::kWebScreenOrientationLockNatural:
    case blink::kWebScreenOrientationLockDefault:
      NOTREACHED();
      return false;
  }

  NOTREACHED();
  return false;
}

}  // namespace host
