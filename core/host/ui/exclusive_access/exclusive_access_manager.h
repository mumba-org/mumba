// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_EXCLUSIVE_ACCESS_EXCLUSIVE_ACCESS_MANAGER_H_
#define CHROME_BROWSER_UI_EXCLUSIVE_ACCESS_EXCLUSIVE_ACCESS_MANAGER_H_

#include <memory>

#include "base/macros.h"
#include "core/host/ui/exclusive_access/exclusive_access_bubble_type.h"
#include "core/host/ui/exclusive_access/fullscreen_controller.h"
#include "core/host/ui/exclusive_access/keyboard_lock_controller.h"
#include "core/host/ui/exclusive_access/mouse_lock_controller.h"

class GURL;

namespace host {
struct NativeWebKeyboardEvent;
class ApplicationContents;
class ExclusiveAccessContext;
class FullscreenController;
class KeyboardLockController;
class MouseLockController;

// This class combines the different exclusive access modes (like fullscreen and
// mouse lock) which are each handled by respective controller. It also updates
// the exit bubble to reflect the combined state.
class ExclusiveAccessManager {
 public:
  explicit ExclusiveAccessManager(
      ExclusiveAccessContext* exclusive_access_context);
  ~ExclusiveAccessManager();

  FullscreenController* fullscreen_controller() {
    return &fullscreen_controller_;
  }

  KeyboardLockController* keyboard_lock_controller() {
    return &keyboard_lock_controller_;
  }

  MouseLockController* mouse_lock_controller() {
    return &mouse_lock_controller_;
  }

  ExclusiveAccessContext* context() const { return exclusive_access_context_; }

  ExclusiveAccessBubbleType GetExclusiveAccessExitBubbleType() const;
  void UpdateExclusiveAccessExitBubbleContent(
      ExclusiveAccessBubbleHideCallback);

  GURL GetExclusiveAccessBubbleURL() const;

  static bool IsSimplifiedFullscreenUIEnabled();

  // Callbacks ////////////////////////////////////////////////////////////////

  // Called by Browser::TabDeactivated.
  void OnTabDeactivated(ApplicationContents* application_contents);

  // Called by Browser::ActiveTabChanged.
  void OnTabDetachedFromView(ApplicationContents* application_contents);

  // Called by Browser::TabClosingAt.
  void OnTabClosing(ApplicationContents* application_contents);

  // Called by Browser::PreHandleKeyboardEvent.
  bool HandleUserKeyEvent(const NativeWebKeyboardEvent& event);

  // Called by Browser::ContentsMouseEvent.
  void OnUserInput();

  // Called by platform ExclusiveAccessExitBubble.
  void ExitExclusiveAccess();
  void RecordBubbleReshownUMA(ExclusiveAccessBubbleType type);

 private:
  ExclusiveAccessContext* const exclusive_access_context_;
  FullscreenController fullscreen_controller_;
  KeyboardLockController keyboard_lock_controller_;
  MouseLockController mouse_lock_controller_;

  DISALLOW_COPY_AND_ASSIGN(ExclusiveAccessManager);
};

}

#endif  // CHROME_BROWSER_UI_EXCLUSIVE_ACCESS_EXCLUSIVE_ACCESS_MANAGER_H_
