// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/accessibility/browser_accessibility_auralinux.h"

#include "ui/accessibility/platform/ax_platform_node_auralinux.h"

namespace host {

BrowserAccessibilityAuraLinux* ToBrowserAccessibilityAuraLinux(
    BrowserAccessibility* obj) {
  DCHECK(!obj || obj->IsNative());
  return static_cast<BrowserAccessibilityAuraLinux*>(obj);
}

// static
BrowserAccessibility* BrowserAccessibility::Create() {
  return new BrowserAccessibilityAuraLinux();
}

BrowserAccessibilityAuraLinux::BrowserAccessibilityAuraLinux() {
  node_ = static_cast<ui::AXPlatformNodeAuraLinux*>(
      ui::AXPlatformNode::Create(this));
}

BrowserAccessibilityAuraLinux::~BrowserAccessibilityAuraLinux() {
  DCHECK(node_);
  node_->Destroy();
}

ui::AXPlatformNodeAuraLinux* BrowserAccessibilityAuraLinux::GetNode() const {
  return node_;
}

gfx::NativeViewAccessible
BrowserAccessibilityAuraLinux::GetNativeViewAccessible() {
  DCHECK(node_);
  return node_->GetNativeViewAccessible();
}

void BrowserAccessibilityAuraLinux::OnDataChanged() {
  BrowserAccessibility::OnDataChanged();

  DCHECK(node_);
  node_->DataChanged();
}

bool BrowserAccessibilityAuraLinux::IsNative() const {
  return true;
}

}  // namespace host
