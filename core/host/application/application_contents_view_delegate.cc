// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/application_contents_view_delegate.h"

#include <stddef.h>

namespace host {

ApplicationContentsViewDelegate::~ApplicationContentsViewDelegate() {
}

gfx::NativeWindow ApplicationContentsViewDelegate::GetNativeWindow() {
  return nullptr;
}

ApplicationDragDestDelegate* ApplicationContentsViewDelegate::GetDragDestDelegate() {
  return nullptr;
}

void ApplicationContentsViewDelegate::ShowContextMenu(
    //RenderFrameHost* render_frame_host,
  ApplicationWindowHost* application_window_host,
    const common::ContextMenuParams& params) {
}

void ApplicationContentsViewDelegate::StoreFocus() {
}

bool ApplicationContentsViewDelegate::RestoreFocus() {
  return false;
}

void ApplicationContentsViewDelegate::ResetStoredFocus() {}

bool ApplicationContentsViewDelegate::Focus() {
  return false;
}

bool ApplicationContentsViewDelegate::TakeFocus(bool reverse) {
  return false;
}

void* ApplicationContentsViewDelegate::CreateApplicationWindowHostViewDelegate(
    ApplicationWindowHost* application_window_host,
    bool is_popup) {
  return nullptr;
}

}  // namespace host
