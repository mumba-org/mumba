// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/web_modal/test_application_contents_modal_dialog_host.h"

#include "ui/gfx/geometry/point.h"

namespace web_modal {

TestApplicationContentsModalDialogHost::TestApplicationContentsModalDialogHost(
    gfx::NativeView host_view)
    : host_view_(host_view) {}

TestApplicationContentsModalDialogHost::~TestApplicationContentsModalDialogHost() {}

gfx::Size TestApplicationContentsModalDialogHost::GetMaximumDialogSize() {
  return max_dialog_size_;
}

gfx::NativeView TestApplicationContentsModalDialogHost::GetHostView() const {
  return host_view_;
}

gfx::Point TestApplicationContentsModalDialogHost::GetDialogPosition(
    const gfx::Size& size) {
  return gfx::Point();
}

void TestApplicationContentsModalDialogHost::AddObserver(
    ModalDialogHostObserver* observer) {}

void TestApplicationContentsModalDialogHost::RemoveObserver(
    ModalDialogHostObserver* observer) {}

}  // namespace web_modal
