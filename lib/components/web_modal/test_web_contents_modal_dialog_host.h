// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_WEB_MODAL_TEST_APPLICATION_CONTENTS_MODAL_DIALOG_HOST_H_
#define COMPONENTS_WEB_MODAL_TEST_APPLICATION_CONTENTS_MODAL_DIALOG_HOST_H_

#include "components/web_modal/application_contents_modal_dialog_host.h"

#include "base/compiler_specific.h"
#include "base/macros.h"
#include "ui/gfx/geometry/size.h"
#include "ui/gfx/native_widget_types.h"

namespace web_modal {

class TestApplicationContentsModalDialogHost : public ApplicationContentsModalDialogHost {
 public:
  explicit TestApplicationContentsModalDialogHost(gfx::NativeView host_view);
  ~TestApplicationContentsModalDialogHost() override;

  // ApplicationContentsModalDialogHost:
  gfx::Size GetMaximumDialogSize() override;
  gfx::NativeView GetHostView() const override;
  gfx::Point GetDialogPosition(const gfx::Size& size) override;
  void AddObserver(ModalDialogHostObserver* observer) override;
  void RemoveObserver(ModalDialogHostObserver* observer) override;

  void set_max_dialog_size(const gfx::Size& max_dialog_size) {
    max_dialog_size_ = max_dialog_size;
  }

 private:
  gfx::NativeView host_view_;
  gfx::Size max_dialog_size_;

  DISALLOW_COPY_AND_ASSIGN(TestApplicationContentsModalDialogHost);
};

}  // namespace web_modal

#endif  // COMPONENTS_WEB_MODAL_TEST_APPLICATION_CONTENTS_MODAL_DIALOG_HOST_H_
