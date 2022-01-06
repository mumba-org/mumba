// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/dock_constrained_window_views_client.h"

#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "core/host/ui/dock_finder.h"
#include "core/host/ui/dock.h"
#include "core/host/ui/platform_util.h"
#include "components/web_modal/application_contents_modal_dialog_host.h"
#include "components/web_modal/application_contents_modal_dialog_manager_delegate.h"

namespace host {

namespace {

class DockConstrainedWindowViewsClient
    : public constrained_window::ConstrainedWindowViewsClient {
 public:
  DockConstrainedWindowViewsClient() {}
  ~DockConstrainedWindowViewsClient() override {}

 private:
  // ConstrainedWindowViewsClient:
  web_modal::ModalDialogHost* GetModalDialogHost(
      gfx::NativeWindow parent) override {
    // Get the browser dialog management and hosting components from |parent|.
    Dock* dock = FindDockWithWindow(parent);
    if (dock) {
      //DockWebModalDialogManagerDelegate* manager = dock;
      DockApplicationModalDialogManagerDelegate* manager = static_cast<DockApplicationModalDialogManagerDelegate*>(dock);
      return manager->GetApplicationContentsModalDialogHost();
    }
    return nullptr;
  }
  gfx::NativeView GetDialogHostView(gfx::NativeWindow parent) override {
    return platform_util::GetViewForWindow(parent);
  }

  DISALLOW_COPY_AND_ASSIGN(DockConstrainedWindowViewsClient);
};

}  // namespace

std::unique_ptr<constrained_window::ConstrainedWindowViewsClient>
CreateDockConstrainedWindowViewsClient() {
  return base::WrapUnique(new DockConstrainedWindowViewsClient);
}

}