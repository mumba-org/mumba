// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/usb/web_usb_chooser_service.h"

#include <utility>

#include "core/host/workspaces/workspace.h"
#include "core/host/usb/usb_chooser_context.h"
#include "core/host/usb/usb_chooser_context_factory.h"
#include "core/host/usb/usb_chooser_controller.h"
#include "core/host/host_thread.h"
#include "core/host/application_window_host.h"
#include "core/host/application_contents.h"

namespace host {

WebUsbChooserService::WebUsbChooserService(
    ApplicationWindowHost* application_window_host)
    : application_window_host_(application_window_host) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  DCHECK(application_window_host);
}

WebUsbChooserService::~WebUsbChooserService() {}

void WebUsbChooserService::GetPermission(
    std::vector<device::mojom::UsbDeviceFilterPtr> device_filters,
    GetPermissionCallback callback) {
  auto* application_contents =
      ApplicationContents::FromApplicationWindowHost(application_window_host_);
  GURL requesting_origin =
      application_window_host_->GetLastCommittedURL().GetOrigin();
  GURL embedding_origin =
      application_contents->GetMainFrame()->GetLastCommittedURL().GetOrigin();
  auto* workspace =
      Workspace::FromBrowserContext(application_contents->GetBrowserContext());
  auto* context = UsbChooserContextFactory::GetForWorkspace(workspace);
  if (!context->CanRequestObjectPermission(requesting_origin,
                                           embedding_origin)) {
    std::move(callback).Run(nullptr);
    return;
  }

  auto controller = std::make_unique<UsbChooserController>(
      application_window_host_, std::move(device_filters), std::move(callback));
  ShowChooser(std::move(controller));
}

void WebUsbChooserService::Bind(
    device::mojom::UsbChooserServiceRequest request) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  bindings_.AddBinding(this, std::move(request));
}

}