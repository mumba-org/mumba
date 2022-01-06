// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/usb/web_usb_permission_provider.h"

#include <stddef.h>
#include <utility>

#include "base/stl_util.h"
#include "core/host/workspace/workspace.h"
#include "core/host/usb/usb_blocklist.h"
#include "core/host/usb/usb_chooser_context.h"
#include "core/host/usb/usb_chooser_context_factory.h"
#include "core/host/usb/usb_tab_helper.h"
#include "core/host/host_thread.h"
#include "core/host/application_window_host.h"
#include "core/host/application_contents.h"
#include "device/usb/usb_device.h"

namespace host {

// static
//bool WebUSBPermissionProvider::HasDevicePermission(
//    UsbChooserContext* chooser_context,
//    const GURL& requesting_origin,
//    const GURL& embedding_origin,
//    scoped_refptr<const device::UsbDevice> device) {
//  DCHECK_CURRENTLY_ON(HostThread::UI);

//  if (UsbBlocklist::Get().IsExcluded(device))
//    return false;

//  return chooser_context->HasDevicePermission(requesting_origin,
//                                              embedding_origin, device);
//}

WebUSBPermissionProvider::WebUSBPermissionProvider(
    ApplicationWindowHost* application_window_host)
    : application_window_host_(application_window_host), weak_factory_(this) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  DCHECK(application_window_host_);
}

WebUSBPermissionProvider::~WebUSBPermissionProvider() {}

base::WeakPtr<device::usb::PermissionProvider>
WebUSBPermissionProvider::GetWeakPtr() {
  return weak_factory_.GetWeakPtr();
}

bool WebUSBPermissionProvider::HasDevicePermission(
    scoped_refptr<const device::UsbDevice> device) const {
  DCHECK_CURRENTLY_ON(HostThread::UI);

  // ApplicationContents* application_contents =
  //     ApplicationContents::FromApplicationWindowHost(application_window_host_);
  // ApplicationWindowHost* main_frame = application_contents->GetMainFrame();
  // Workspace* workspace =
  //     Workspace::FromBrowserContext(application_contents->GetBrowserContext());

  // return HasDevicePermission(
  //     UsbChooserContextFactory::GetForWorkspace(workspace),
  //     application_window_host_->GetLastCommittedURL().GetOrigin(),
  //     main_frame->GetLastCommittedURL().GetOrigin(), device);
  return true;
}

void WebUSBPermissionProvider::IncrementConnectionCount() {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  ApplicationContents* application_contents =
      ApplicationContents::FromApplicationWindowHost(application_window_host_);
  UsbTabHelper* tab_helper = UsbTabHelper::FromApplicationContents(application_contents);
  tab_helper->IncrementConnectionCount(application_window_host_);
}

void WebUSBPermissionProvider::DecrementConnectionCount() {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  ApplicationContents* application_contents =
      ApplicationContents::FromApplicationWindowHost(application_window_host_);
  UsbTabHelper* tab_helper = UsbTabHelper::FromApplicationContents(application_contents);
  tab_helper->DecrementConnectionCount(application_window_host_);
}

}