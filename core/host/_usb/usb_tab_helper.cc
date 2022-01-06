// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/usb/usb_tab_helper.h"

#include <memory>
#include <utility>

#include "core/host/ui/browser_finder.h"
#include "core/host/ui/tabs/tab_strip_model.h"
#include "core/host/usb/web_usb_permission_provider.h"
#include "core/host/application_window_host.h"
#include "core/commoncontent_features.h"
#include "device/usb/mojo/device_manager_impl.h"
#include "mojo/public/cpp/bindings/message.h"
#include "third_party/blink/public/mojom/feature_policy/feature_policy.mojom.h"

#if defined(OS_ANDROID)
#include "core/host/android/usb/web_usb_chooser_service_android.h"
#else
#include "core/host/usb/web_usb_chooser_service_desktop.h"
#endif  // defined(OS_ANDROID)

using ApplicationWindowHost;
using ApplicationContents;

namespace host {

namespace {

// The renderer performs its own feature policy checks so a request that gets
// to the browser process indicates malicous code.
const char kFeaturePolicyViolation[] =
    "Feature policy blocks access to WebUSB.";

}  // namespace

DEFINE_WEB_CONTENTS_USER_DATA_KEY(UsbTabHelper);

struct FrameUsbServices {
  std::unique_ptr<WebUSBPermissionProvider> permission_provider;
#if defined(OS_ANDROID)
  std::unique_ptr<WebUsbChooserServiceAndroid> chooser_service;
#else
  std::unique_ptr<WebUsbChooserServiceDesktop> chooser_service;
#endif  // defined(OS_ANDROID)
  int device_connection_count_ = 0;
};

// static
UsbTabHelper* UsbTabHelper::GetOrCreateForApplicationContents(
    ApplicationContents* application_contents) {
  UsbTabHelper* tab_helper = FromApplicationContents(application_contents);
  if (!tab_helper) {
    CreateForApplicationContents(application_contents);
    tab_helper = FromApplicationContents(application_contents);
  }
  return tab_helper;
}

UsbTabHelper::~UsbTabHelper() {
  //DLOG(INFO) << "~UsbTabHelper: " << this;
}

void UsbTabHelper::CreateDeviceManager(
    ApplicationWindowHost* application_window_host,
    mojo::InterfaceRequest<device::mojom::UsbDeviceManager> request) {
  if (!AllowedByFeaturePolicy(application_window_host)) {
    mojo::ReportBadMessage(kFeaturePolicyViolation);
    return;
  }
  device::usb::DeviceManagerImpl::Create(
      GetPermissionProvider(application_window_host), std::move(request));
}

void UsbTabHelper::CreateChooserService(
    ApplicationWindowHost* application_window_host,
    mojo::InterfaceRequest<device::mojom::UsbChooserService> request) {
  if (!AllowedByFeaturePolicy(application_window_host)) {
    mojo::ReportBadMessage(kFeaturePolicyViolation);
    return;
  }
  GetChooserService(application_window_host, std::move(request));
}

void UsbTabHelper::IncrementConnectionCount(
    ApplicationWindowHost* application_window_host) {
  auto it = frame_usb_services_.find(application_window_host);
  DCHECK(it != frame_usb_services_.end());
  it->second->device_connection_count_++;
  NotifyTabStateChanged();
}

void UsbTabHelper::DecrementConnectionCount(
    ApplicationWindowHost* application_window_host) {
  auto it = frame_usb_services_.find(application_window_host);
  DCHECK(it != frame_usb_services_.end());
  DCHECK_GT(it->second->device_connection_count_, 0);
  it->second->device_connection_count_--;
  NotifyTabStateChanged();
}

bool UsbTabHelper::IsDeviceConnected() const {
  for (const auto& map_entry : frame_usb_services_) {
    if (map_entry.second->device_connection_count_ > 0)
      return true;
  }
  return false;
}

UsbTabHelper::UsbTabHelper(ApplicationContents* application_contents)
    : ApplicationContentsObserver(application_contents) {

  DLOG(INFO) << "UsbTabHelper: " << this;
}

void UsbTabHelper::ApplicationWindowDeleted(ApplicationWindowHost* application_window_host) {
  frame_usb_services_.erase(application_window_host);
  NotifyTabStateChanged();
}

FrameUsbServices* UsbTabHelper::GetFrameUsbService(
    ApplicationWindowHost* application_window_host) {
  FrameUsbServicesMap::const_iterator it =
      frame_usb_services_.find(application_window_host);
  if (it == frame_usb_services_.end()) {
    std::unique_ptr<FrameUsbServices> frame_usb_services(
        new FrameUsbServices());
    it = (frame_usb_services_.insert(
              std::make_pair(application_window_host, std::move(frame_usb_services))))
             .first;
  }
  return it->second.get();
}

base::WeakPtr<device::usb::PermissionProvider>
UsbTabHelper::GetPermissionProvider(ApplicationWindowHost* application_window_host) {
  FrameUsbServices* frame_usb_services = GetFrameUsbService(application_window_host);
  if (!frame_usb_services->permission_provider) {
    frame_usb_services->permission_provider.reset(
        new WebUSBPermissionProvider(application_window_host));
  }
  return frame_usb_services->permission_provider->GetWeakPtr();
}

void UsbTabHelper::GetChooserService(
    ApplicationWindowHost* application_window_host,
    mojo::InterfaceRequest<device::mojom::UsbChooserService> request) {
  FrameUsbServices* frame_usb_services = GetFrameUsbService(application_window_host);
  if (!frame_usb_services->chooser_service) {
    frame_usb_services->chooser_service.reset(
#if defined(OS_ANDROID)
        new WebUsbChooserServiceAndroid(application_window_host));
#else
        new WebUsbChooserServiceDesktop(application_window_host));
#endif  // defined(OS_ANDROID)
  }
  frame_usb_services->chooser_service->Bind(std::move(request));
}

void UsbTabHelper::NotifyTabStateChanged() const {
  // TODO(https://crbug.com/601627): Implement tab indicator for Android.
#if !defined(OS_ANDROID)
  Browser* browser = chrome::FindBrowserWithApplicationContents(application_contents());
  if (browser) {
    TabStripModel* tab_strip_model = browser->tab_strip_model();
    tab_strip_model->UpdateApplicationContentsStateAt(
        tab_strip_model->GetIndexOfApplicationContents(application_contents()),
        TabChangeType::kAll);
  }
#endif
}

bool UsbTabHelper::AllowedByFeaturePolicy(
    ApplicationWindowHost* application_window_host) const {
  DCHECK(ApplicationContents::FromApplicationWindowHost(application_window_host) == application_contents());
  return application_window_host->IsFeatureEnabled(
      blink::mojom::FeaturePolicyFeature::kUsb);
}

}