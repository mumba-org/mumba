// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_USB_USB_TAB_HELPER_H_
#define CHROME_BROWSER_USB_USB_TAB_HELPER_H_

#include <map>

#include "base/macros.h"
#include "core/host/application/application_contents_observer.h"
#include "core/host/application/application_contents_user_data.h"
#include "mojo/public/cpp/bindings/interface_request.h"

namespace device {
namespace mojom {
class UsbChooserService;
class UsbDeviceManager;
}

namespace usb {
class PermissionProvider;
}
}

namespace host {
struct FrameUsbServices;

typedef std::map<ApplicationWindowHost*, std::unique_ptr<FrameUsbServices>>
    FrameUsbServicesMap;

// Per-tab owner of USB services provided to render frames within that tab.
class UsbTabHelper : public ApplicationContentsObserver,
                     public ApplicationContentsUserData<UsbTabHelper> {
 public:
  static UsbTabHelper* GetOrCreateForApplicationContents(
      ApplicationContents* application_contents);

  ~UsbTabHelper() override;

  void CreateDeviceManager(
      ApplicationWindowHost* application_window_host,
      mojo::InterfaceRequest<device::mojom::UsbDeviceManager> request);

  void CreateChooserService(
      ApplicationWindowHost* application_window_host,
      mojo::InterfaceRequest<device::mojom::UsbChooserService> request);

  void IncrementConnectionCount(ApplicationWindowHost* application_window_host);
  void DecrementConnectionCount(ApplicationWindowHost* application_window_host);
  bool IsDeviceConnected() const;

 private:
  explicit UsbTabHelper(ApplicationContents* application_contents);
  friend class ApplicationContentsUserData<UsbTabHelper>;

  // ApplicationContentsObserver overrides:
  void ApplicationWindowDeleted(ApplicationWindowHost* application_window_host) override;

  FrameUsbServices* GetFrameUsbService(
      ApplicationWindowHost* application_window_host);

  base::WeakPtr<device::usb::PermissionProvider> GetPermissionProvider(
      ApplicationWindowHost* application_window_host);

  void GetChooserService(
      ApplicationWindowHost* application_window_host,
      mojo::InterfaceRequest<device::mojom::UsbChooserService> request);

  void NotifyTabStateChanged() const;

  bool AllowedByFeaturePolicy(
      ApplicationWindowHost* application_window_host) const;

  FrameUsbServicesMap frame_usb_services_;

  DISALLOW_COPY_AND_ASSIGN(UsbTabHelper);
};

}

#endif  // CHROME_BROWSER_USB_USB_TAB_HELPER_H_
