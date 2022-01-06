// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_DEVICE_DISPATCHER_HOST_H_
#define MUMBA_HOST_APPLICATION_DEVICE_DISPATCHER_HOST_H_

#include "base/macros.h"
#include "core/shared/common/mojom/device.mojom.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "mojo/public/cpp/bindings/associated_binding_set.h"
#include "mojo/public/cpp/bindings/interface_ptr.h"

namespace host {

class DeviceDispatcherHost  : public common::mojom::DeviceDispatcherHost {
public:
  DeviceDispatcherHost();
 ~DeviceDispatcherHost() override;

 common::mojom::DeviceManager* GetDeviceManagerInterface();

 void AddBinding(common::mojom::DeviceDispatcherHostAssociatedRequest request);

 void Noop() override;

private:
  friend class DomainProcessHost;
  common::mojom::DeviceManagerAssociatedPtr device_interface_;
  mojo::AssociatedBinding<common::mojom::DeviceDispatcherHost> device_host_binding_;

  DISALLOW_COPY_AND_ASSIGN(DeviceDispatcherHost);
};

}

#endif