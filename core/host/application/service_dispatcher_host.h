// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_SERVICE_DISPATCHER_HOST_H_
#define MUMBA_HOST_APPLICATION_SERVICE_DISPATCHER_HOST_H_

#include "base/macros.h"
#include "core/shared/common/mojom/service.mojom.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "mojo/public/cpp/bindings/associated_binding_set.h"
#include "mojo/public/cpp/bindings/interface_ptr.h"

namespace host {

class ServiceDispatcherHost : public common::mojom::ServiceDispatcherClient {
public:
  ServiceDispatcherHost();
  ~ServiceDispatcherHost() override;
  
  common::mojom::ServiceDispatcher* GetServiceDispatcherInterface();

  void AddBinding(common::mojom::ServiceDispatcherClientAssociatedRequest request);

  void BindService(common::mojom::ServiceBindRequestPtr request, BindServiceCallback callback);
 
private:
  friend class DomainProcessHost;
  
  common::mojom::ServiceDispatcherAssociatedPtr service_dispatcher_interface_;
  mojo::AssociatedBinding<common::mojom::ServiceDispatcherClient> service_dispatcher_host_binding_;

  DISALLOW_COPY_AND_ASSIGN(ServiceDispatcherHost);
};

}

#endif