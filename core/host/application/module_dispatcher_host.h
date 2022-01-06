// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_MODULE_DISPATCHER_HOST_H_
#define MUMBA_HOST_APPLICATION_MODULE_DISPATCHER_HOST_H_

#include "base/macros.h"
#include "core/shared/common/mojom/module.mojom.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "mojo/public/cpp/bindings/associated_binding_set.h"
#include "mojo/public/cpp/bindings/interface_ptr.h"

namespace host {

class ModuleDispatcherHost : public common::mojom::ModuleDispatcherHost {
public:
 ModuleDispatcherHost();
 ~ModuleDispatcherHost() override;

 common::mojom::ModuleDispatcher* GetModuleDispatcherInterface();

 void AddBinding(common::mojom::ModuleDispatcherHostAssociatedRequest request);

 void Noop() override;
 
private:
  friend class DomainProcessHost;
  common::mojom::ModuleDispatcherAssociatedPtr module_dispatcher_interface_;
  mojo::AssociatedBinding<common::mojom::ModuleDispatcherHost> module_dispatcher_host_binding_;

  DISALLOW_COPY_AND_ASSIGN(ModuleDispatcherHost);
};

}

#endif