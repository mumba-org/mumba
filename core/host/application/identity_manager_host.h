// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_PERSONA_MANAGER_HOST_H_
#define MUMBA_HOST_APPLICATION_PERSONA_MANAGER_HOST_H_

#include "base/macros.h"
#include "core/shared/common/mojom/identity.mojom.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "mojo/public/cpp/bindings/associated_binding_set.h"
#include "mojo/public/cpp/bindings/interface_ptr.h"

namespace host {

class IdentityManagerHost : public common::mojom::IdentityManagerHost {
public:
  IdentityManagerHost();
  ~IdentityManagerHost() override;
  
  common::mojom::IdentityManagerClient* GetIdentityManagerClientInterface();

  void AddBinding(common::mojom::IdentityManagerHostAssociatedRequest request);
  
  void IdentityList(IdentityListCallback callback) override;
  void IdentityGet(const std::string& uuid, IdentityGetCallback callback) override;

private:
  friend class DomainProcessHost;
  
  common::mojom::IdentityManagerClientAssociatedPtr identity_manager_client_interface_;
  mojo::AssociatedBinding<common::mojom::IdentityManagerHost> identity_manager_host_binding_;

  DISALLOW_COPY_AND_ASSIGN(IdentityManagerHost);
};

}

#endif