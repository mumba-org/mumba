// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_PERSONA_MANAGER_CLIENT_H_
#define MUMBA_DOMAIN_PERSONA_MANAGER_CLIENT_H_

#include "base/macros.h"

#include "core/shared/common/mojom/objects.mojom.h"
#include "core/shared/common/mojom/identity.mojom.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"

namespace domain {

class IdentityManagerClient : public common::mojom::IdentityManagerClient {
public:
  IdentityManagerClient();
  ~IdentityManagerClient() override;

  void Bind(common::mojom::IdentityManagerClientAssociatedRequest request);
  void Noop() override;
  
private:
  //class Handler;

  mojo::AssociatedBinding<common::mojom::IdentityManagerClient> binding_;

  //scoped_refptr<Handler> handler_;

  base::WeakPtrFactory<IdentityManagerClient> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(IdentityManagerClient);
};

}

#endif