// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_PLACE_DISPATCHER_H_
#define MUMBA_DOMAIN_PLACE_DISPATCHER_H_

#include "base/macros.h"

#include "core/shared/common/mojom/objects.mojom.h"
#include "core/shared/common/mojom/place.mojom.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"

namespace domain {

class PlaceDispatcher : public common::mojom::PlaceDispatcher {
public:
  PlaceDispatcher();
  ~PlaceDispatcher() override;

  void Bind(common::mojom::PlaceDispatcherAssociatedRequest request);

  void PlaceLoad(common::mojom::PlaceHandlePtr handle, const std::string& url, PlaceLoadCallback cb);
  void PlaceUnload(common::mojom::PlaceHandlePtr handle, const std::string& url, PlaceUnloadCallback cb);
  
private:
  //class Handler;

  mojo::AssociatedBinding<common::mojom::PlaceDispatcher> binding_;

  //scoped_refptr<Handler> handler_;

  base::WeakPtrFactory<PlaceDispatcher> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(PlaceDispatcher);
};

}

#endif