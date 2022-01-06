// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_RENDERER_SHARED_WORKER_SHARED_WORKER_FACTORY_IMPL_H_
#define CONTENT_RENDERER_SHARED_WORKER_SHARED_WORKER_FACTORY_IMPL_H_

#include "base/macros.h"
#include "core/shared/common/service_worker/service_worker_provider.mojom.h"
#include "core/shared/common/shared_worker/shared_worker_factory.mojom.h"
#include "services/network/public/mojom/url_loader_factory.mojom.h"

namespace application {

class SharedWorkerFactoryImpl : public common::mojom::SharedWorkerFactory {
 public:
  static void Create(common::mojom::SharedWorkerFactoryRequest request);

 private:
  SharedWorkerFactoryImpl();

  // common::mojom::SharedWorkerFactory methods:
  void CreateSharedWorker(
      common::mojom::SharedWorkerInfoPtr info,
      bool pause_on_start,
      const base::UnguessableToken& devtools_worker_token,
      blink::mojom::WorkerContentSettingsProxyPtr content_settings,
      common::mojom::ServiceWorkerProviderInfoForSharedWorkerPtr
          service_worker_provider_info,
      network::mojom::URLLoaderFactoryAssociatedPtrInfo
          script_loader_factory_ptr_info,
      common::mojom::SharedWorkerHostPtr host,
      common::mojom::SharedWorkerRequest request,
      service_manager::mojom::InterfaceProviderPtr interface_provider) override;

  DISALLOW_COPY_AND_ASSIGN(SharedWorkerFactoryImpl);
};

}  // namespace content

#endif  // CONTENT_RENDERER_SHARED_WORKER_SHARED_WORKER_FACTORY_IMPL_H_
