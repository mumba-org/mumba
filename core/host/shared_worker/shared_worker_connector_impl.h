// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_SHARED_WORKER_SHARED_WORKER_CONNECTOR_IMPL_H_
#define CONTENT_BROWSER_SHARED_WORKER_SHARED_WORKER_CONNECTOR_IMPL_H_

#include "core/shared/common/content_export.h"
#include "core/shared/common/shared_worker/shared_worker_connector.mojom.h"
#include "core/host/service_worker/service_worker_type.h"

namespace host {

// Instances of this class live on the UI thread and have their lifetime bound
// to a Mojo connection.
class CONTENT_EXPORT SharedWorkerConnectorImpl
    : public common::mojom::SharedWorkerConnector {
 public:
  static void Create(ServiceWorkerProcessType process_type,
                     int process_id,
                     int frame_id,
                     common::mojom::SharedWorkerConnectorRequest request);

 private:
  SharedWorkerConnectorImpl(ServiceWorkerProcessType process_type, int process_id, int frame_id);

  // common::mojom::SharedWorkerConnector methods:
  void Connect(
      common::mojom::SharedWorkerInfoPtr info,
      common::mojom::SharedWorkerClientPtr client,
      blink::mojom::SharedWorkerCreationContextType creation_context_type,
      mojo::ScopedMessagePipeHandle message_port) override;
  const ServiceWorkerProcessType process_type_;
  const int process_id_;
  const int frame_id_;
};

}  // namespace host

#endif  // CONTENT_BROWSER_SHARED_WORKER_SHARED_WORKER_CONNECTOR_IMPL_H_
