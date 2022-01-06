// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/shared_worker/shared_worker_connector_impl.h"

#include "base/memory/ptr_util.h"
#include "core/host/shared_worker/shared_worker_service_impl.h"
//#include "core/host/storage_partition_impl.h"
//#include "core/host/browser_context.h"
#include "core/host/host_thread.h"
#include "core/host/application/domain.h"
#include "core/host/application/application_process_host.h"
#include "mojo/public/cpp/bindings/strong_binding.h"
#include "third_party/blink/public/common/message_port/message_port_channel.h"

namespace host {

// static
void SharedWorkerConnectorImpl::Create(
    ServiceWorkerProcessType process_type,
    int process_id,
    int frame_id,
    common::mojom::SharedWorkerConnectorRequest request) {
  mojo::MakeStrongBinding(
      base::WrapUnique(new SharedWorkerConnectorImpl(process_type, process_id, frame_id)),
      std::move(request));
}

SharedWorkerConnectorImpl::SharedWorkerConnectorImpl(ServiceWorkerProcessType process_type,
                                                     int process_id,
                                                     int frame_id)
    : process_type_(process_type), process_id_(process_id), frame_id_(frame_id) {}

void SharedWorkerConnectorImpl::Connect(
    common::mojom::SharedWorkerInfoPtr info,
    common::mojom::SharedWorkerClientPtr client,
    blink::mojom::SharedWorkerCreationContextType creation_context_type,
    mojo::ScopedMessagePipeHandle message_port) {
  SharedWorkerServiceImpl* service = nullptr;
  if (process_type_ == kPROCESS_TYPE_APPLICATION) {
    ApplicationProcessHost* host = ApplicationProcessHost::FromID(process_id_);
    // The render process was already terminated.
    if (!host) {
      client->OnScriptLoadFailed();
      return;
    }
    service = host->domain()->GetSharedWorkerService();
  } else {
    DomainProcessHost* host = DomainProcessHost::FromID(process_id_);
    if (!host) {
      client->OnScriptLoadFailed();
      return;
    }
    service = host->domain()->GetSharedWorkerService();
  }
  service->ConnectToWorker(process_type_, process_id_, frame_id_, std::move(info),
                           std::move(client), creation_context_type,
                           blink::MessagePortChannel(std::move(message_port)));
}

}  // namespace host
