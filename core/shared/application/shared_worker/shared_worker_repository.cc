// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/shared_worker/shared_worker_repository.h"

//#include "content/common/view_messages.h"
//#include "core/shared/application/application_frame_impl.h"
#include "url/gurl.h"
#include "services/service_manager/public/cpp/interface_provider.h"
#include "third_party/blink/public/web/web_shared_worker_connect_listener.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/public/common/message_port/message_port_channel.h"

namespace application {

SharedWorkerRepository::SharedWorkerRepository(
    service_manager::InterfaceProvider* interface_provider)
    : interface_provider_(interface_provider) {}

SharedWorkerRepository::~SharedWorkerRepository() = default;

void SharedWorkerRepository::Connect(
    const blink::WebURL& url,
    const blink::WebString& name,
    DocumentID document_id,
    const blink::WebString& content_security_policy,
    blink::WebContentSecurityPolicyType content_security_policy_type,
    blink::mojom::IPAddressSpace creation_address_space,
    blink::mojom::SharedWorkerCreationContextType creation_context_type,
    blink::MessagePortChannel channel,
    std::unique_ptr<blink::WebSharedWorkerConnectListener> listener) {
  // Lazy bind the connector.
  if (!connector_)
    interface_provider_->GetInterface(mojo::MakeRequest(&connector_));

  common::mojom::SharedWorkerInfoPtr info(common::mojom::SharedWorkerInfo::New(
      GURL(url.GetString().Utf8(), url.GetParsed(), url.IsValid()), 
      name.Utf8(), 
      content_security_policy.Utf8(),
      content_security_policy_type, creation_address_space));

  common::mojom::SharedWorkerClientPtr client;
  AddWorker(document_id,
            std::make_unique<SharedWorkerClientImpl>(std::move(listener)),
            mojo::MakeRequest(&client));

  connector_->Connect(std::move(info), std::move(client), creation_context_type,
                      channel.ReleaseHandle());
}

void SharedWorkerRepository::DocumentDetached(DocumentID document_id) {
  // Delete any associated SharedWorkerClientImpls, which will signal, via the
  // dropped mojo connection, disinterest in the associated shared worker.
  client_map_.erase(document_id);
}

void SharedWorkerRepository::AddWorker(
    DocumentID document_id,
    std::unique_ptr<common::mojom::SharedWorkerClient> impl,
    common::mojom::SharedWorkerClientRequest request) {
  std::pair<ClientMap::iterator, bool> result =
      client_map_.emplace(document_id, nullptr);
  std::unique_ptr<ClientSet>& clients = result.first->second;
  if (!clients)
    clients = std::make_unique<ClientSet>();
  clients->AddBinding(std::move(impl), std::move(request));
}

}  // namespace content
