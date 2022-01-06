// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_SHARED_WORKER_MOCK_SHARED_WORKER_H_
#define CONTENT_BROWSER_SHARED_WORKER_MOCK_SHARED_WORKER_H_

#include <memory>
#include <queue>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "base/macros.h"
#include "core/host/shared_worker/shared_worker_host.h"
#include "core/shared/common/service_worker/service_worker_provider.mojom.h"
#include "core/shared/common/shared_worker/shared_worker_factory.mojom.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "third_party/blink/public/common/message_port/message_port_channel.h"

class GURL;

namespace host {

class MockSharedWorker : public common::mojom::SharedWorker {
 public:
  explicit MockSharedWorker(common::mojom::SharedWorkerRequest request);
  ~MockSharedWorker() override;

  bool CheckReceivedConnect(int* connection_request_id,
                            blink::MessagePortChannel* port);
  bool CheckNotReceivedConnect();
  bool CheckReceivedTerminate();

 private:
  // common::mojom::SharedWorker methods:
  void Connect(int connection_request_id,
               mojo::ScopedMessagePipeHandle port) override;
  void Terminate() override;
  void BindDevToolsAgent(
      blink::mojom::DevToolsAgentAssociatedRequest request) override;

  mojo::Binding<common::mojom::SharedWorker> binding_;
  std::queue<std::pair<int, blink::MessagePortChannel>> connect_received_;
  bool terminate_received_ = false;

  DISALLOW_COPY_AND_ASSIGN(MockSharedWorker);
};

class MockSharedWorkerFactory : public common::mojom::SharedWorkerFactory {
 public:
  explicit MockSharedWorkerFactory(common::mojom::SharedWorkerFactoryRequest request);
  ~MockSharedWorkerFactory() override;

  bool CheckReceivedCreateSharedWorker(
      const GURL& expected_url,
      const std::string& expected_name,
      blink::WebContentSecurityPolicyType expected_content_security_policy_type,
      common::mojom::SharedWorkerHostPtr* host,
      common::mojom::SharedWorkerRequest* request);

 private:
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

  struct CreateParams {
    CreateParams();
    ~CreateParams();
    common::mojom::SharedWorkerInfoPtr info;
    bool pause_on_start;
    blink::mojom::WorkerContentSettingsProxyPtr content_settings;
    common::mojom::SharedWorkerHostPtr host;
    common::mojom::SharedWorkerRequest request;
    service_manager::mojom::InterfaceProviderPtr interface_provider;
  };

  mojo::Binding<common::mojom::SharedWorkerFactory> binding_;
  std::unique_ptr<CreateParams> create_params_;

  DISALLOW_COPY_AND_ASSIGN(MockSharedWorkerFactory);
};

class MockSharedWorkerClient : public common::mojom::SharedWorkerClient {
 public:
  MockSharedWorkerClient();
  ~MockSharedWorkerClient() override;

  void Bind(common::mojom::SharedWorkerClientRequest request);
  void Close();
  bool CheckReceivedOnCreated();
  bool CheckReceivedOnConnected(
      std::set<blink::mojom::WebFeature> expected_used_features);
  bool CheckReceivedOnFeatureUsed(blink::mojom::WebFeature expected_feature);
  bool CheckNotReceivedOnFeatureUsed();
  bool CheckReceivedOnScriptLoadFailed();

 private:
  // common::mojom::SharedWorkerClient methods:
  void OnCreated(blink::mojom::SharedWorkerCreationContextType
                     creation_context_type) override;
  void OnConnected(
      const std::vector<blink::mojom::WebFeature>& features_used) override;
  void OnScriptLoadFailed() override;
  void OnFeatureUsed(blink::mojom::WebFeature feature) override;

  mojo::Binding<common::mojom::SharedWorkerClient> binding_;
  bool on_created_received_ = false;
  bool on_connected_received_ = false;
  std::set<blink::mojom::WebFeature> on_connected_features_;
  bool on_feature_used_received_ = false;
  blink::mojom::WebFeature on_feature_used_feature_ =
      blink::mojom::WebFeature();
  bool on_script_load_failed_ = false;

  DISALLOW_COPY_AND_ASSIGN(MockSharedWorkerClient);
};

}  // namespace host

#endif  // CONTENT_BROWSER_SHARED_WORKER_MOCK_SHARED_WORKER_H_
