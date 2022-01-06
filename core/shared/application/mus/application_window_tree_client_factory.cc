// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/mus/application_window_tree_client_factory.h"

#include <stdint.h>

#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/sequenced_task_runner.h"
#include "base/threading/thread_task_runner_handle.h"
#include "core/shared/common/application_window_tree_client_factory.mojom.h"
#include "core/shared/common/connection_filter.h"
#include "core/shared/common/service_manager_connection.h"
#include "core/shared/application/mus/application_window_tree_client.h"
#include "mojo/public/cpp/bindings/binding_set.h"
#include "services/service_manager/public/cpp/service.h"
#include "services/ui/public/interfaces/window_tree.mojom.h"
#include "url/gurl.h"

namespace application {

namespace {

void BindMusConnectionOnMainThread(
    uint32_t routing_id,
    ui::mojom::WindowTreeClientRequest request,
    mojom::ApplicationWindowTreeClientRequest
        application_widget_window_tree_client_request) {
  ApplicationWindowTreeClient::CreateIfNecessary(routing_id);
  ApplicationWindowTreeClient::Get(routing_id)
      ->Bind(std::move(request),
             std::move(application_widget_window_tree_client_request));
}

// This object's lifetime is managed by ServiceManagerConnection because it's a
// registered with it.
class ApplicationWindowTreeClientFactoryImpl
    : public ConnectionFilter,
      public common::mojom::ApplicationWindowTreeClientFactory {
 public:
  ApplicationWindowTreeClientFactoryImpl() {
    main_thread_task_runner_ = base::ThreadTaskRunnerHandle::Get();
  }

  ~ApplicationWindowTreeClientFactoryImpl() override {}

 private:
  // ConnectionFilter implementation:
  void OnBindInterface(const service_manager::BindSourceInfo& source_info,
                       const std::string& interface_name,
                       mojo::ScopedMessagePipeHandle* interface_pipe,
                       service_manager::Connector* connector) override {
    if (interface_name == common::mojom::ApplicationWindowTreeClientFactory::Name_) {
      bindings_.AddBinding(this,
                           common::mojom::ApplicationWindowTreeClientFactoryRequest(
                               std::move(*interface_pipe)));
    }
  }

  // mojom::ApplicationWindowTreeClientFactory implementation.
  void CreateWindowTreeClientForApplicationWidget(
      uint32_t routing_id,
      ui::mojom::WindowTreeClientRequest request,
      common::mojom::ApplicationWindowTreeClientRequest
          application_widget_window_tree_client_request) override {
    main_thread_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&BindMusConnectionOnMainThread, routing_id,
                       std::move(request),
                       std::move(application_widget_window_tree_client_request)));
  }

  scoped_refptr<base::SequencedTaskRunner> main_thread_task_runner_;
  mojo::BindingSet<common::mojom::ApplicationWindowTreeClientFactory> bindings_;

  DISALLOW_COPY_AND_ASSIGN(ApplicationWindowTreeClientFactoryImpl);
};

}  // namespace

void CreateApplicationWindowTreeClientFactory(
    ServiceManagerConnection* connection) {
  connection->AddConnectionFilter(
      std::make_unique<ApplicationWindowTreeClientFactoryImpl>());
}

}  // namespace application
