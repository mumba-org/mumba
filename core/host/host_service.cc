// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/host_service.h"

#include "base/no_destructor.h"
#include "core/shared/common/mojom/constants.mojom.h"
//#include "components/spellcheck/spellcheck_buildflags.h"
//#include "components/startup_metric_utils/browser/startup_metric_host_impl.h"
#include "core/host/host_thread.h"
#include "core/host/host_client.h"
#include "core/shared/common/client.h"
#include "core/shared/common/service_manager_connection.h"
#include "services/service_manager/public/cpp/binder_registry.h"
#include "services/service_manager/public/cpp/connector.h"
#include "services/service_manager/public/cpp/service.h"
#include "services/service_manager/public/cpp/service_context.h"

//#if defined(USE_OZONE)
//#include "services/ui/public/cpp/input_devices/input_device_controller.h"
//#endif

namespace host {

class HostService::IOThreadContext : public service_manager::Service {
 public:
  IOThreadContext() {
    //scoped_refptr<base::SingleThreadTaskRunner> ui_task_runner =
    //    HostThread::GetTaskRunnerForThread(
    //        HostThread::UI);

// #if defined(OS_CHROMEOS)
// #if defined(USE_OZONE)
//     input_device_controller_.AddInterface(&registry_, ui_task_runner);
// #endif
//     registry_.AddInterface(base::BindRepeating(&chromeos::Launchable::Bind,
//                                                base::Unretained(&launchable_)),
//                            ui_task_runner);
// #endif
//     registry_.AddInterface(base::BindRepeating(
//         &startup_metric_utils::StartupMetricHostImpl::Create));
// #if BUILDFLAG(ENABLE_SPELLCHECK)
//     registry_with_source_info_.AddInterface(
//         base::BindRepeating(&SpellCheckHostHostImpl::Create), ui_task_runner);
// #if BUILDFLAG(HAS_SPELLCHECK_PANEL)
//     registry_.AddInterface(
//         base::BindRepeating(&SpellCheckPanelHostImpl::Create), ui_task_runner);
// #endif
// #endif
  }
  ~IOThreadContext() override = default;

  void BindConnector(
      service_manager::mojom::ConnectorRequest connector_request) {
    DCHECK_CURRENTLY_ON(HostThread::UI);

    // NOTE: It's not safe to modify |connector_request_| here since it's read
    // on the IO thread. Post a task instead. As long as this task is posted
    // before any code attempts to connect to the chrome service, there's no
    // race.
    HostThread::GetTaskRunnerForThread(HostThread::IO)
        ->PostTask(FROM_HERE,
                   base::BindOnce(&IOThreadContext::BindConnectorOnIOThread,
                                  base::Unretained(this),
                                  std::move(connector_request)));
  }

 private:
  void BindConnectorOnIOThread(
      service_manager::mojom::ConnectorRequest connector_request) {
    DCHECK_CURRENTLY_ON(HostThread::IO);
    connector_request_ = std::move(connector_request);
  }

  // service_manager::Service:
  void OnStart() override {
    DCHECK_CURRENTLY_ON(HostThread::IO);
    DCHECK(connector_request_.is_pending());
    context()->connector()->BindConnectorRequest(std::move(connector_request_));
  }

  void OnBindInterface(const service_manager::BindSourceInfo& remote_info,
                       const std::string& name,
                       mojo::ScopedMessagePipeHandle handle) override {
    DCHECK_CURRENTLY_ON(HostThread::IO);
    common::GetClient()->host()->OverrideOnBindInterface(remote_info, name, &handle);
    if (!handle.is_valid())
      return;

    if (!registry_.TryBindInterface(name, &handle))
      registry_with_source_info_.TryBindInterface(name, &handle, remote_info);
  }

  service_manager::mojom::ConnectorRequest connector_request_;

  service_manager::BinderRegistry registry_;
  service_manager::BinderRegistryWithArgs<
      const service_manager::BindSourceInfo&>
      registry_with_source_info_;

// #if defined(OS_CHROMEOS)
//   chromeos::Launchable launchable_;
// #if defined(USE_OZONE)
//   ui::InputDeviceController input_device_controller_;
// #endif
// #endif

  DISALLOW_COPY_AND_ASSIGN(IOThreadContext);
};

// class HostService::ExtraParts : public HostBrowserMainExtraParts {
//  public:
//   ExtraParts() = default;
//   ~ExtraParts() override = default;

//  private:
//   void ServiceManagerConnectionStarted(
//       common::ServiceManagerConnection* connection) override {
//     // Initializing the connector asynchronously configures the Connector on the
//     // IO thread. This needs to be done before StartService() is called or
//     // HostService::BindConnector() can race with HostService::OnStart().
//     HostService::GetInstance()->InitConnector();

//     connection->GetConnector()->StartService(
//         //service_manager::Identity(chrome::mojom::kServiceName));
//         service_manager::Identity(common::mojom::kServiceName));
//   }

//   DISALLOW_COPY_AND_ASSIGN(ExtraParts);
// };

// static
HostService* HostService::GetInstance() {
  static base::NoDestructor<HostService> service;
  return service.get();
}

// HostBrowserMainExtraParts* HostService::CreateExtraParts() {
//   return new ExtraParts;
// }

service_manager::EmbeddedServiceInfo::ServiceFactory HostService::CreateHostServiceFactory() {
  return base::BindRepeating(&HostService::CreateHostServiceWrapper,
                             base::Unretained(this));
}

HostService::HostService()
    : io_thread_context_(std::make_unique<IOThreadContext>()) {}

HostService::~HostService() = default;

void HostService::InitConnector() {
  service_manager::mojom::ConnectorRequest request;
  connector_ = service_manager::Connector::Create(&request);
  io_thread_context_->BindConnector(std::move(request));
}

std::unique_ptr<service_manager::Service>
HostService::CreateHostServiceWrapper() {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  return std::make_unique<service_manager::ForwardingService>(
      io_thread_context_.get());
}

}
