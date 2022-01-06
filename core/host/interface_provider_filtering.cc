// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/interface_provider_filtering.h"

#include <utility>

//#include "core/host/browser_context.h"
#include "core/host/host_thread.h"
#include "core/host/service_manager/service_manager_context.h"
#include "core/host/application/application_process_host.h"
#include "core/host/application/domain_process_host.h"
#include "services/service_manager/public/cpp/connector.h"

namespace host {
namespace {

bool g_bypass_interface_filtering_for_testing = false;

service_manager::Connector* GetConnector() {
  service_manager::Connector* connector =
       ServiceManagerContext::GetConnectorForIOThread();
  if (!connector) {
    connector = common::ServiceManagerConnection::GetForProcess()->GetConnector();
  }
  return connector;
}

void FilterInterfacesImpl(
    const char* spec,
    ApplicationProcessHost* process,
    service_manager::mojom::InterfaceProviderRequest request,
    service_manager::mojom::InterfaceProviderPtr provider) {
  
  service_manager::Connector* connector = process->GetConnector();
      //BrowserContext::GetConnectorFor(process->GetBrowserContext());
  // |connector| is null in unit tests.
  if (!connector)
    return;

  connector->FilterInterfaces(spec, process->GetChildIdentity(),
                              std::move(request), std::move(provider));
}

void FilterInterfacesForServiceImpl(
    const char* spec,
    DomainProcessHost* process,
    service_manager::mojom::InterfaceProviderRequest request,
    service_manager::mojom::InterfaceProviderPtr provider) {
  
  service_manager::Connector* connector = GetConnector();
      //BrowserContext::GetConnectorFor(process->GetBrowserContext());
  // |connector| is null in unit tests.
  if (!connector)
    return;

  connector->FilterInterfaces(spec, process->GetChildIdentity(),
                              std::move(request), std::move(provider));
}

}  // namespace

service_manager::mojom::InterfaceProviderRequest
FilterRendererExposedInterfaces(
    const char* spec,
    int process_id,
    ApplicationProcessHost* process,
    service_manager::mojom::InterfaceProviderRequest request) {
  // if (g_bypass_interface_filtering_for_testing)
  //   return request;

  // ApplicationProcessHost* process = ApplicationProcessHost::FromID(process_id);
  // if (!process)
  //   return request;

  service_manager::mojom::InterfaceProviderPtr provider;
  auto filtered_request = mojo::MakeRequest(&provider);
  // if (!HostThread::CurrentlyOn(HostThread::UI)) {
  //   HostThread::PostTask(
  //       HostThread::UI, FROM_HERE,
  //       base::BindOnce(&FilterInterfacesImpl, spec, process_id,
  //                      std::move(request), std::move(provider)));
  // } else {
  if (!HostThread::CurrentlyOn(HostThread::IO)) {
    HostThread::PostTask(
        HostThread::IO, FROM_HERE,
        base::BindOnce(&FilterInterfacesImpl, spec, base::Unretained(process),
                       std::move(request), std::move(provider)));
  } else {
    FilterInterfacesImpl(spec, process, std::move(request),
                         std::move(provider));
  }
  return filtered_request;
}

service_manager::mojom::InterfaceProviderRequest FilterServiceExposedInterfaces(
    const char* spec,
    int process_id,
    DomainProcessHost* process,
    service_manager::mojom::InterfaceProviderRequest request) {
  service_manager::mojom::InterfaceProviderPtr provider;
  auto filtered_request = mojo::MakeRequest(&provider);
  if (!HostThread::CurrentlyOn(HostThread::IO)) {
    HostThread::PostTask(
        HostThread::IO, FROM_HERE,
        base::BindOnce(&FilterInterfacesForServiceImpl, spec, base::Unretained(process),
                       std::move(request), std::move(provider)));
  } else {
    FilterInterfacesForServiceImpl(spec, process, std::move(request), std::move(provider));
  }
  return filtered_request;
}

namespace test {

ScopedInterfaceFilterBypass::ScopedInterfaceFilterBypass() {
  // Nesting not supported.
  DCHECK(!g_bypass_interface_filtering_for_testing);
  g_bypass_interface_filtering_for_testing = true;
}

ScopedInterfaceFilterBypass::~ScopedInterfaceFilterBypass() {
  g_bypass_interface_filtering_for_testing = false;
}

}  // namespace test

}  // namespace content
