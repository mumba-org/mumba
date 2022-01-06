// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/net/system_network_context_manager.h"

#include <string>

#include "base/feature_list.h"
#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/process/process_handle.h"
#include "base/values.h"
#include "build/build_config.h"
#include "core/host/host.h"
#include "core/host/io_thread.h"
//#include "core/host/net/default_network_context_params.h"
//#include "components/policy/core/common/policy_namespace.h"
//#include "components/policy/core/common/policy_service.h"
//#include "components/policy/policy_constants.h"
#include "core/host/host_thread.h"
#include "core/host/network_service_instance.h"
#include "core/host/net/default_network_context_params.h"
#include "core/shared/common/content_features.h"
#include "core/shared/common/service_names.mojom.h"
#include "mojo/public/cpp/bindings/associated_interface_ptr.h"
#include "net/net_buildflags.h"
#include "services/network/network_service.h"
#include "services/network/public/cpp/features.h"

namespace host {

base::LazyInstance<SystemNetworkContextManager>::Leaky
    g_system_network_context_manager = LAZY_INSTANCE_INITIALIZER;

network::mojom::NetworkContext* SystemNetworkContextManager::GetContext() {
  if (!base::FeatureList::IsEnabled(network::features::kNetworkService)) {
    // SetUp should already have been called.
    DCHECK(io_thread_network_context_);
    return io_thread_network_context_.get();
  }

  if (!network_service_network_context_ ||
      network_service_network_context_.encountered_error()) {
    network::mojom::NetworkService* network_service = GetNetworkService();
    network_service->CreateNetworkContext(
        MakeRequest(&network_service_network_context_),
        CreateNetworkContextParams());
  }
  return network_service_network_context_.get();
}

network::mojom::URLLoaderFactory*
SystemNetworkContextManager::GetURLLoaderFactory() {
  if (!url_loader_factory_ || url_loader_factory_.encountered_error()) {
    GetContext()->CreateURLLoaderFactory(
        mojo::MakeRequest(&url_loader_factory_), 0);
  }
  return url_loader_factory_.get();
}

void SystemNetworkContextManager::SetUp(
    network::mojom::NetworkContextRequest* network_context_request,
    network::mojom::NetworkContextParamsPtr* network_context_params) {
  if (!base::FeatureList::IsEnabled(network::features::kNetworkService)) {
    *network_context_request = mojo::MakeRequest(&io_thread_network_context_);
    *network_context_params = CreateNetworkContextParams();
  } else {
    // Just use defaults if the network service is enabled, since
    // CreateNetworkContextParams() can only be called once.
    *network_context_params = CreateDefaultNetworkContextParams();
  }
}

SystemNetworkContextManager::SystemNetworkContextManager() {}

SystemNetworkContextManager::~SystemNetworkContextManager() {}

network::mojom::NetworkContextParamsPtr
SystemNetworkContextManager::CreateNetworkContextParams() {
  // TODO(mmenke): Set up parameters here (in memory cookie store, etc).
  network::mojom::NetworkContextParamsPtr network_context_params =
      CreateDefaultNetworkContextParams();

  network_context_params->context_name = std::string("system");

  network_context_params->http_cache_enabled = false;

  // These are needed for PAC scripts that use file or data URLs (Or FTP URLs?).
  network_context_params->enable_data_url_support = true;
  network_context_params->enable_file_url_support = true;
//#if !BUILDFLAG(DISABLE_FTP_SUPPORT)
  network_context_params->enable_ftp_url_support = true;
//#endif

  //proxy_config_monitor_.AddToNetworkContextParams(network_context_params.get());

  return network_context_params;
}

}