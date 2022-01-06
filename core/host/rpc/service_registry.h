// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_CORE_HOST_SERVICE_REGISTRY_H_
#define MUMBA_CORE_HOST_SERVICE_REGISTRY_H_

#include <string>
#include <unordered_map>
#include <map>
#include <vector>

#include "base/macros.h"
#include "base/uuid.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/memory/ref_counted_memory.h"
#include "base/observer_list.h"
#include "core/host/host_thread.h"
#include "core/host/workspace/workspace.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/mojom/service.mojom.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding_set.h"

namespace host {

class CONTENT_EXPORT ServiceRegistry final : public common::mojom::ServiceRegistry {
public:
  ServiceRegistry(scoped_refptr<Workspace> workspace);
  ~ServiceRegistry() override;

  void AddBinding(common::mojom::ServiceRegistryAssociatedRequest request);

  scoped_refptr<Workspace> workspace() const {
    return workspace_;
  }

  void LookupService(const std::string& scheme, const std::string& name, LookupServiceCallback callback) final;
  void LookupServiceByUUID(const std::string& uuid, LookupServiceByUUIDCallback callback) final;
  void HaveService(const std::string& scheme, const std::string& name, HaveServiceCallback callback) final;
  void HaveServiceByUUID(const std::string& uuid, HaveServiceByUUIDCallback callback) final;
  void ListServices(ListServicesCallback callback) final;
  void ListServicesForScheme(const std::string& scheme, ListServicesForSchemeCallback callback) final;
  void GetServiceCount(GetServiceCountCallback callback) final;
  void StartService(const std::string& uuid, StartServiceCallback callback) final;
  void StopService(const std::string& uuid, StopServiceCallback callback) final;
  void GetServiceHeader(const std::string& url, GetServiceHeaderCallback callback) final;

  void Subscribe(const std::string& scheme, common::mojom::ServiceSubscriberPtr subscriber, SubscribeCallback callback) final;
  void Unsubscribe(int id) final;

  void Shutdown();

private:

  void LookupServiceImpl(const std::string& scheme, const std::string& name, LookupServiceCallback callback);
  void LookupServiceByUUIDImpl(const std::string& uuid, LookupServiceByUUIDCallback callback);
  void HaveServiceImpl(const std::string& scheme, const std::string& name, HaveServiceCallback callback);
  void HaveServiceByUUIDImpl(const std::string& uuid, HaveServiceByUUIDCallback callback);
  void ListServicesImpl(ListServicesCallback callback);
  void ListServicesForSchemeImpl(const std::string& scheme, ListServicesForSchemeCallback callback);
  void GetServiceCountImpl(GetServiceCountCallback callback);
  void GetServiceHeaderImpl(const std::string& url, GetServiceHeaderCallback callback);

  void StartServiceImpl(const std::string& uuid, StartServiceCallback callback);
  void StopServiceImpl(const std::string& uuid, StopServiceCallback callback);

  void SubscribeImpl(const std::string& scheme, common::mojom::ServiceSubscriberPtr subscriber, SubscribeCallback callback);
  void UnsubscribeImpl(int id);

  void ShutdownImpl();

  scoped_refptr<Workspace> workspace_;
  RpcManager* rpc_manager_;

  std::map<int, std::pair<std::string, common::mojom::ServiceSubscriberPtr>> subscribers_;
  
  mojo::AssociatedBindingSet<common::mojom::ServiceRegistry> service_registry_binding_;

  int next_watcher_id_ = 0;

  base::WaitableEvent shutdown_event_;

  DISALLOW_COPY_AND_ASSIGN(ServiceRegistry);
};

}

#endif