// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ServiceRegistryShims.h"
#include "EngineHelper.h"

#include "base/sha1.h"
#include "base/strings/utf_string_conversions.h"
#include "base/strings/string_number_conversions.h"
#include "base/single_thread_task_runner.h"
#include "core/shared/domain/module/module_state.h"
#include "core/shared/domain/application/application.h"
#include "core/shared/application/application_thread.h"
#include "core/shared/application/application_process.h"
#include "core/shared/common/mojom/service.mojom.h"
#include "mojo/public/cpp/bindings/binding.h"

struct ServiceRegistrySubscriberCallbacks {
  void(*OnServiceAdded)(void*, const char*, const char*, const char*, const char*, int);
  void(*OnServiceRemoved)(void*, const char*, const char*, const char*, const char*, int);
  void(*OnServiceChanged)(void*, const char*, const char*, const char*, const char*, int);
  void(*OnServiceStateChanged)(void*, const char*, const char*, const char*, const char*, int, int);
};

class ServiceRegistrySubscriberImpl : public common::mojom::ServiceSubscriber {
public:
 
 ServiceRegistrySubscriberImpl(
  void* state, 
  ServiceRegistrySubscriberCallbacks cb,
  common::mojom::ServiceSubscriberRequest request): 
  state_(state),
  cb_(std::move(cb)),
  binding_(this) {
  
  binding_.Bind(std::move(request));
}

 ~ServiceRegistrySubscriberImpl() {}

 void OnServiceAdded(common::mojom::ServiceEntryPtr entry) override {
   cb_.OnServiceAdded(state_, 
    entry->scheme.c_str(), 
    entry->name.c_str(), 
    entry->uuid.c_str(), 
    entry->host_port.host().c_str(), 
    entry->host_port.port());
 }
 
 void OnServiceRemoved(common::mojom::ServiceEntryPtr entry) override {
   cb_.OnServiceRemoved(state_, 
    entry->scheme.c_str(), 
    entry->name.c_str(), 
    entry->uuid.c_str(), 
    entry->host_port.host().c_str(), 
    entry->host_port.port());
 }

 void OnServiceChanged(common::mojom::ServiceEntryPtr entry) override {
   cb_.OnServiceChanged(state_, 
    entry->scheme.c_str(), 
    entry->name.c_str(), 
    entry->uuid.c_str(), 
    entry->host_port.host().c_str(), 
    entry->host_port.port());
 }

 void OnServiceStateChanged(common::mojom::ServiceEntryPtr entry, common::mojom::ServiceState new_state) override {
   cb_.OnServiceStateChanged(state_, 
    entry->scheme.c_str(), 
    entry->name.c_str(), 
    entry->uuid.c_str(), 
    entry->host_port.host().c_str(), 
    entry->host_port.port(),
    static_cast<int>(new_state));
 }

private:
  void* state_;
  ServiceRegistrySubscriberCallbacks cb_;
  mojo::Binding<common::mojom::ServiceSubscriber> binding_;
};

struct ServiceHaveCallbackState {
  void* state;
  void(*cb)(void*, int);
};

struct ServiceGetCallbackState {
  void* state;
  void(*cb)(void*, int, const char*, const char*, const char*, const char*, int);
};

struct ServiceListCallbackState {
  void* state;
  void(*cb)(void*, int, int, const char**, const char**, const char**, const char**, int*);
};

struct ServiceAddSubscriberCallbackState {
  void* state;
  void* watcher_state;
  void(*cb)(void*, int, void*, void*);
  void(*OnServiceAdded)(void*, const char*, const char*, const char*, const char*, int);
  void(*OnServiceRemoved)(void*, const char*, const char*, const char*, const char*, int);
  void(*OnServiceChanged)(void*, const char*, const char*, const char*, const char*, int);
  void(*OnServiceStateChanged)(void*, const char*, const char*, const char*, const char*, int, int);
  common::mojom::ServiceSubscriberPtr watcher_ptr;
};

void OnGetServiceResult(ServiceGetCallbackState cb_state, common::mojom::ServiceStatusCode r, common::mojom::ServiceEntryPtr entry) {
  if (r == common::mojom::ServiceStatusCode::kSERVICE_STATUS_OK) {
    cb_state.cb(cb_state.state, static_cast<int>(r), entry->scheme.c_str(), entry->name.c_str(), entry->uuid.c_str(), entry->host_port.host().c_str(), entry->host_port.port());
  } else {
    cb_state.cb(cb_state.state, static_cast<int>(r), nullptr, nullptr, nullptr, nullptr, 0);
  }
}

void OnHaveServiceResult(ServiceHaveCallbackState cb_state, bool r) {
  cb_state.cb(cb_state.state, r ? 1 : 0);
}

void OnCountServicesResult(ServiceHaveCallbackState cb_state, uint32_t count) {
  cb_state.cb(cb_state.state, static_cast<int>(count));
}

void OnListServicesResult(ServiceListCallbackState cb_state, std::vector<common::mojom::ServiceEntryPtr> entries) {
  if (entries.size() > 0) {
    size_t count = entries.size();
    const char* schemes[count];
    const char* names[count];
    const char* uuids[count];
    const char* hosts[count];
    int ports[count];
    for (size_t i = 0; i < count; ++i) {
      schemes[i] = entries[i]->scheme.c_str();
      names[i] = entries[i]->name.c_str();
      uuids[i] = entries[i]->uuid.c_str();
      hosts[i] = entries[i]->host_port.host().c_str();
      ports[i] = static_cast<int>(entries[i]->host_port.port());
    }
    cb_state.cb(
      cb_state.state, 
      0,
      count,
      schemes,
      names,
      uuids,
      hosts,
      ports);
  } else {
    cb_state.cb(cb_state.state, 2, 0, nullptr, nullptr, nullptr, nullptr, nullptr);
  }
}

void OnAddSubscriberResult(
  ServiceRegistrySubscriberImpl* watcher,
  ServiceAddSubscriberCallbackState cb_state, 
  int32_t id) {
    cb_state.cb(cb_state.state, id, cb_state.watcher_state, watcher);
}

struct ServiceRegistryWrapper {

  ServiceRegistryWrapper(common::mojom::ServiceRegistry* registry,
                         const scoped_refptr<base::SingleThreadTaskRunner>& task_runner): 
    registry(registry),
    task_runner(task_runner) {}

  common::mojom::ServiceRegistry* registry;
  scoped_refptr<base::SingleThreadTaskRunner> task_runner;

  void AddSubscriber(
    std::string scheme,
    ServiceAddSubscriberCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&ServiceRegistryWrapper::AddSubscriberImpl, 
        base::Unretained(this),
        base::Passed(std::move(scheme)),
        base::Passed(std::move(cb_state))));
  }

  void RemoveSubscriber(int id) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&ServiceRegistryWrapper::RemoveSubscriberImpl, 
        base::Unretained(this),
        id));
  }

  void HaveServiceByName(std::string scheme, std::string name, ServiceHaveCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&ServiceRegistryWrapper::HaveServiceByNameImpl, 
        base::Unretained(this),
        base::Passed(std::move(scheme)),
        base::Passed(std::move(name)),
        base::Passed(std::move(cb_state))));
  }

  void HaveServiceByUUID(std::string uuid, ServiceHaveCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&ServiceRegistryWrapper::HaveServiceByUUIDImpl, 
        base::Unretained(this),
        base::Passed(std::move(uuid)),
        base::Passed(std::move(cb_state))));
  }

  void CountServices(ServiceHaveCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&ServiceRegistryWrapper::CountServicesImpl, 
        base::Unretained(this),
        base::Passed(std::move(cb_state))));
  }
  
  void LookupServiceByName(std::string scheme, std::string name, ServiceGetCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&ServiceRegistryWrapper::LookupServiceByName, 
        base::Unretained(this), 
        base::Passed(std::move(scheme)),
        base::Passed(std::move(name)),
        base::Passed(std::move(cb_state))));
  }

  void LookupServiceByUUID(std::string uuid, ServiceGetCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&ServiceRegistryWrapper::LookupServiceByUUIDImpl, 
        base::Unretained(this), 
        base::Passed(std::move(uuid)),
        base::Passed(std::move(cb_state))));
  }

  void ListServices(std::string scheme, ServiceListCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&ServiceRegistryWrapper::ListServicesWithSchemeImpl, 
        base::Unretained(this), 
        base::Passed(std::move(scheme)),
        base::Passed(std::move(cb_state))));
  }

  void ListServices(ServiceListCallbackState cb_state) {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&ServiceRegistryWrapper::ListAllServicesImpl, 
        base::Unretained(this),
        base::Passed(std::move(cb_state))));
  }

  void HaveServiceByNameImpl(std::string scheme, std::string name, ServiceHaveCallbackState cb_state) {
    registry->HaveService(scheme, name, base::BindOnce(&OnHaveServiceResult, base::Passed(std::move(cb_state))));
  }

  void HaveServiceByUUIDImpl(std::string uuid, ServiceHaveCallbackState cb_state) {
    registry->HaveServiceByUUID(uuid, base::BindOnce(&OnHaveServiceResult, base::Passed(std::move(cb_state))));
  }

  void CountServicesImpl(ServiceHaveCallbackState cb_state) {
    registry->GetServiceCount(base::BindOnce(&OnCountServicesResult, base::Passed(std::move(cb_state))));
  }

  void LookupServiceByNameImpl(std::string scheme, std::string name, ServiceGetCallbackState cb_state) {
    registry->LookupService(scheme, name, base::BindOnce(&OnGetServiceResult, base::Passed(std::move(cb_state))));
  }

  void LookupServiceByUUIDImpl(std::string uuid, ServiceGetCallbackState cb_state) {
    registry->LookupServiceByUUID(uuid, base::BindOnce(&OnGetServiceResult, base::Passed(std::move(cb_state))));
  }

  void ListServicesWithSchemeImpl(std::string scheme, ServiceListCallbackState cb_state) {
    registry->ListServicesForScheme(scheme, base::BindOnce(&OnListServicesResult, base::Passed(std::move(cb_state))));
  }

  void ListAllServicesImpl(ServiceListCallbackState cb_state) {
    registry->ListServices(base::BindOnce(&OnListServicesResult, base::Passed(std::move(cb_state))));
  }

  void AddSubscriberImpl(std::string scheme, ServiceAddSubscriberCallbackState cb_state) {
    common::mojom::ServiceSubscriberPtrInfo service_watcher_info;
    ServiceRegistrySubscriberImpl* watcher = new ServiceRegistrySubscriberImpl(
      cb_state.watcher_state, 
      ServiceRegistrySubscriberCallbacks{cb_state.OnServiceAdded, cb_state.OnServiceRemoved},
      mojo::MakeRequest(&service_watcher_info));
    registry->Subscribe(
      scheme,
      common::mojom::ServiceSubscriberPtr(std::move(service_watcher_info)),
      base::BindOnce(&OnAddSubscriberResult, 
        base::Unretained(watcher),
        base::Passed(std::move(cb_state))));
  }

  void RemoveSubscriberImpl(int id) {
    registry->Unsubscribe(id);
  }

};

ServiceRegistryRef _ServiceRegistryCreateFromEngine(EngineInstanceRef handle) {
  domain::ModuleState* module = reinterpret_cast<_EngineInstance *>(handle)->module_state();
  common::mojom::ServiceRegistry* registry = module->service_registry();
  return new ServiceRegistryWrapper(registry, module->GetMainTaskRunner());
}

void _ServiceRegistryDestroy(ServiceRegistryRef handle) {
  delete reinterpret_cast<ServiceRegistryWrapper *>(handle);
}

void _ServiceRegistryHaveServiceByName(ServiceRegistryRef registry, const char* scheme, const char* name, void* state, void(*cb)(void*, int)) {
  ServiceHaveCallbackState cb_state{state, cb};
  reinterpret_cast<ServiceRegistryWrapper *>(registry)->HaveServiceByName(std::string(scheme), std::string(name), std::move(cb_state));
}

void _ServiceRegistryHaveServiceByUUID(ServiceRegistryRef registry, const char* uuid, void* state, void(*cb)(void*, int)) {
  ServiceHaveCallbackState cb_state{state, cb};
  reinterpret_cast<ServiceRegistryWrapper *>(registry)->HaveServiceByUUID(std::string(uuid), std::move(cb_state));
}

void _ServiceRegistryLookupServiceByName(ServiceRegistryRef registry, const char* scheme, const char* name, void* state, void(*cb)(void*, int, const char*, const char*, const char*, const char*, int)) {
  ServiceGetCallbackState cb_state{state, cb};
  reinterpret_cast<ServiceRegistryWrapper *>(registry)->LookupServiceByName(std::string(scheme), std::string(name), std::move(cb_state));
}

void _ServiceRegistryLookupServiceByUUID(ServiceRegistryRef registry, const char* uuid, void* state, void(*cb)(void*, int, const char*, const char*, const char*, const char*, int)) {
  ServiceGetCallbackState cb_state{state, cb};
  reinterpret_cast<ServiceRegistryWrapper *>(registry)->LookupServiceByUUID(std::string(uuid), std::move(cb_state));
}

void _ServiceRegistryListServicesWithScheme(ServiceRegistryRef registry, const char* scheme, void* state, void(*cb)(void*, int, int, const char**, const char**, const char**, const char**, int*)) {
  ServiceListCallbackState cb_state{state, cb};
  reinterpret_cast<ServiceRegistryWrapper *>(registry)->ListServices(std::string(scheme), std::move(cb_state));
}

void _ServiceRegistryListAllServices(ServiceRegistryRef registry, void* state, void(*cb)(void*, int, int, const char**, const char**, const char**, const char**, int*)) {
  ServiceListCallbackState cb_state{state, cb};
  reinterpret_cast<ServiceRegistryWrapper *>(registry)->ListServices(std::move(cb_state));
}

void _ServiceRegistryGetServiceCount(ServiceRegistryRef registry, void* state, void(*cb)(void*, int)) {
  ServiceHaveCallbackState cb_state{state, cb};
  reinterpret_cast<ServiceRegistryWrapper *>(registry)->CountServices(std::move(cb_state));
}

void _ServiceRegistryAddSubscriber(
  ServiceRegistryRef registry, 
  const char* scheme, 
  void* state,
  void* watcher_state, 
  void(*cb)(void*, int, void*, void*),
  void(*OnServiceAdded)(void*, const char*, const char*, const char*, const char*, int),
  void(*OnServiceRemoved)(void*, const char*, const char*, const char*, const char*, int),
  void(*OnServiceChanged)(void*, const char*, const char*, const char*, const char*, int),
  void(*OnServiceStateChanged)(void*, const char*, const char*, const char*, const char*, int, int)) {
  ServiceAddSubscriberCallbackState cb_state{state, watcher_state, cb, OnServiceAdded, OnServiceRemoved, OnServiceChanged, OnServiceStateChanged};
  reinterpret_cast<ServiceRegistryWrapper *>(registry)->AddSubscriber(
    std::string(scheme), 
    std::move(cb_state)); 
}

void _ServiceRegistryRemoveSubscriber(ServiceRegistryRef registry, int id) {
  reinterpret_cast<ServiceRegistryWrapper *>(registry)->RemoveSubscriber(id); 
}

void _ServiceSubscriberDestroy(void* handle) {
  delete reinterpret_cast<ServiceRegistrySubscriberImpl *>(handle);
}