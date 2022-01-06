// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_MODULE_STATE_H_
#define MUMBA_DOMAIN_MODULE_STATE_H_

#include <memory>
#include <unordered_map>

#include "base/memory/ref_counted.h"
#include "base/bind.h"
#include "base/callback.h"
#include "base/synchronization/lock.h"
#include "base/single_thread_task_runner.h"
#include "core/shared/common/content_export.h"
#include "runtime/MumbaShims/WebDefinitions.h"

namespace common {
class ServiceManagerConnection;
namespace mojom {
class RouteRegistry;
class ServiceRegistry;
class ChannelRegistry;
}  
}

namespace domain {
class P2PSocketDispatcher;
class StorageManager;
class RouteDispatcher;

class CONTENT_EXPORT ModuleState {
public:
  class Delegate {
  public:
    virtual ~Delegate() {}
    virtual scoped_refptr<base::SingleThreadTaskRunner> GetMainTaskRunner() const = 0;
    virtual scoped_refptr<base::SingleThreadTaskRunner> GetModuleTaskRunner() const = 0;
    virtual scoped_refptr<base::SingleThreadTaskRunner> GetIOTaskRunner() const = 0;
    virtual common::ServiceManagerConnection* GetServiceManagerConnection() = 0;
    virtual StorageManager* storage_manager() const = 0;
    virtual RouteDispatcher* route_dispatcher() const = 0;
    virtual P2PSocketDispatcher* socket_dispatcher() const = 0;
    virtual common::mojom::RouteRegistry* route_registry() const = 0;
    virtual common::mojom::ChannelRegistry* channel_registry() const = 0;
    virtual common::mojom::ServiceRegistry* service_registry() const = 0;
    virtual void CreateP2PSocket(
      int type, 
      int id, 
      const uint8_t* local_addr, 
      int local_port, 
      uint16_t port_range_min, 
      uint16_t port_range_max, 
      const uint8_t* remote_addr, 
      int remote_port, 
      base::Callback<void(int, int)> onCreate) = 0;
    virtual void CloseP2PSocket(int id) = 0;
    virtual void ForeachApplication(void* state, void(*foreach)(void* state, void* app_state, const char* name, const char* uuid, const char* url)) = 0;
  };

  ModuleState(Delegate* delegate);
  ~ModuleState();

  P2PSocketDispatcher* socket_dispatcher() const;
  StorageManager* storage_manager() const;
  RouteDispatcher* route_dispatcher() const;
  common::mojom::RouteRegistry* route_registry() const;
  common::mojom::ChannelRegistry* channel_registry() const;
  common::mojom::ServiceRegistry* service_registry() const;
  
  void CreateP2PSocket(int type,
    int id, 
    const uint8_t* local_addr, 
    int local_port,
    uint16_t port_range_min,
    uint16_t port_range_max,
    const uint8_t* remote_addr, 
    int remote_port,
    void (*on_create)(void* data, int, int),
    void* data);
  
  void CloseP2PSocket(int id);
  void ForeachApplication(void* state, void(*foreach)(void* state, void* app_state, const char* name, const char* uuid, const char* url));

  Delegate* delegate() const {
    return delegate_;
  }

  scoped_refptr<base::SingleThreadTaskRunner> GetMainTaskRunner() const {
    return delegate_->GetMainTaskRunner();
  }

  scoped_refptr<base::SingleThreadTaskRunner> GetIOTaskRunner() const {
    return delegate_->GetIOTaskRunner();
  }
  
  scoped_refptr<base::SingleThreadTaskRunner> GetModuleTaskRunner() const {
    return delegate_->GetModuleTaskRunner();
  }

  common::ServiceManagerConnection* GetServiceManagerConnection() {
    return delegate_->GetServiceManagerConnection();
  }
  
private:
  
  void OnSocketCreated(void* data, int handle, int err);
  
  // to call delegate from the Engine
  base::Lock mutex_;

  Delegate* delegate_;
  
  std::unordered_map<int, void (*)(void*, int, int)> callbacks_;

  DISALLOW_COPY_AND_ASSIGN(ModuleState);
};

}

#endif