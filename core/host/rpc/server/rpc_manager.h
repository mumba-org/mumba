// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_RPC_RPC_MANAGER_H_
#define NET_RPC_RPC_MANAGER_H_

#include <unordered_map>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/synchronization/waitable_event.h"
//#include "base/threading/sequenced_worker_pool.h"
#include "base/uuid.h"
#include "net/rpc/server/rpc_service.h"
//#include "net/rpc/server/rpc_tree.h"

namespace base {
class SequencedTaskRunner;
}

namespace host {
class Schema;
class Domain;
class Workspace;
class HostRpcService;

class RpcManager : public net::RpcService::Observer {
public:
  class Observer {
  public:
    virtual ~Observer(){}
    virtual void OnServicesLoad(int r, int count) {}
    virtual void OnServiceAdded(HostRpcService* service) {}
    virtual void OnServiceRemoved(HostRpcService* service) {}
  };
  RpcManager(scoped_refptr<Workspace> workspace);
  ~RpcManager() override;

  const std::unordered_map<base::UUID, HostRpcService *>& services() const {
    return services_;
  }

  HostRpcService* CreateService(
    //Domain* shell,
    const std::string& container,
    const std::string& name,
    const std::string& host,
    int port, 
    net::RpcTransportType type,
    const scoped_refptr<base::SingleThreadTaskRunner>& main_runner,
    const scoped_refptr<base::SingleThreadTaskRunner>& io_runner,
    Schema* schema,
    std::unique_ptr<net::RpcHandler> rpc_handler);
  
  HostRpcService* GetService(const base::UUID& uuid) const;
  HostRpcService* GetService(const std::string& name) const;
  bool HaveService(const base::UUID& uuid) const;
  bool HaveService(const std::string& name) const;
  void AddService(HostRpcService* service);
  void RemoveService(const base::UUID& uuid);

  void Init();
  void Shutdown();

  void AddObserver(Observer* observer);
  void RemoveObserver(Observer* observer);

private:

  // Service::Observer
  void OnStart(net::RpcService* service) override;
  void OnStop(net::RpcService* service) override;

  void OnLoad(int r, int count);

  void NotifyServiceAdded(HostRpcService* service);
  void NotifyServiceRemoved(HostRpcService* service);
  void NotifyServicesLoad(int r, int count);

  std::unordered_map<base::UUID, HostRpcService*> services_;
  std::unordered_map<std::string, base::UUID> services_names_;
  std::vector<Observer*> observers_;
  std::vector<int16_t> allocated_ports_;

  //RpcTree rpc_tree_;

  //scoped_refptr<base::SequencedWorkerPool> worker_pool_;
  //scoped_refptr<base::SingleThreadTaskRunner> service_task_runner_;

  std::unordered_map<std::string, scoped_refptr<base::SingleThreadTaskRunner>> service_task_runners_;
  
  scoped_refptr<Workspace> workspace_;

  base::WaitableEvent shutdown_event_;

  DISALLOW_COPY_AND_ASSIGN(RpcManager);
};

}

#endif