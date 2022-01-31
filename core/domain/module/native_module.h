// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_EXECUTION_NATIVE_MODULE_H_
#define MUMBA_DOMAIN_EXECUTION_NATIVE_MODULE_H_

#include <memory>

#include "base/macros.h"
//#include "disk/disk.h"
#include "net/base/ip_address.h"
#include "core/domain/module/module.h"
#include "core/domain/module/callable.h"
#include "core/domain/module/function.h"
#include "core/domain/module/executable.h"
#include "core/domain/module/native_executable.h"
#include "core/shared/common/mojom/objects.mojom.h"
#include "core/shared/common/mojom/channel.mojom.h"
#include "core/shared/common/mojom/route.mojom.h"
#include "core/domain/module/code.h"
//#include "disk/proto/disk.pb.h"

namespace domain {
class DomainContext;

class NativeModule : public Module {
public:
  NativeModule(
    scoped_refptr<DomainContext> context,
    const base::UUID& id, 
    const std::string& name,
    P2PSocketDispatcher* dispatcher,
    scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> io_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> module_task_runner);

  ~NativeModule() override;

  Executable* executable() const {
    return executable_.get();
  }

  // Module
  const base::UUID& id() const override;
  const std::string& name() const override;
  common::mojom::ModuleHandlePtr module_handle() const override;
  ModuleClient* module_client() const override;
  bool Load(Executable::InitParams executable_params) override;
  void Unload() override;

  // if its a dyn lib we bind to the real function ptr
  // if its a executable we will fork the exe
  template <typename R,typename... Args>
  inline Callable<base::MakeUnboundRunType<R, Args...>>
  Bind(storage_proto::ExecutableEntry entry, Args&&... args) {
    std::string entry_point = executable_->GetEntryName(entry);
    if (entry_point.empty()) {
      //DLOG(ERROR) << "the entry point returned a empty function name.";
      return {};
    }
    Code* code = executable_->host_code();
    CodeEntry* code_entry = code->GetEntry(entry_point);
    if (code_entry) {
      Function<R> func(code_entry);
      return func.Bind(std::forward(args)...);
    }
    return {};
  }

  Closure BindClosure(storage_proto::ExecutableEntry entry) {
    return Bind<void()>(entry);
  }

private:

  scoped_refptr<base::SingleThreadTaskRunner> GetMainTaskRunner() const override;
  scoped_refptr<base::SingleThreadTaskRunner> GetModuleTaskRunner() const override;
  scoped_refptr<base::SingleThreadTaskRunner> GetIOTaskRunner() const override;
  common::ServiceManagerConnection* GetServiceManagerConnection() override;

  P2PSocketDispatcher* socket_dispatcher() const override;
  StorageManager* storage_manager() const override;
  RouteDispatcher* route_dispatcher() const override;
  RepoDispatcher* repo_dispatcher() const override;
  CollectionDispatcher* collection_dispatcher() const override;
  common::mojom::RouteRegistry* route_registry() const override;
  common::mojom::ChannelRegistry* channel_registry() const override;
  common::mojom::ServiceRegistry* service_registry() const override;

  void CreateP2PSocket(
      int type, 
      int id, 
      const uint8_t* local_addr, 
      int local_port, 
      uint16_t port_range_min, 
      uint16_t port_range_max, 
      const uint8_t* remote_addr, 
      int remote_port,
      base::Callback<void(int, int)> onCreate) override;

  void CloseP2PSocket(int id) override;

  void ForeachApplication(void* state, void(*foreach)(void* state, void* app_state, const char* name, const char* uuid, const char* url)) override;

  void SendCreateP2PSocketOnMainThread(
      int type, 
      int id, 
      net::IPAddress local_ipaddr, 
      int local_port, 
      uint16_t port_range_min, 
      uint16_t port_range_max, 
      net::IPAddress remote_ipaddr, 
      int remote_port,
      base::Callback<void(int, int)> onCreate);
  
  void SendCloseP2PSocketOnMainThread(int id);

  scoped_refptr<DomainContext> context_;

  scoped_refptr<base::SingleThreadTaskRunner> main_task_runner_;

  scoped_refptr<base::SingleThreadTaskRunner> module_task_runner_;

  scoped_refptr<base::SingleThreadTaskRunner> io_task_runner_;

  std::unique_ptr<NativeExecutable> executable_;

  base::UUID id_;

  std::string name_;

  ModuleState engine_state_;

  ModuleClient* client_;

  P2PSocketDispatcher* dispatcher_;

  base::Lock client_mutex_;
  
  DISALLOW_COPY_AND_ASSIGN(NativeModule);
};


}

#endif