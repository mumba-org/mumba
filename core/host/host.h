// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_HOST_H_
#define MUMBA_HOST_HOST_H_

#include <string>
#include <vector>
#include <memory>

#include "base/macros.h"
#include "base/callback.h"
#include "base/run_loop.h"
#include "base/files/file_path.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/supports_user_data.h"
#include "base/sequenced_task_runner.h"
#include "core/common/main_params.h"
#include "core/host/host_controller.h"
#include "core/host/host_delegate.h"
#include "core/host/host_options.h"
#include "core/host/workspace/workspace.h"
#include "core/host/data/resource.h"
//#include "core/host/container/container_manager.h"
#include "core/host/application/domain_management_service_impl.h"
#include "core/host/application/mojo_domain_management_service.h"
#include "url/gurl.h"

#if defined(OS_POSIX)
#include <signal.h>
#endif // OS_POSIX

//class PrefService;

namespace host {
class IOThread;
class CommandSession;
class HostDomainManager;
class DomainProcessHost;
class StatusTray;
class ResourceDispatcherHost;
class PlatformNotificationService;
class NotificationPlatformBridge;
class NotificationUIManager;
//class VolumeManager;
//class RpcManager;
//class DomainManager;
class SystemNetworkContextManager;
// TODO: Implementar um URLRequest como no chrome
// para processar url's que vao fazer operacoes fora do filesystem local

class Host :  public ResourceManager, // Host is the resource manager of workspaces
              public base::SupportsUserData {//,
//              public VolumeManager::Delegate {
public:

 enum class Status {
  Ok,
  InitError, // todo: this tells nothing
 };

 static Host* Instance();

 Host(base::WeakPtr<HostDelegate> delegate,
       const base::FilePath& path,
       const common::MainParams& main_params,
       bool is_first_run);

 ~Host() override;

 IOThread* io_thread() const;

 scoped_refptr<Workspace> current_workspace() const {
   return workspace_;
 }

 //PrefService* local_state() const;

 scoped_refptr<HostController> controller() const { return controller_; }

 StatusTray* status_tray() {
  if (!status_tray_)
    CreateStatusTray();
  return status_tray_.get();
 }
 // Returns the platform notification service, capable of displaying Web
 // Notifications to the user. The embedder can return a nullptr if they don't
 // support this functionality. May be called from any thread.
 PlatformNotificationService* GetPlatformNotificationService();

 NotificationPlatformBridge* notification_platform_bridge();
 NotificationUIManager* notification_ui_manager();
 
 //ServiceManager* service_manager() const { return service_manager_.get(); }
 //VolumeManager* container_manager() const { return container_manager_.get(); }
 //net::RpcServiceManager* rpc_manager() const { return rpc_manager_.get(); }
 //DomainManager* domain_manager() const { return domain_manager_.get(); }
 //std::vector<CommandSession*>& sessions() { return sessions_.get(); }
 //const std::vector<CommandSession*>& sessions() const { return sessions_.get(); }

 void set_inside_runloop(bool inside_runloop) { inside_runloop_ = inside_runloop; }

 bool Init(const HostOptions& params);
 void Shutdown();

 // Called before the host threads are created.
 void PreCreateThreads();

 // Called after the threads have been created but before the message loops
 // starts running. Allows the host process to do any initialization that
 // requires all threads running.
 bool PreMainMessageLoopRun();

 // Most cleanup is done by these functions, driven from
 // SlashupHostMain based on notifications from the content
 // framework, rather than in the destructor, so that we can
 // interleave cleanup with threads being stopped.
 void StartTearDown();
 void PostMainMessageLoopRun();
 void PostDestroyThreads();

 unsigned int AddRefModule();
 unsigned int ReleaseModule();

 bool IsShuttingDown();
  
//#if defined(OS_POSIX)
 void OnShutdown(bool fast);
//#endif

 void CreateStatusTray();

  // ResourceManager 
  bool HaveResource(const base::UUID& id) override;
  bool HaveResource(const std::string& name) override;
  Resource* GetResource(const base::UUID& id) override;
  Resource* GetResource(const std::string& name) override;
  const google::protobuf::Descriptor* resource_descriptor() override;
  std::string resource_classname() const override;

private:

 void CreateNotificationPlatformBridge();
 void CreateNotificationUIManager();

 unsigned int module_ref_count_;
 bool did_start_;

 scoped_refptr<HostController> controller_;

 std::unique_ptr<IOThread> io_thread_;

 std::unique_ptr<MojoDomainManagementService> domain_management_service_;

 std::unique_ptr<HostDomainManager> domain_manager_service_;

 scoped_refptr<Workspace> workspace_;

 std::unique_ptr<ResourceDispatcherHost> resource_dispatcher_host_;

 std::unique_ptr<SystemNetworkContextManager> system_network_context_manager_;
 
 bool inside_runloop_;
 
 bool is_shutting_down_;

 base::FilePath path_;
 
 base::WeakPtr<HostDelegate> delegate_;

 std::unique_ptr<StatusTray> status_tray_;

 std::unique_ptr<NotificationPlatformBridge> notification_bridge_;

 std::unique_ptr<NotificationUIManager> notification_ui_manager_;
 
 base::WeakPtrFactory<Host> weak_factory_;

 DISALLOW_COPY_AND_ASSIGN(Host);
};

extern Host* g_host;

}

#endif
