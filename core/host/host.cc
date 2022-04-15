// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/host.h"

#include "base/path_service.h"
#include "base/bind.h"
#include "base/logging.h"
#include "base/command_line.h"
#include "base/trace_event/trace_event.h"
#include "base/synchronization/lock.h"
#include "base/files/file_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/message_loop/message_loop.h"
#include "base/message_loop/message_loop_current.h"
#include "core/shared/common/paths.h"
#include "core/common/constants.h"
#include "core/shared/common/child_process_host.h"
#include "core/host/host_thread.h"
#include "core/host/application/host_domain_manager.h"
#include "core/host/application/resource_dispatcher_host.h"
#include "core/host/host_startup.h"
#include "core/host/net/system_network_context_manager.h"
#include "core/host/notifications/notification_platform_bridge.h"
#include "core/host/notifications/notification_ui_manager.h"
#include "core/host/notification_service_impl.h"
#include "core/host/notification_types.h"
#include "core/host/io_thread.h"
#include "core/host/platform_notification_service.h"
#include "core/host/network_service_instance.h"
#include "core/host/ui/status_icons/status_tray.h"
#include "core/host/notifications/platform_notification_service_impl.h"
#include "core/common/constants.h"
#include "core/shared/common/switches.h"

namespace host {

void NotifyAppTerminating() {
  static bool notified = false;
  if (notified)
    return;
  notified = true;
  NotificationService::current()->Notify(
      NOTIFICATION_APP_TERMINATING,
      NotificationService::AllSources(),
      NotificationService::NoDetails());
}

Host *g_host = nullptr;

// static
Host *Host::Instance() {
  return g_host;
}

Host::Host(base::WeakPtr<HostDelegate> delegate,
             const base::FilePath &path,
             const common::MainParams &main_params, 
             bool is_first_run)
    : module_ref_count_(0),
      did_start_(false),
      controller_(new HostController(this)),
      domain_manager_service_(new HostDomainManager()),
      inside_runloop_(false),
      is_shutting_down_(false),
      path_(path),
      delegate_(std::move(delegate)),
      weak_factory_(this) {

  g_host = this;
}

Host::~Host() { g_host = nullptr; }

IOThread *Host::io_thread() const {
  return io_thread_.get();
}

bool Host::Init(const HostOptions& params) {
  WorkspaceParams workspace_params;

  if (!params.profile_path.empty()) {
    workspace_params.profile_path = params.profile_path;
  } else {
    if (!base::PathService::Get(common::DIR_PROFILE, &workspace_params.profile_path)) {
      LOG(ERROR) << "fatal: failed to get the default home directory";
      return false;
    }
  }

  if (!params.workspace_name.empty()) {
    workspace_params.workspace_name = params.workspace_name;
  }

  workspace_params.admin_service_host = params.admin_service_host;
  workspace_params.admin_service_port = params.admin_service_port;

  controller_->Init();

  domain_management_service_.reset(
    new MojoDomainManagementService(domain_manager_service_->GetWeakPtr()));

  // in the future we may have and manage more than one workspace
  // but for now we will just manage one default workspace
#if defined(OS_WIN)  
  workspace_ = Workspace::New(base::UTF16ToASCII(workspace_params.workspace_name));
#elif defined(OS_POSIX)
  workspace_ = Workspace::New(workspace_params.workspace_name);
#endif
  workspace_->set_current(true);
  workspace_->Init(workspace_params, io_thread_.get(), controller_, DatabasePolicy::AlwaysOpen);

  resource_dispatcher_host_.reset(new ResourceDispatcherHost(HostThread::GetTaskRunnerForThread(HostThread::IO)));

  // Force the creation of the network service
  GetNetworkService();

  did_start_ = true;

  return true;
}

void Host::Shutdown() {
  NotifyAppTerminating();
  // if the shutdown is called while the main loop is running
  if (inside_runloop_) {
    delegate_->PerformShutdown();
  }

  workspace_->Shutdown();
  workspace_ = nullptr;

  resource_dispatcher_host_.reset();
}

//#if defined(OS_POSIX)
void Host::OnShutdown(bool fast) { Shutdown(); }
//#endif

void Host::PreCreateThreads() {
  system_network_context_manager_ = std::make_unique<SystemNetworkContextManager>();
  io_thread_.reset(new IOThread(system_network_context_manager_.get()));
}

bool Host::PreMainMessageLoopRun() {
  HostOptions params;

  base::CommandLine* cmd = base::CommandLine::ForCurrentProcess();

  if (cmd->HasSwitch(switches::kWorkspaceId)) {
    params.workspace_name = cmd->GetSwitchValueASCII(switches::kWorkspaceId);
  }

  if (cmd->HasSwitch(switches::kProfilePath)) {
    params.profile_path = base::FilePath(cmd->GetSwitchValueASCII(switches::kProfilePath));
  }

  if (cmd->HasSwitch(switches::kAdminServiceHost)) {
    params.admin_service_host = cmd->GetSwitchValueASCII(switches::kAdminServiceHost);
  }

  if (cmd->HasSwitch(switches::kAdminServicePort)) {
    std::string port_string = cmd->GetSwitchValueASCII(switches::kAdminServicePort);
    int int_port = 0;
    if (base::StringToInt(port_string, &int_port)) {
      params.admin_service_port = int_port;
    }
  }

  if (!Init(params)) {
    DLOG(ERROR) << "Error initializing host";
    return false;
  }

  return true;
}

void Host::StartTearDown() { is_shutting_down_ = true; }

void Host::PostMainMessageLoopRun() {
  HostThread::PostTask(
      HostThread::IO, FROM_HERE,
      base::Bind(&IOThread::CleanUpOnIOThread, io_thread_->weak_ptr()));
    
  // we should wait for a proper IOThread cleanup
  io_thread_->shutdown_event()->Wait();
  controller_->Shutdown();
}

void Host::PostDestroyThreads() { io_thread_.reset(); }

unsigned int Host::AddRefModule() {
  //DCHECK(CalledOnValidThread());
  did_start_ = true;
  module_ref_count_++;
  return module_ref_count_;
}

unsigned int Host::ReleaseModule() {
  //DCHECK(CalledOnValidThread());
  DCHECK_NE(0u, module_ref_count_);
  module_ref_count_--;
  return module_ref_count_;
}

bool Host::IsShuttingDown() { 
  return is_shutting_down_; 
}

void Host::CreateStatusTray() {
  DCHECK(!status_tray_);
  status_tray_.reset(StatusTray::Create());
}

PlatformNotificationService* Host::GetPlatformNotificationService() {
  return PlatformNotificationServiceImpl::GetInstance();
}

NotificationPlatformBridge* Host::notification_platform_bridge() {
  if (!notification_bridge_) {
    CreateNotificationPlatformBridge();
  }
  return notification_bridge_.get();
}

NotificationUIManager* Host::notification_ui_manager() {
  //DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
// TODO(miguelg) return NULL for MAC as well once native notifications
// are enabled by default.
#if defined(OS_ANDROID)
  return nullptr;
#else
  if (notification_ui_manager_) {
    CreateNotificationUIManager();
  }
  return notification_ui_manager_.get();
#endif
}

void Host::CreateNotificationPlatformBridge() {
  //DCHECK(!notification_bridge_);
  notification_bridge_.reset(NotificationPlatformBridge::Create());
}

void Host::CreateNotificationUIManager() {
// Android does not use the NotificationUIManager anymore
// All notification traffic is routed through NotificationPlatformBridge.
#if !defined(OS_ANDROID)
  DCHECK(!notification_ui_manager_);
  notification_ui_manager_.reset(NotificationUIManager::Create());
#endif
}

bool Host::HaveResource(const base::UUID& id) {
  return workspace_->id() == id;
}

bool Host::HaveResource(const std::string& name) {
  return workspace_->name() == name;
}

Resource* Host::GetResource(const base::UUID& id) {
  if (workspace_->id() == id) {
    return workspace_.get();
  }
  return nullptr;
}

Resource* Host::GetResource(const std::string& name) {
  if (workspace_->name() == name) {
    return workspace_.get();
  }
  return nullptr;
}

const google::protobuf::Descriptor* Host::resource_descriptor() {
  // FIXME: implement
  return nullptr;
}

std::string Host::resource_classname() const {
  return Workspace::kClassName;
}

}