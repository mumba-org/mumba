// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "mumba_service_manager_main_delegate.h"

#include "base/command_line.h"
//#include "content_main_delegate.h"
#include "ProcessMainRunner.h"
#include "core/shared/common/switches.h"
#include "core/shared/common/service_names.mojom.h"
#include "services/service_manager/runner/common/client_util.h"

MumbaServiceManagerMainDelegate::MumbaServiceManagerMainDelegate(
    const common::MainParams& params)
    : main_params_(params),
      process_main_runner_(new ProcessMainRunner()) {}

MumbaServiceManagerMainDelegate::~MumbaServiceManagerMainDelegate() =
    default;

int MumbaServiceManagerMainDelegate::Initialize(
    const InitializeParams& params) {
  //at_exit_ = std::make_unique<base::AtExitManager>();     
#if defined(OS_ANDROID)
  // May be called twice on Android due to the way browser startup requests are
  // dispatched by the system.
  if (initialized_)
    return -1;
#endif

#if defined(OS_MACOSX)
  main_params_.autorelease_pool = params.autorelease_pool;
#endif

  int result = process_main_runner_->Initialize(main_params_);
  return result;
}

bool MumbaServiceManagerMainDelegate::IsEmbedderSubprocess() {
  base::CommandLine* cmd = base::CommandLine::ForCurrentProcess();
  if (cmd->HasSwitch(switches::kGpuProcess) || 
      cmd->HasSwitch(switches::kDomainProcess) ||
      cmd->HasSwitch(switches::kUtilityProcess) ||
      cmd->HasSwitch(switches::kZygoteProcess)) {
    return true;
  }
  return false;
}

int MumbaServiceManagerMainDelegate::RunEmbedderProcess() {
  return process_main_runner_->Run();
}

void MumbaServiceManagerMainDelegate::ShutDownEmbedderProcess() {
#if !defined(OS_ANDROID)
  process_main_runner_->Shutdown();
#endif
}

service_manager::ProcessType
MumbaServiceManagerMainDelegate::OverrideProcessType() {
  return service_manager::ProcessType::kDefault;//main_params_.delegate->OverrideProcessType();
}

void MumbaServiceManagerMainDelegate::OverrideMojoConfiguration(
    mojo::edk::Configuration* config) {
  // If this is the browser process and there's no remote service manager, we
  // will serve as the global Mojo broker.
  if (!service_manager::ServiceManagerIsRemote() && IsHostProcess())
    config->is_broker_process = true;
}

std::unique_ptr<base::Value>
MumbaServiceManagerMainDelegate::CreateServiceCatalog() {
  return nullptr;
}

bool MumbaServiceManagerMainDelegate::ShouldLaunchAsServiceProcess(
    const service_manager::Identity& identity) {
  return identity.name() != common::mojom::kPackagedServicesServiceName;
}

void MumbaServiceManagerMainDelegate::AdjustServiceProcessCommandLine(
    const service_manager::Identity& identity,
    base::CommandLine* command_line) {
  base::CommandLine::StringVector args_without_switches;
  if (identity.name() == common::mojom::kPackagedServicesServiceName) {
    // Ensure other arguments like URL are not lost.
    args_without_switches = command_line->GetArgs();

    // When launching the browser process, ensure that we don't inherit any
    // process type flag. When content embeds Service Manager, a process with no
    // type is launched as a browser process.
    base::CommandLine::SwitchMap switches = command_line->GetSwitches();
    //switches.erase(switches::kProcessType);
    *command_line = base::CommandLine(command_line->GetProgram());
    for (const auto& sw : switches)
      command_line->AppendSwitchNative(sw.first, sw.second);
  }

  //main_params_.delegate->AdjustServiceProcessCommandLine(identity,
  //                                                               command_line);

  // Append other arguments back to |command_line| after the second call to
  // delegate as long as it can still remove all the arguments without switches.
  for (const auto& arg : args_without_switches)
    command_line->AppendArgNative(arg);
}

void MumbaServiceManagerMainDelegate::OnServiceManagerInitialized(
    const base::Closure& quit_closure,
    service_manager::BackgroundServiceManager* service_manager) {
  //return main_params_.delegate->OnServiceManagerInitialized(
   //   quit_closure, service_manager);
}

std::unique_ptr<service_manager::Service>
MumbaServiceManagerMainDelegate::CreateEmbeddedService(
    const std::string& service_name) {
  // TODO

  return nullptr;
}
