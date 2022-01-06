// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_APP_CONTENT_SERVICE_MANAGER_MAIN_DELEGATE_H_
#define CONTENT_APP_CONTENT_SERVICE_MANAGER_MAIN_DELEGATE_H_

#include <memory>

#include "Globals.h"
#include "base/macros.h"
#include "base/at_exit.h"
#include "build/build_config.h"
#include "core/common/main_params.h"
#include "services/service_manager/embedder/main_delegate.h"

class ProcessMainRunner;

class MumbaServiceManagerMainDelegate : public service_manager::MainDelegate {
 public:
  explicit MumbaServiceManagerMainDelegate(const common::MainParams& params);
  ~MumbaServiceManagerMainDelegate() override;

  // service_manager::MainDelegate:
  int Initialize(const InitializeParams& params) override;
  bool IsEmbedderSubprocess() override;
  int RunEmbedderProcess() override;
  void ShutDownEmbedderProcess() override;
  service_manager::ProcessType OverrideProcessType() override;
  void OverrideMojoConfiguration(mojo::edk::Configuration* config) override;
  std::unique_ptr<base::Value> CreateServiceCatalog() override;
  bool ShouldLaunchAsServiceProcess(
      const service_manager::Identity& identity) override;
  void AdjustServiceProcessCommandLine(
      const service_manager::Identity& identity,
      base::CommandLine* command_line) override;
  void OnServiceManagerInitialized(
      const base::Closure& quit_closure,
      service_manager::BackgroundServiceManager* service_manager) override;
  std::unique_ptr<service_manager::Service> CreateEmbeddedService(
      const std::string& service_name) override;

 private:
  common::MainParams main_params_;
  std::unique_ptr<ProcessMainRunner> process_main_runner_;

#if defined(OS_ANDROID)
  bool initialized_ = false;
#endif
//  std::unique_ptr<base::AtExitManager> at_exit_;

  DISALLOW_COPY_AND_ASSIGN(MumbaServiceManagerMainDelegate);
};


#endif  // CONTENT_APP_CONTENT_SERVICE_MANAGER_MAIN_DELEGATE_H_
