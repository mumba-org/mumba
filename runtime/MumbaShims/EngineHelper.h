// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_ENGINE_HELPER_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_ENGINE_HELPER_H_

#include <memory>

#include "base/macros.h"
#include "base/synchronization/lock.h"
#include "core/shared/domain/module/module_client.h"
#include "core/shared/domain/application/application.h"
#include "core/shared/domain/application/application_instance.h"
#include "core/shared/domain/storage/storage_context.h"
#include "core/shared/common/mojom/storage.mojom.h"
#include "EngineCallbacks.h"
#include "WebDefinitions.h"

class EngineClientImpl : public domain::ModuleClient {
public:
  EngineClientImpl(void* instance, CEngineCallbacks callback);
  ~EngineClientImpl() override;

  //domain::EventQueue* event_queue() override;

  domain::ModuleState* module_state() const {
    return module_state_;
  }

  void OnInit(domain::ModuleState* context) override;
  //void OnRun() override;
  void OnShutdown() override;

  void* GetServiceWorkerContextClientState() override; 
  ServiceWorkerContextClientCallbacks GetServiceWorkerContextClientCallbacks() override;

private:

  CEngineCallbacks callback_;
  void* instance_;
  domain::ModuleState* module_state_;
  base::Lock mutex_;

  DISALLOW_COPY_AND_ASSIGN(EngineClientImpl);
};

class ApplicationState : public domain::Application::Observer {
public:
  ApplicationState(domain::Application* application);
  ~ApplicationState() override;

  void set_callbacks(void* state, CApplicationHostCallbacks callbacks) {
    state_ = state;
    callbacks_ = std::move(callbacks);
    callbacks_bounded_ = true;
  }

  domain::Application* application() const {
    return application_;
  }

  void* state() const override {
    return state_;
  }

  void OnApplicationInstanceCreated(domain::Application* app, domain::ApplicationInstance* app_instance) override;
  void OnApplicationInstanceDestroyed(domain::Application* app, int id) override;
  void OnApplicationInstanceLaunched(domain::Application* app, int id) override;
  void OnApplicationInstanceLaunchFailed(domain::Application* app, int id, int err_code, const std::string& message) override;
  void OnApplicationInstanceKilled(domain::Application* app, int id, int exit_code, const std::string& message) override;
  void OnApplicationInstanceActivated(domain::Application* app, int id) override;
  void OnApplicationInstanceClosed(domain::Application* app, int id, int exit_code, const std::string& message) override;
  void OnApplicationInstanceRunError(domain::Application* app, int id, int err_code, const std::string& message) override;
  void OnApplicationInstanceStateChanged(domain::Application* app, int id, domain::ApplicationState app_state) override;
  void OnApplicationInstanceBoundsChanged(domain::Application* app, int id, const gfx::Size& bounds) override;
  void OnApplicationInstanceVisible(domain::Application* app, int id) override;
  void OnApplicationInstanceHidden(domain::Application* app, int id) override;

private:

  domain::Application* application_;
  void* state_;
  CApplicationHostCallbacks callbacks_;
  bool callbacks_bounded_;

  DISALLOW_COPY_AND_ASSIGN(ApplicationState);
};

class _EngineInstance {
public:
  _EngineInstance(std::unique_ptr<EngineClientImpl> client);
  ~_EngineInstance();

  EngineClientImpl* client() const {
    return client_.get();
  }

  domain::ModuleState* module_state() const;

private:
  std::unique_ptr<EngineClientImpl> client_;

  DISALLOW_COPY_AND_ASSIGN(_EngineInstance);
};

#endif