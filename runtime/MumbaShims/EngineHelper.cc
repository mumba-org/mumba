// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "EngineHelper.h"

#include "base/task_scheduler/post_task.h"
#include "base/threading/thread_restrictions.h"
#include "base/message_loop/message_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/task_scheduler/task_traits.h"
#include "core/shared/domain/storage/share_storage.h"
#include "core/shared/domain/module/module_state.h"
#include "core/shared/domain/application/application.h"
#include "core/shared/domain/storage/data_storage.h"
#include "core/shared/domain/storage/file_storage.h"

ApplicationState::ApplicationState(domain::Application* application): 
  application_(application),
  state_(nullptr),
  callbacks_bounded_(false) {

  memset(&callbacks_, 0 , sizeof(CApplicationHostCallbacks));

  application_->AddObserver(this);
}

ApplicationState::~ApplicationState() {
  application_->RemoveObserver(this);
}

void ApplicationState::OnApplicationInstanceCreated(domain::Application* app, domain::ApplicationInstance* app_instance) {
  if (!callbacks_bounded_) {
    return;
  }
  // FIXME: bug
  std::string url = app_instance->url().size() > std::numeric_limits<int32_t>::max() ? std::string() : app_instance->url();
  std::string uuid_string = app_instance->uuid().to_string();
  //DLOG(INFO) << "ApplicationState::OnApplicationInstanceCreated: app_instance => " << app_instance << " uuid: [" << uuid_string.size() << "] url: [" << app_instance->url().size() << "]";
  callbacks_.OnApplicationInstanceCreated(state_, app_instance->id(), url.c_str(), uuid_string.empty() ? nullptr : uuid_string.c_str());
}

void ApplicationState::OnApplicationInstanceDestroyed(domain::Application* app, int id) {
  if (!callbacks_bounded_) {
    return;
  }
  callbacks_.OnApplicationInstanceDestroyed(state_, id);  
}

void ApplicationState::OnApplicationInstanceLaunched(domain::Application* app, int id) {
  if (!callbacks_bounded_) {
    return;
  }
  callbacks_.OnApplicationInstanceLaunched(state_, id);
}

void ApplicationState::OnApplicationInstanceLaunchFailed(domain::Application* app, int id, int err_code, const std::string& message) {
  if (!callbacks_bounded_) {
    return;
  }
  callbacks_.OnApplicationInstanceLaunchFailed(state_, id, err_code, message.c_str());
}

void ApplicationState::OnApplicationInstanceKilled(domain::Application* app, int id, int exit_code, const std::string& message) {
  if (!callbacks_bounded_) {
    return;
  }
  callbacks_.OnApplicationInstanceKilled(state_, id, exit_code, message.c_str());
}

void ApplicationState::OnApplicationInstanceActivated(domain::Application* app, int id) {
  if (!callbacks_bounded_) {
    return;
  }
  callbacks_.OnApplicationInstanceActivated(state_, id);
}

void ApplicationState::OnApplicationInstanceClosed(domain::Application* app, int id, int exit_code, const std::string& message) {
  if (!callbacks_bounded_) {
    return;
  }
  callbacks_.OnApplicationInstanceClosed(state_, id, exit_code, message.c_str());
}

void ApplicationState::OnApplicationInstanceRunError(domain::Application* app, int id, int err_code, const std::string& message) {
  if (!callbacks_bounded_) {
    return;
  }
  callbacks_.OnApplicationInstanceKilled(state_, id, err_code, message.c_str());
}

void ApplicationState::OnApplicationInstanceStateChanged(domain::Application* app, int id, domain::ApplicationState app_state) {
  if (!callbacks_bounded_) {
    return;
  }
  callbacks_.OnApplicationInstanceStateChanged(state_, id, static_cast<int>(app_state));
}

void ApplicationState::OnApplicationInstanceBoundsChanged(domain::Application* app, int id, const gfx::Size& bounds) {
  if (!callbacks_bounded_) {
    return;
  }
  callbacks_.OnApplicationInstanceBoundsChanged(state_, id, bounds.width(), bounds.height()); 
}

void ApplicationState::OnApplicationInstanceVisible(domain::Application* app, int id) {
  if (!callbacks_bounded_) {
    return;
  }
  callbacks_.OnApplicationInstanceVisible(state_, id);
}

void ApplicationState::OnApplicationInstanceHidden(domain::Application* app, int id) {
  if (!callbacks_bounded_) {
    return;
  }
  callbacks_.OnApplicationInstanceHidden(state_, id);
}

EngineClientImpl::EngineClientImpl(void* instance, CEngineCallbacks callback): 
 callback_(callback),
 instance_(instance),
 module_state_(nullptr) {
}

EngineClientImpl::~EngineClientImpl() {

}

// domain::EventQueue* EngineClientImpl::event_queue() {
//   base::AutoLock lock(mutex_);
  
//   domain::EventQueue* ev_queue = reinterpret_cast<domain::EventQueue *>(callback_.GetEventQueue(state_));
//   DCHECK(ev_queue);
//   return ev_queue;
// }

void EngineClientImpl::OnInit(domain::ModuleState* state) {
  base::AutoLock lock(mutex_);
  module_state_ = state;
  callback_.OnInit(instance_, state);
}

// void EngineClientImpl::OnRun() {
//   //base::AutoLock lock(mutex_);

//   // change: do not autolock on callback mutex
//   // because OnRun is a *blocking* call

//   // so use the lock only when dealing with callback_
//   // releasing the lock after getting the handle
//   // for the blocking run function 
  
//   mutex_.Acquire();
//   auto* callback_cb = callback_.OnRun;
//   mutex_.Release();

//   callback_cb(state_);
// }

void EngineClientImpl::OnShutdown() {
  base::AutoLock lock(mutex_);
  callback_.OnShutdown(instance_);
}

void* EngineClientImpl::GetServiceWorkerContextClientState() {
  base::AutoLock lock(mutex_);
  return callback_.GetServiceWorkerContextClientState(instance_);
}

ServiceWorkerContextClientCallbacks EngineClientImpl::GetServiceWorkerContextClientCallbacks() {
  base::AutoLock lock(mutex_);
  return callback_.GetServiceWorkerContextClientCallbacks(instance_);
}

_EngineInstance::_EngineInstance(std::unique_ptr<EngineClientImpl> client):
    client_(std::move(client)) {}

_EngineInstance::~_EngineInstance() {}

domain::ModuleState* _EngineInstance::module_state() const {
  return client_->module_state();
}