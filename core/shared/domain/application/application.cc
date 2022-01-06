// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/application/application.h"

#include "base/strings/string_number_conversions.h"
#include "core/shared/domain/application/application_instance.h"
#include "core/shared/domain/application/window_instance.h"
#include "core/shared/domain/application/application_driver.h"
#include "ipc/ipc_sync_channel.h"
#include "ipc/ipc_sync_message_filter.h"
#include "ipc/ipc_channel_mojo.h"
#include "mojo/public/cpp/bindings/strong_binding.h"
#include "mojo/public/cpp/system/message_pipe.h"
#include "mojo/edk/embedder/embedder.h"
#include "mojo/edk/embedder/incoming_broker_client_invitation.h"
#include "mojo/edk/embedder/named_platform_channel_pair.h"
#include "mojo/edk/embedder/platform_channel_pair.h"
#include "mojo/edk/embedder/scoped_ipc_support.h"
#include "mojo/edk/embedder/named_platform_handle_utils.h"
#include "mojo/edk/embedder/named_platform_handle.h"
#include "mojo/public/cpp/system/buffer.h"
#include "mojo/public/cpp/system/platform_handle.h"
#include "third_party/blink/public/common/associated_interfaces/associated_interface_registry.h"

namespace domain {

Application::Application(
  Delegate* delegate, 
  const std::string& name, 
  const base::UUID& uuid,
  const GURL url):
    delegate_(delegate),
    controller_(this),
    name_(name),
    uuid_(uuid),
    url_(std::move(url)) {
  
}

Application::~Application() {

}

size_t Application::instance_count() {
  base::AutoLock lock(instances_lock_);
  return instances_.size();
}

int Application::CreateInstance(
  int32_t id, 
  const std::string& url,
  WindowMode window_mode,
  gfx::Rect initial_bounds,
  ui::mojom::WindowOpenDisposition window_open_disposition,
  bool fullscreen,
  bool headless) {
  // we delegate this to the controller and the controller will 
  // return to us what happened
  return controller_.CreateInstance(
    this, 
    id, 
    url,
    window_mode,
    initial_bounds,
    window_open_disposition,
    fullscreen,
    headless);
}

void Application::KillInstance(int id) {
  controller_.KillApplication(this, id);
}

void Application::CloseInstance(int id) {
  controller_.CloseApplication(this, id);
}

void Application::ActivateInstance(int id) {
  controller_.ActivateApplication(this, id);
}

ApplicationDriver* Application::GetDriver(int id) const {
  auto it = drivers_.find(id);
  if (it == drivers_.end()) {
    return nullptr;
  }
  return it->second.get();
}

ApplicationInstance* Application::GetInstance(int id) {
  base::AutoLock lock(instances_lock_);
  for (auto it = instances_.begin(); it != instances_.end(); ++it) {
    if ((*it)->id() == id) {
      return *it;
    }
  }
  return nullptr;
}

WindowInstance* Application::GetWindow(int id) const {
  for (auto it = windows_.begin(); it != windows_.end(); ++it) {
    if ((*it)->id == id) {
      return *it;
    }
  }
  return nullptr;
}

void Application::AddObserver(Observer* observer) {
  base::AutoLock lock(observers_lock_);
  observers_.push_back(observer);
}

void Application::RemoveObserver(Observer* observer) {
  base::AutoLock lock(observers_lock_);
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    if (*it == observer) {
      observers_.erase(it);
      break;
    }
  }
}

void Application::set_driver_state(int id, void* state) {
  ApplicationDriver* driver = GetDriver(id);
  if (!driver) {
    //DLOG(INFO) << "Application::set_driver_state: no driver(instance) found with id " << id << ". cancelling setting state";
    return;
  }
  driver->set_state(state);
}

scoped_refptr<base::SingleThreadTaskRunner> Application::GetIOTaskRunner() const {
  return delegate_->GetIOTaskRunner();
}

IPC::SyncChannel* Application::GetChannel() {
  return delegate_->GetChannel();
}

blink::AssociatedInterfaceRegistry* Application::GetAssociatedInterfaceRegistry() const {
  return delegate_->GetAssociatedInterfaceRegistry();
}

common::mojom::ApplicationManagerHost* Application::GetApplicationManagerHost() {
  return delegate_->GetApplicationManagerHost();
}

ApplicationInstance* Application::CreateApplicationInstance(
  Application* parent, 
  int32_t id, 
  const std::string& url,
  WindowMode window_mode,
  gfx::Rect initial_bounds,
  ui::mojom::WindowOpenDisposition window_open_disposition,
  bool fullscreen,
  bool headless) {
  //DLOG(INFO) << "Application::CreateApplicationInstance";
  base::AutoLock lock(observers_lock_);
  // auto app_state_it = observers_.begin();
  // DCHECK(app_state_it != observers_.end());
  // void* state = (*app_state_it)->state();
  std::unique_ptr<ApplicationInstance> instance = std::make_unique<ApplicationInstance>();
  std::unique_ptr<ApplicationDriver> owned_driver = std::make_unique<ApplicationDriver>(nullptr, this, id);
  ApplicationDriver* driver = owned_driver.get();
  drivers_.emplace(std::make_pair(id, std::move(owned_driver)));
  ApplicationInstance* handle = instance.get();
  delegate_->CreateApplicationInstance(std::move(instance), parent, id, url, window_mode, initial_bounds, window_open_disposition, fullscreen, headless);

  // bind client interfaces
  //DLOG(INFO) << "Application::CreateApplicationInstance: binding domain automation client interfaces:\n" << 
  // "creating client interface: " << "'automation.AnimationClient_" + base::NumberToString(id) << "'";
  

  GetAssociatedInterfaceRegistry()->AddInterface(
    "automation.AnimationClient_" + base::NumberToString(id),
    base::BindRepeating(&Application::BindInterface<automation::AnimationClient>, 
      base::BindRepeating(&ApplicationDriver::BindAnimationClient,
                          base::Unretained(driver))));

  GetAssociatedInterfaceRegistry()->AddInterface(
    "automation.PageClient_" + base::NumberToString(id),
    base::BindRepeating(&Application::BindInterface<automation::PageClient>, 
      base::BindRepeating(&ApplicationDriver::BindPageClient,
                          base::Unretained(driver))));
  
  GetAssociatedInterfaceRegistry()->AddInterface(
    "automation.OverlayClient_" + base::NumberToString(id),
    base::BindRepeating(&Application::BindInterface<automation::OverlayClient>, 
    base::BindRepeating(&ApplicationDriver::BindOverlayClient,
                        base::Unretained(driver))));

  GetAssociatedInterfaceRegistry()->AddInterface(
    "automation.ServiceWorkerClient_" + base::NumberToString(id),
    base::BindRepeating(&Application::BindInterface<automation::ServiceWorkerClient>, 
    base::BindRepeating(&ApplicationDriver::BindWorkerClient,
                        base::Unretained(driver))));

  GetAssociatedInterfaceRegistry()->AddInterface(
    "automation.StorageClient_" + base::NumberToString(id),
    base::BindRepeating(&Application::BindInterface<automation::StorageClient>, 
    base::BindRepeating(&ApplicationDriver::BindStorageClient,
                        base::Unretained(driver))));

  GetAssociatedInterfaceRegistry()->AddInterface(
    "automation.NetworkClient_" + base::NumberToString(id),
    base::BindRepeating(&Application::BindInterface<automation::NetworkClient>, 
    base::BindRepeating(&ApplicationDriver::BindNetworkClient,
                        base::Unretained(driver))));

  GetAssociatedInterfaceRegistry()->AddInterface(
    "automation.LayerTreeClient_" + base::NumberToString(id),
    base::BindRepeating(&Application::BindInterface<automation::LayerTreeClient>, 
    base::BindRepeating(&ApplicationDriver::BindLayerTreeClient,
                        base::Unretained(driver))));

  GetAssociatedInterfaceRegistry()->AddInterface(
    "automation.HeadlessClient_" + base::NumberToString(id),
    base::BindRepeating(&Application::BindInterface<automation::HeadlessClient>, 
    base::BindRepeating(&ApplicationDriver::BindHeadlessClient,
                        base::Unretained(driver))));
  
  GetAssociatedInterfaceRegistry()->AddInterface(
    "automation.DOMStorageClient_" + base::NumberToString(id),
    base::BindRepeating(&Application::BindInterface<automation::DOMStorageClient>, 
    base::BindRepeating(&ApplicationDriver::BindDOMStorageClient,
                        base::Unretained(driver))));
  
  GetAssociatedInterfaceRegistry()->AddInterface(
    "automation.DatabaseClient_" + base::NumberToString(id),
    base::BindRepeating(&Application::BindInterface<automation::DatabaseClient>, 
    base::BindRepeating(&ApplicationDriver::BindDatabaseClient,
                        base::Unretained(driver))));

  GetAssociatedInterfaceRegistry()->AddInterface(
    "automation.EmulationClient_" + base::NumberToString(id),
    base::BindRepeating(&Application::BindInterface<automation::EmulationClient>, 
    base::BindRepeating(&ApplicationDriver::BindEmulationClient,
                        base::Unretained(driver))));
  
  GetAssociatedInterfaceRegistry()->AddInterface(
    "automation.DOMClient_" + base::NumberToString(id),
    base::BindRepeating(&Application::BindInterface<automation::DOMClient>, 
    base::BindRepeating(&ApplicationDriver::BindDOMClient,
                        base::Unretained(driver))));
  
  GetAssociatedInterfaceRegistry()->AddInterface(
    "automation.CSSClient_" + base::NumberToString(id),
    base::BindRepeating(&Application::BindInterface<automation::CSSClient>, 
    base::BindRepeating(&ApplicationDriver::BindCSSClient,
                        base::Unretained(driver))));
  
  GetAssociatedInterfaceRegistry()->AddInterface(
    "automation.ApplicationCacheClient_" + base::NumberToString(id),
    base::BindRepeating(&Application::BindInterface<automation::ApplicationCacheClient>, 
    base::BindRepeating(&ApplicationDriver::BindApplicationCacheClient,
                        base::Unretained(driver))));

  GetIOTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(
      &Application::NotifyApplicationInstanceCreated,
      base::Unretained(this),
      base::Unretained(handle))
  );
  return handle;
}

void Application::NotifyApplicationInstanceCreated(ApplicationInstance* instance) {
  //DCHECK_CURRENTLY_ON(GetIOTaskRunner());
  base::AutoLock lock(observers_lock_);
  //DLOG(INFO) << "Application::CreateApplicationInstance: passing instance " << instance << " url [" << instance->url().size() << "]";
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    (*it)->OnApplicationInstanceCreated(this, instance);
  }
}

void Application::OnApplicationLaunched(const std::string& url, ApplicationInstance* instance) {
  //DCHECK_CURRENTLY_ON(GetIOTaskRunner());
  base::AutoLock lock(observers_lock_);
  instances_.push_back(instance);
  //DLOG(INFO) << "Application::OnApplicationLaunched: initializing application driver..";
  auto driver_it = drivers_.find(instance->id());
  DCHECK(driver_it != drivers_.end());
  auto* driver = driver_it->second.get();

  // automation clients

  driver->RegisterInterfaces();
  //DLOG(INFO) << "Application::OnApplicationLaunched: notifying observers..";
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    (*it)->OnApplicationInstanceLaunched(this, instance->id());
  }
  ChangeInstanceState(instance, ApplicationState::kRUNNING);
}

void Application::OnApplicationActivated(const std::string& url, int id) {
  //DCHECK_CURRENTLY_ON(GetIOTaskRunner());
  base::AutoLock lock(observers_lock_);
  delegate_->OnApplicationActivated(url, id);
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    (*it)->OnApplicationInstanceActivated(this, id);
  }
}

void Application::OnApplicationClosed(const std::string& url, int id, int exit_code) {
  //DCHECK_CURRENTLY_ON(GetIOTaskRunner());
  base::AutoLock lock(observers_lock_);
  delegate_->OnApplicationClosed(url, id, exit_code);
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    (*it)->OnApplicationInstanceClosed(this, id, exit_code, std::string());
  }
  RemoveInstance(id);
}

void Application::OnApplicationKilled(const std::string& url, int id, int exit_code) {
  //DCHECK_CURRENTLY_ON(GetIOTaskRunner());
  base::AutoLock lock(observers_lock_);
  delegate_->OnApplicationKilled(url, id, exit_code);
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    (*it)->OnApplicationInstanceKilled(this, id, exit_code, std::string());
  }
  RemoveInstance(id);
}

void Application::OnApplicationLaunchError(const std::string& url, ApplicationInstance* instance, int err_code) {
  //DCHECK_CURRENTLY_ON(GetIOTaskRunner());
  base::AutoLock lock(observers_lock_);
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    (*it)->OnApplicationInstanceLaunchFailed(this, instance->id(), err_code, std::string());
  }
  ChangeInstanceState(instance, ApplicationState::kLAUNCH_ERROR);
} 

void Application::OnApplicationRunError(const std::string& url, ApplicationInstance* instance, int err_code) {
  //DCHECK_CURRENTLY_ON(GetIOTaskRunner());
  base::AutoLock lock(observers_lock_);
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    (*it)->OnApplicationInstanceRunError(this, instance->id(), err_code, std::string());
  }
  RemoveInstance(instance->id());
}

void Application::OnWindowLaunched(const std::string& url, WindowInstance* window) {
  windows_.push_back(window);
}

void Application::OnWindowKilled(const std::string& url, int id) {
  RemoveWindow(id);
}

void Application::RemoveWindow(int id) {
  for (auto it = windows_.begin(); it != windows_.end(); ++it) {
    if ((*it)->id == id) {
      windows_.erase(it);
      return;
    }
  }
}

void Application::RemoveInstance(int id) {
  //DCHECK_CURRENTLY_ON(GetIOTaskRunner());
  base::AutoLock lock(instances_lock_);
  for (auto it = instances_.begin(); it != instances_.end(); ++it) {
    if ((*it)->id() == id) {
      instances_.erase(it);
    }
  }
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    (*it)->OnApplicationInstanceDestroyed(this, id);
  }
}

void Application::ChangeInstanceState(ApplicationInstance* instance, ApplicationState state) {
  //DCHECK_CURRENTLY_ON(GetIOTaskRunner());
  instance->set_state(state);
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    (*it)->OnApplicationInstanceStateChanged(this, instance->id(), state);
  }
}

}