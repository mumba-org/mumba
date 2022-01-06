// Copyright 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/application/application_manager.h"

#include "core/shared/domain/application/window_instance.h"
#include "core/domain/domain_context.h"

namespace domain {

namespace {

// std::string GetApplicationNameFromURL(const std::string& url) {
//   std::string name;
//   size_t pos = url.find("://");
//   if (pos == std::string::npos) {
//     return name;
//   }
//   name = url.substr(pos + 3);
//   size_t last_pos = name.find("/");
//   if (last_pos == std::string::npos) {
//     return name;
//   }
//   return name.substr(0, last_pos);
// }

std::string GetApplicationNameFromURL(const std::string& url) {
  std::string name;
  size_t pos = url.find("://");
  if (pos == std::string::npos) {
    return name;
  }
  return url.substr(0, pos);
}

}

ApplicationManager::ApplicationManager(
  scoped_refptr<DomainContext> context, 
  scoped_refptr<base::SingleThreadTaskRunner> io_task_runner,
  IPC::SyncChannel* ipc_channel,
  blink::AssociatedInterfaceRegistry* associated_interface_registry):
  context_(context),
  io_task_runner_(io_task_runner),
  ipc_channel_(ipc_channel),
  associated_interface_registry_(associated_interface_registry) {

}

ApplicationManager::~ApplicationManager() {
  //DLOG(INFO) << "~ApplicationManager";
  for (auto it = instances_.begin(); it != instances_.end(); ++it) {
    delete it->second;
  }
  instances_.clear();
  context_ = nullptr;
}

Application* ApplicationManager::CreateApplication(
  const std::string& name, 
  const base::UUID& id, 
  GURL url) {
  //DLOG(INFO) << "ApplicationManager: adding app '" << name << "' => " << id.to_string();
  base::AutoLock lock(apps_lock_);
  std::unique_ptr<Application> app = std::make_unique<Application>(this, name, id, std::move(url));
  Application* app_handle = app.get();
  applications_.emplace(std::make_pair(name, std::move(app)));
  return app_handle;
}

Application* ApplicationManager::GetApplication(const std::string& name) {
  base::AutoLock lock(apps_lock_);
  auto found_it = applications_.find(name);
  if (found_it != applications_.end()) {
    return found_it->second.get();
  }
  return nullptr;
}

Application* ApplicationManager::GetApplicationByUrl(const std::string& url_string) {
  base::AutoLock lock(apps_lock_);
  std::string name = GetApplicationNameFromURL(url_string);
  //DLOG(INFO) << "GetApplicationByUrl: finding app by name: '" << name << "'";
  if (name.empty()) {
    //DLOG(ERROR) << "GetApplicationByUrl: failed. name is empty. original url = '" << url_string << "'";
    return nullptr;
  }
  auto found_it = applications_.find(name);
  if (found_it != applications_.end()) {
    //DLOG(INFO) << "GetApplicationByUrl: app found. returning it"; 
    return found_it->second.get();
  }
  //DLOG(INFO) << "GetApplicationByUrl: not found"; 
  return nullptr;
}

void ApplicationManager::RemoveApplication(const std::string& name) {
  base::AutoLock lock(apps_lock_);
  apps_lock_.Acquire();
  auto found_it = applications_.find(name);
  if (found_it != applications_.end()) {
    applications_.erase(found_it);
  }
  apps_lock_.Release();
}

void ApplicationManager::CreateApplicationInstance(
  std::unique_ptr<ApplicationInstance> instance, 
  Application* parent, 
  int32_t id, 
  const std::string& url,
  WindowMode window_mode,
  gfx::Rect initial_bounds,
  ui::mojom::WindowOpenDisposition window_open_disposition,
  bool fullscreen,
  bool headless) {
  //DLOG(INFO) << "ApplicationManager::CreateApplicationInstance: url: [" << url.size() << "] '" << url << "'";
  if (!parent) {
    //DLOG(ERROR) << "ApplicationManager::CreateApplicationInstance: no parent for app. returning null";
    return;
  }
  //int id = instance_id_gen_.GetNext() + 1;
  // FIX: weird bug: moving the unique ptr is not working and the heap
  //      is getting destroyed, so we are using new here instead
  //std::unique_ptr<ApplicationInstance> instance = std::make_unique<ApplicationInstance>();
  instance->set_id(id);
  instance->set_application(parent);
  instance->set_url(url);
  instance->set_uuid(base::UUID::generate());
  instance->set_window_mode(window_mode);
  instance->set_initial_bounds(initial_bounds);
  instance->set_window_open_disposition(window_open_disposition);
  instance->set_fullscreen(fullscreen);
  instance->set_headless(headless);
  AddApplicationInstance(std::move(instance));
}

ApplicationInstance* ApplicationManager::CreateApplicationInstance(
  const std::string& parent_name, 
  int32_t id, 
  const std::string& url,
  WindowMode window_mode,
  gfx::Rect initial_bounds,
  ui::mojom::WindowOpenDisposition window_open_disposition,
  bool fullscreen,
  bool headless) {
  Application* app = GetApplication(parent_name);
  if (!app) {
    //DLOG(ERROR) << "ApplicationManager::CreateApplicationInstance: the application for '" << parent_name << "' was not found. therefore we couldny launch an instance of it";
    return nullptr; 
  }
  std::unique_ptr<ApplicationInstance> instance = std::make_unique<ApplicationInstance>();
  ApplicationInstance* result = instance.get();
  CreateApplicationInstance(std::move(instance), app, id, url, window_mode, initial_bounds, window_open_disposition, fullscreen, headless);
  return result;
}

ApplicationInstance* ApplicationManager::GetApplicationInstance(int id) {
  base::AutoLock lock(instances_lock_);
  auto found_it = instances_.find(id);
  return found_it != instances_.end() ? found_it->second : nullptr;
}

void ApplicationManager::AddApplicationInstance(std::unique_ptr<ApplicationInstance> instance) {
  int id = instance->id();
  //instances_lock_.Acquire();
  instances_.emplace(std::make_pair(id, instance.release()));
  //instances_lock_.Release();
}

void ApplicationManager::RemoveApplicationInstance(int id) {
  //DLOG(INFO) << "ApplicationManager::RemoveApplicationInstance";
  base::AutoLock lock(instances_lock_);
  auto found = instances_.find(id);
  if (found != instances_.end()) {
    delete found->second;
    instances_.erase(found);
  }
}

WindowInstance* ApplicationManager::GetWindowInstance(int id) {
  base::AutoLock lock(windows_lock_);
  auto found_it = windows_.find(id);
  return found_it != windows_.end() ? found_it->second.get() : nullptr;
}

void ApplicationManager::AddWindowInstance(std::unique_ptr<WindowInstance> window) {
  base::AutoLock lock(windows_lock_);
  
  int id = window_id_gen_.GetNext() + 1;
  window->id = id;
  windows_.emplace(id, std::move(window));
}

void ApplicationManager::RemoveWindowInstance(int id) {
  base::AutoLock lock(windows_lock_);
  
  auto found = windows_.find(id);
  if (found != windows_.end()) {
    windows_.erase(found);
  }
}

ApplicationManagerClient* ApplicationManager::application_manager_client() const {
  return context_->application_manager_client();
}

common::mojom::ApplicationManagerHost* ApplicationManager::GetApplicationManagerHost() {
  return context_->GetApplicationManagerHost();
}

void ApplicationManager::OnApplicationLaunched(const std::string& url, ApplicationInstance* instance) {

}

void ApplicationManager::OnApplicationKilled(const std::string& url, int id, int exit_code) {
  //DLOG(INFO) << "ApplicationManager::OnApplicationKilled";
  RemoveApplicationInstance(id);
}

void ApplicationManager::OnApplicationActivated(const std::string& url, int id) {

}

void ApplicationManager::OnApplicationClosed(const std::string& url, int id, int exit_code) {
  //DLOG(INFO) << "ApplicationManager::OnApplicationClosed";
  RemoveApplicationInstance(id);
}

void ApplicationManager::OnApplicationLaunchError(const std::string& url, int err_code) {

}

void ApplicationManager::OnApplicationRunError(const std::string& url, int id, int err_code) {

}

}