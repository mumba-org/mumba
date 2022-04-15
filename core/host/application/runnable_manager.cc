// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/runnable_manager.h"

#include "core/host/application/domain.h"
#include "core/host/application/application.h"
#include "core/host/application/application.h"
#include "core/host/workspace/workspace.h"

namespace host {

RunnableManager::RunnableManager(scoped_refptr<Workspace> workspace): workspace_(std::move(workspace)) {

}

RunnableManager::~RunnableManager() {

}

void RunnableManager::Shutdown() {
  
}

Application* RunnableManager::NewApplication(
  Domain* domain,
  int id, 
  const std::string& name, 
  const GURL& url, 
  const base::UUID& uuid, 
  Dock::Type window_mode,
  gfx::Rect initial_bounds,
  WindowOpenDisposition window_open_disposition,
  bool fullscreen,
  bool headless) {
  std::unique_ptr<Application> app = std::make_unique<Application>(
    this, 
    domain,
    id, 
    name, 
    url, 
    uuid, 
    window_mode,
    initial_bounds,
    window_open_disposition,
    fullscreen,
    headless);

  Application* app_handle = app.get();
  runnables_lock_.Acquire();
  runnable_names_.emplace(std::make_pair(name, id));
  runnables_.emplace(std::make_pair(id, std::move(app)));
  runnables_lock_.Release();
  return app_handle;
}

Runnable* RunnableManager::GetRunnable(int id) {
  base::AutoLock lock(runnables_lock_);
  auto it = runnables_.find(id);
  if (it != runnables_.end()) {
    return it->second.get();
  }
  return nullptr;
}

Runnable* RunnableManager::GetRunnable(const base::UUID& id) {
  for (auto it = runnables_.begin(); it != runnables_.end(); it++) {
    if (it->second->id() == id) {
      return it->second.get();
    }
  }
  return nullptr;
}

Runnable* RunnableManager::GetRunnable(const std::string& name) {
  base::AutoLock lock(runnables_lock_);
  auto name_it = runnable_names_.find(name);
  if (name_it == runnable_names_.end()) {
    return nullptr;
  }
  return runnables_.find(name_it->second)->second.get();
}

std::vector<Runnable*> RunnableManager::GetRunnablesForDomain(const std::string& domain_name) {
  base::AutoLock lock(runnables_lock_);
  std::vector<Runnable*> result;
  for (auto it = runnables_.begin(); it != runnables_.end(); ++it) {
    if (domain_name == it->second->domain()->name()) {
      result.push_back(it->second.get());
    }
  }
  return result;
}

int RunnableManager::GetRunnableCountForDomain(const std::string& domain_name) {
  base::AutoLock lock(runnables_lock_);
  int count = 0;
  for (auto it = runnables_.begin(); it != runnables_.end(); ++it) {
    if (domain_name == it->second->domain()->name()) {
      count++;
    }
  }
  return count;
}

bool RunnableManager::HaveRunnable(int id) {
  base::AutoLock lock(runnables_lock_);
  auto it = runnables_.find(id);
  if (it != runnables_.end()) {
    return true;
  }
  return false;
}

bool RunnableManager::HaveRunnable(const base::UUID& id) {
  for (auto it = runnables_.begin(); it != runnables_.end(); it++) {
    if (it->second->id() == id) {
      return true;
    }
  }
  return false;
}

bool RunnableManager::HaveRunnable(const std::string& name) {
  base::AutoLock lock(runnables_lock_);
  auto name_it = runnable_names_.find(name);
  if (name_it == runnable_names_.end()) {
    return true;
  }
  return false;
}

void RunnableManager::RemoveRunnable(int id) {
  base::AutoLock lock(runnables_lock_);
  auto it = runnables_.find(id);
  if (it == runnables_.end()) {
    return;
  }
  auto name_it = runnable_names_.find(it->second->name());
  if (name_it != runnable_names_.end()) {
    runnable_names_.erase(name_it);
  }
  runnables_.erase(it);
}

void RunnableManager::RemoveRunnable(Runnable* runnable) {
  RemoveRunnable(runnable->rid());  
}

const google::protobuf::Descriptor* RunnableManager::resource_descriptor() {
  Schema* schema = workspace_->schema_registry()->GetSchemaByName("objects.proto");
  DCHECK(schema);
  return schema->GetMessageDescriptorNamed("Application");
}

std::string RunnableManager::resource_classname() const {
  return Runnable::kClassName;
}

}