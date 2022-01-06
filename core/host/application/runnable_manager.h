// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_RUNNABLE_MANAGER_H_
#define MUMBA_HOST_APPLICATION_RUNNABLE_MANAGER_H_

#include <string>
#include <memory>
#include <vector>
#include <map>
#include <unordered_map>

#include "base/macros.h"
#include "base/uuid.h"
#include "base/synchronization/lock.h"
#include "core/shared/common/mojom/application.mojom.h"
#include "core/host/serializable.h"
#include "core/common/proto/objects.pb.h"
#include "core/host/ui/dock.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "ui/base/window_open_disposition.h"

namespace host {
class Application;
class Runnable;
class Domain;

class RunnableManager {
public:
  RunnableManager();
  ~RunnableManager();

  // const std::map<int, std::unique_ptr<Runnable>>& runnables() const {
  //   return runnables_;
  // }

  Runnable* GetRunnable(int id);
  Runnable* GetRunnable(const std::string& name);
  std::vector<Runnable*> GetRunnablesForDomain(const std::string& domain_name);
  int GetRunnableCountForDomain(const std::string& domain_name);
  bool HaveRunnable(int id);
  bool HaveRunnable(const std::string& name);
  void RemoveRunnable(int id);
  void RemoveRunnable(Runnable* runnable);

  Application* NewApplication(
    Domain* domain,
    int id, 
    const std::string& name, 
    const GURL& url, 
    const base::UUID& uuid, 
    Dock::Type window_mode,
    gfx::Rect initial_bounds,
    WindowOpenDisposition window_open_disposition,
    bool fullscreen,
    bool headless);

  void Shutdown();
  
private:

  base::Lock runnables_lock_; 
  std::map<int, std::unique_ptr<Runnable>> runnables_;
  std::unordered_map<std::string, int> runnable_names_;

  DISALLOW_COPY_AND_ASSIGN(RunnableManager);
};

}

#endif