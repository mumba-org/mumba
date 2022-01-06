// Copyright 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_APPLICATION_APPLICATION_MANAGER_H_
#define MUMBA_DOMAIN_APPLICATION_APPLICATION_MANAGER_H_

#include "base/macros.h"
#include "base/uuid.h"
#include "base/atomic_sequence_num.h"
#include "base/synchronization/lock.h"
#include "core/shared/common/mojom/application.mojom.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "core/shared/domain/application/application.h"
#include "core/shared/domain/application/application_instance.h"

namespace blink {
class AssociatedInterfaceRegistry;
}

namespace domain {
class DomainContext;
struct WindowInstance;
class ApplicationManagerClient;

class ApplicationManager : public Application::Delegate {
public:
  ApplicationManager(
    scoped_refptr<DomainContext> context, 
    scoped_refptr<base::SingleThreadTaskRunner> io_task_runner,
    IPC::SyncChannel* ipc_channel,
    blink::AssociatedInterfaceRegistry* associated_interface_registry);
  ~ApplicationManager();

  scoped_refptr<base::SingleThreadTaskRunner> GetIOTaskRunner() const override {
    return io_task_runner_;
  }

  IPC::SyncChannel* GetChannel() override {
    return ipc_channel_;
  }

  blink::AssociatedInterfaceRegistry* GetAssociatedInterfaceRegistry() const override {
    return associated_interface_registry_;
  }

  Application* CreateApplication(const std::string& name, const base::UUID& id, GURL url);
  Application* GetApplication(const std::string& name);
  Application* GetApplicationByUrl(const std::string& url_string);
  void RemoveApplication(const std::string& name);

  void CreateApplicationInstance(
    std::unique_ptr<ApplicationInstance> instance, 
    Application* parent, 
    int32_t id, 
    const std::string& url,
    WindowMode window_mode,
    gfx::Rect initial_bounds,
    ui::mojom::WindowOpenDisposition window_open_disposition,
    bool fullscreen,
    bool headless) override;

  ApplicationInstance* CreateApplicationInstance(
    const std::string& parent_name, 
    int32_t id, 
    const std::string& url,
    WindowMode window_mode,
    gfx::Rect initial_bounds,
    ui::mojom::WindowOpenDisposition window_open_disposition,
    bool fullscreen,
    bool headless);
    
  ApplicationInstance* GetApplicationInstance(int id);
  void AddApplicationInstance(std::unique_ptr<ApplicationInstance> instance);
  void RemoveApplicationInstance(int id);

  WindowInstance* GetWindowInstance(int id);
  void AddWindowInstance(std::unique_ptr<WindowInstance> window);
  void RemoveWindowInstance(int id);

  // helpers
  ApplicationManagerClient* application_manager_client() const;
  common::mojom::ApplicationManagerHost* GetApplicationManagerHost() override;

  // Note: sharing this outside of this class defeats the locks.
  const std::unordered_map<std::string, std::unique_ptr<Application>>& applications() const {
    return applications_;
  }
 
private:

  // Application::Delegate

  void OnApplicationLaunched(const std::string& url, ApplicationInstance* instance) override;
  void OnApplicationKilled(const std::string& url, int id, int exit_code) override;
  void OnApplicationClosed(const std::string& url, int id, int exit_code) override;
  void OnApplicationActivated(const std::string& url, int id) override;
  void OnApplicationLaunchError(const std::string& url, int err_code) override;
  void OnApplicationRunError(const std::string& url, int id, int err_code) override;
   
  scoped_refptr<DomainContext> context_;
  scoped_refptr<base::SingleThreadTaskRunner> io_task_runner_;

  base::AtomicSequenceNumber instance_id_gen_;
  base::AtomicSequenceNumber window_id_gen_;

  base::Lock apps_lock_;
  base::Lock instances_lock_;
  base::Lock windows_lock_;

  std::unordered_map<std::string, std::unique_ptr<Application>> applications_;
  std::map<int, ApplicationInstance*> instances_;
  std::map<int, std::unique_ptr<WindowInstance>> windows_;

  IPC::SyncChannel* ipc_channel_;
  blink::AssociatedInterfaceRegistry* associated_interface_registry_;

  DISALLOW_COPY_AND_ASSIGN(ApplicationManager);
};

}

#endif