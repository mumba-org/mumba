// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_APPLICATION_APPLICATION_H_
#define MUMBA_DOMAIN_APPLICATION_APPLICATION_H_

#include "base/macros.h"
#include "base/uuid.h"
#include "core/shared/domain/application/application_controller.h"
#include "core/shared/domain/application/window_instance.h"
#include "core/shared/common/content_export.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "mojo/public/cpp/bindings/associated_binding_set.h"
#include "mojo/public/cpp/bindings/interface_ptr.h"
#include "ui/base/mojo/window_open_disposition.mojom.h"
#include "third_party/blink/public/common/associated_interfaces/associated_interface_registry.h"
// for callbacks
#include "runtime/MumbaShims/EngineShims.h"

namespace IPC {
class SyncChannel;  
}

namespace blink {
class AssociatedInterfaceRegistry;  
}

namespace domain {
class Application;
class ApplicationDriver;

/*
 * This represents a registered application.
 * Theres one instance for each application this host have
 * For running applications theres the ApplicationInstance
 * and this singleton-per-application state have a one-to-many
 * relationship with them
 */

class CONTENT_EXPORT Application : public ApplicationController::Delegate {
public:
  class CONTENT_EXPORT Delegate {
  public:
    virtual ~Delegate() {}
    virtual scoped_refptr<base::SingleThreadTaskRunner> GetIOTaskRunner() const = 0;
    virtual common::mojom::ApplicationManagerHost* GetApplicationManagerHost() = 0;
    virtual IPC::SyncChannel* GetChannel() = 0;
    virtual blink::AssociatedInterfaceRegistry* GetAssociatedInterfaceRegistry() const = 0;
    virtual void CreateApplicationInstance(std::unique_ptr<ApplicationInstance> instance, 
      Application* parent, 
      int32_t id, 
      const std::string& url,
      WindowMode window_mode,
      gfx::Rect initial_bounds,
      ui::mojom::WindowOpenDisposition window_open_disposition,
      bool fullscreen,
      bool headless) = 0;
    virtual void OnApplicationLaunched(const std::string& url, ApplicationInstance* instance) = 0;
    virtual void OnApplicationKilled(const std::string& url, int id, int exit_code) = 0;
    virtual void OnApplicationActivated(const std::string& url, int id) = 0;
    virtual void OnApplicationClosed(const std::string& url, int id, int exit_code) = 0;
    virtual void OnApplicationLaunchError(const std::string& url, int err_code) = 0;
    virtual void OnApplicationRunError(const std::string& url, int id, int err_code) = 0;
  };
  class CONTENT_EXPORT Observer {
  public:
    virtual ~Observer() {}
    virtual void* state() const = 0;
    virtual void OnApplicationInstanceCreated(Application* app, ApplicationInstance* app_instance) = 0;
    virtual void OnApplicationInstanceDestroyed(Application* app, int id) = 0;
    virtual void OnApplicationInstanceLaunched(Application* app, int id) = 0;
    virtual void OnApplicationInstanceLaunchFailed(Application* app, int id, int err_code, const std::string& message) = 0;
    virtual void OnApplicationInstanceKilled(Application* app, int id, int exit_code, const std::string& message) = 0;
    virtual void OnApplicationInstanceClosed(Application* app, int id, int exit_code, const std::string& message) = 0;
    virtual void OnApplicationInstanceActivated(Application* app, int id) = 0;
    virtual void OnApplicationInstanceRunError(Application* app, int id, int err_code, const std::string& message) = 0;
    virtual void OnApplicationInstanceStateChanged(Application* app, int id, ApplicationState app_state) = 0;
    virtual void OnApplicationInstanceBoundsChanged(Application* app, int id, const gfx::Size& bounds) = 0;
    virtual void OnApplicationInstanceVisible(Application* app, int id) = 0;
    virtual void OnApplicationInstanceHidden(Application* app, int id) = 0;
  };
  
  Application(
    Delegate* delegate, 
    const std::string& name, 
    const base::UUID& uuid,
    GURL url);
  
  ~Application() override;

  const std::string& name() const {
    return name_;
  }

  const base::UUID& uuid() const {
    return uuid_;
  }

  const GURL& url() const {
    return url_;
  }

  scoped_refptr<base::SingleThreadTaskRunner> GetIOTaskRunner() const override;

  IPC::SyncChannel* GetChannel();

  blink::AssociatedInterfaceRegistry* GetAssociatedInterfaceRegistry() const;

  ApplicationDriver* GetDriver(int id) const;

  const CPageCallbacks& page_callbacks() const {
    return page_callbacks_;
  }

  const COverlayCallbacks& overlay_callbacks() const {
    return overlay_callbacks_;
  }

  const CWorkerCallbacks& worker_callbacks() const {
    return worker_callbacks_;
  }

  const CStorageCallbacks& storage_callbacks() const {
    return storage_callbacks_;
  }

  const CTetheringCallbacks& tethering_callbacks() const {
    return tethering_callbacks_;
  }

  const CNetworkCallbacks& network_callbacks() const {
    return network_callbacks_;
  }

  const CLayerTreeCallbacks& layer_tree_callbacks() const {
    return layer_tree_callbacks_;
  }

  const CHeadlessCallbacks& headless_callbacks() const {
    return headless_callbacks_;
  }

  const CDOMStorageCallbacks& dom_storage_callbacks() const {
    return dom_storage_callbacks_;
  }

  const CDatabaseCallbacks& database_callbacks() const {
    return database_callbacks_;
  }

  const CEmulationCallbacks& emulation_callbacks() const { 
    return emulation_callbacks_;
  }
  
  const CDOMCallbacks& dom_callbacks() const {
    return dom_callbacks_;
  }

  const CCSSCallbacks& css_callbacks() const {
    return css_callbacks_;
  }

  const CApplicationCacheCallbacks& application_cache_callback() const {
    return application_cache_callbacks_;
  }

  const CAnimationCallbacks& animation_callbacks() const {
    return animation_callbacks_;
  }

  bool is_running() {
    return instance_count() > 0;
  }

  size_t instance_count();

  int CreateInstance(
    int32_t id, 
    const std::string& url, 
    WindowMode window_mode,
    gfx::Rect initial_bounds,
    ui::mojom::WindowOpenDisposition window_open_disposition,
    bool fullscreen,
    bool headless);

  void KillInstance(int id);
  void CloseInstance(int id);
  void ActivateInstance(int id);

  ApplicationInstance* GetInstance(int id);
  WindowInstance* GetWindow(int id) const;

  const std::vector<ApplicationInstance *>& instances() {
    return instances_;
  }

  void AddObserver(Observer* observer);
  void RemoveObserver(Observer* observer);

  void set_driver_state(int id, void* state);

  CPageCallbacks page_callbacks_;
  COverlayCallbacks overlay_callbacks_;
  CWorkerCallbacks worker_callbacks_;
  CStorageCallbacks storage_callbacks_;
  CTetheringCallbacks tethering_callbacks_;
  CNetworkCallbacks network_callbacks_;
  CLayerTreeCallbacks layer_tree_callbacks_;
  CHeadlessCallbacks headless_callbacks_;
  CDOMStorageCallbacks dom_storage_callbacks_;
  CDatabaseCallbacks database_callbacks_;
  CEmulationCallbacks emulation_callbacks_;
  CDOMCallbacks dom_callbacks_;
  CCSSCallbacks css_callbacks_;
  CApplicationCacheCallbacks application_cache_callbacks_;
  CAnimationCallbacks animation_callbacks_;

  // Templated helper for AddInterface() above.
  // template <typename Interface>
  // void AddInterface(const std::string& name, const blink::AssociatedInterfaceRegistry::InterfaceBinder<Interface>& binder) {
  //   AddInterface(name,
  //                base::BindRepeating(&BindInterface<Interface>, binder));
  // }

private:

  // called by ApplicationController
  common::mojom::ApplicationManagerHost* GetApplicationManagerHost() override;
  ApplicationInstance* CreateApplicationInstance(
    Application* parent, 
    int32_t id, 
    const std::string& url,
    WindowMode window_mode,
    gfx::Rect initial_bounds,
    ui::mojom::WindowOpenDisposition window_open_disposition,
    bool fullscreen,
    bool headless) override;
  void OnApplicationLaunched(const std::string& url, ApplicationInstance* instance) override;
  void OnApplicationKilled(const std::string& url, int id, int exit_code) override;
  void OnApplicationActivated(const std::string& url, int id) override;
  void OnApplicationClosed(const std::string& url, int id, int exit_code) override;
  void OnApplicationLaunchError(const std::string& url, ApplicationInstance* instance, int err_code) override;
  void OnApplicationRunError(const std::string& url, ApplicationInstance* instance, int err_code) override;
  void OnWindowLaunched(const std::string& url, WindowInstance* instance) override;
  void OnWindowKilled(const std::string& url, int id) override;

  void RemoveWindow(int id);
  void RemoveInstance(int id);

  void ChangeInstanceState(ApplicationInstance* instance, ApplicationState state);

  void NotifyApplicationInstanceCreated(ApplicationInstance* instance);

  template <typename Interface>
  static void BindInterface(const blink::AssociatedInterfaceRegistry::InterfaceBinder<Interface>& binder,
                            mojo::ScopedInterfaceEndpointHandle handle) {
    binder.Run(mojo::AssociatedInterfaceRequest<Interface>(std::move(handle)));
  }

  Delegate* delegate_;
  
  ApplicationController controller_;

  std::string name_;

  base::UUID uuid_;

  GURL url_;

  std::vector<Observer*> observers_;

  std::vector<ApplicationInstance *> instances_;

  std::vector<WindowInstance *> windows_;

  std::unordered_map<int, std::unique_ptr<ApplicationDriver>> drivers_;

  base::Lock observers_lock_;
  base::Lock instances_lock_;
  
  DISALLOW_COPY_AND_ASSIGN(Application);
};

}

#endif