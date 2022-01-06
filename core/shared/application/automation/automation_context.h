// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_APPLICATION_AUTOMATION_AUTOMATION_CONTEXT_H_
#define MUMBA_APPLICATION_AUTOMATION_AUTOMATION_CONTEXT_H_

#include <memory>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/single_thread_task_runner.h"
#include "core/shared/common/content_export.h"
#include "core/shared/application/automation/page_instance.h"
#include "services/service_manager/public/cpp/binder_registry.h"
#include "third_party/blink/renderer/core/inspector/inspected_frames.h"
#include "third_party/blink/public/web/web_frame.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/CoreProbeSink.h"
#include "third_party/blink/renderer/core/inspector/protocol/Protocol.h"
#include "third_party/blink/renderer/core/inspector/inspector_session.h"
#include "third_party/blink/renderer/platform/heap/handle.h"


namespace blink {
class WebFrame;
class WebLocalFrameImpl;
class AssociatedInterfaceRegistry;
}

namespace service_manager {
class InterfaceProvider;
class Service;
}

namespace IPC {
class SyncChannel;
}

namespace common {
class ServiceManagerConnection;
}

namespace application {
class AccessibilityDispatcher;
class AnimationDispatcher;
class ApplicationCacheDispatcher;
class CacheStorageDispatcher;
class CSSDispatcher;
class DatabaseDispatcher;
class DeviceOrientationDispatcher;
class DOMDispatcher;
class DOMSnapshotDispatcher;
class DOMStorageDispatcher;
class EmulationDispatcher;
class HeadlessDispatcher;
class HostDispatcher;
class IndexedDBDispatcher;
class InputDispatcher;
class IODispatcher;
class LayerTreeDispatcher;
class NetworkDispatcher;
class OverlayDispatcher;
class PageDispatcher;
class ServiceWorkerAutomationDispatcher;
class StorageDispatcher;
class SystemInfoDispatcher;
class TargetDispatcher;
class TetheringDispatcher;
class ApplicationWindowDispatcher;


class CONTENT_EXPORT AutomationContext : public blink::InspectorSession::Client {
public:
  AutomationContext(IPC::SyncChannel* channel,
                    ApplicationWindowDispatcher* application_window_dispatcher,
                    common::ServiceManagerConnection* service_manager_connection);

  ~AutomationContext();

  void Init(service_manager::BinderRegistry* registry,
            blink::AssociatedInterfaceRegistry* associated_interface_registry,
            scoped_refptr<base::SingleThreadTaskRunner> task_runner);

  AccessibilityDispatcher* accessibility_dispatcher() const {
    return accessibility_dispatcher_.get();
  }

  AnimationDispatcher* animation_dispatcher() const {
    return animation_dispatcher_.get();
  }

  ApplicationCacheDispatcher* application_cache_dispatcher() const {
    return application_cache_dispatcher_.get();
  }

  CacheStorageDispatcher* cache_storage_dispatcher() const { 
    return cache_storage_dispatcher_.get();
  }

  CSSDispatcher* css_dispatcher() const {
    return css_dispatcher_.get();
  }

  DatabaseDispatcher* database_dispatcher() const {
    return database_dispatcher_.get();
  }

  DeviceOrientationDispatcher* device_orientation_dispatcher() const {
    return device_orientation_dispatcher_.get();
  }

  DOMDispatcher* dom_dispatcher() const {
    return dom_dispatcher_.get();
  }

  DOMSnapshotDispatcher* dom_snapshot_dispatcher() const {
    return dom_snapshot_dispatcher_.get();
  }

  DOMStorageDispatcher* dom_storage_dispatcher() const {
    return dom_storage_dispatcher_.get();
  }

  EmulationDispatcher* emulation_dispatcher() const {
    return emulation_dispatcher_.get();
  }

  HeadlessDispatcher* headless_dispatcher() const { 
    return headless_dispatcher_.get();
  }

  HostDispatcher* host_dispatcher() const {
    return host_dispatcher_.get();
  }

  IndexedDBDispatcher* indexed_db_dispatcher() const { 
    return indexed_db_dispatcher_.get();
  }

  InputDispatcher* input_dispatcher() const {
    return input_dispatcher_.get();
  }

  IODispatcher* io_dispatcher() const {
    return io_dispatcher_.get();
  }

  LayerTreeDispatcher* layer_tree_dispatcher() const {
    return layer_tree_dispatcher_.get();
  }

  NetworkDispatcher* network_dispatcher() const {
    return network_dispatcher_.get();
  }

  OverlayDispatcher* overlay_dispatcher() const {
    return overlay_dispatcher_.get();
  }

  PageDispatcher* page_dispatcher() const {
    return page_dispatcher_.get();
  }

  ServiceWorkerAutomationDispatcher* service_worker_dispatcher() const {
    return service_worker_dispatcher_.get();
  }
  
  StorageDispatcher* storage_dispatcher() const {
    return storage_dispatcher_.get();
  }
  
  SystemInfoDispatcher* system_info_dispatcher() const {
    return system_info_dispatcher_.get();
  }
  
  TargetDispatcher* target_dispatcher() const {
    return target_dispatcher_.get();
  }

  TetheringDispatcher* tethering_dispatcher() const {
    return tethering_dispatcher_.get();
  }

  ApplicationWindowDispatcher* application_window_dispatcher() const {
    return application_window_dispatcher_;
  }
  
  IPC::SyncChannel* channel() const {
    return channel_;
  }

  PageInstance* page_instance() const {
    return page_instance_.get();
  }

  void OnWebFrameCreated(blink::WebLocalFrame* frame);

  
private:

  // std::unique_ptr<service_manager::Service> CreateAccessibilityService(PageInstance* page_instance);
  // std::unique_ptr<service_manager::Service> CreateApplicationCacheService(PageInstance* page_instance);
  // std::unique_ptr<service_manager::Service> CreateCacheStorageService(PageInstance* page_instance);
  // std::unique_ptr<service_manager::Service> CreateDatabaseService(PageInstance* page_instance);
  // std::unique_ptr<service_manager::Service> CreateDeviceOrientationService(PageInstance* page_instance);
  // std::unique_ptr<service_manager::Service> CreateDOMService(PageInstance* page_instance);
  // std::unique_ptr<service_manager::Service> CreateCSSService(PageInstance* page_instance);
  // std::unique_ptr<service_manager::Service> CreateDOMSnapshotService(PageInstance* page_instance);
  // std::unique_ptr<service_manager::Service> CreateDOMStorageService(PageInstance* page_instance);
  // std::unique_ptr<service_manager::Service> CreateEmulationService(PageInstance* page_instance);
  // std::unique_ptr<service_manager::Service> CreateHeadlessService(PageInstance* page_instance);
  // std::unique_ptr<service_manager::Service> CreateHostService(PageInstance* page_instance);
  // std::unique_ptr<service_manager::Service> CreateIndexedDBService(PageInstance* page_instance);
  // std::unique_ptr<service_manager::Service> CreateInputService(PageInstance* page_instance, blink::WebLocalFrameImpl* frame_impl);
  // std::unique_ptr<service_manager::Service> CreateIOService(PageInstance* page_instance);
  // std::unique_ptr<service_manager::Service> CreateLayerTreeService(PageInstance* page_instance);
  // std::unique_ptr<service_manager::Service> CreateNetworkService(PageInstance* page_instance);
  // std::unique_ptr<service_manager::Service> CreateAnimationService(PageInstance* page_instance);
  // std::unique_ptr<service_manager::Service> CreateOverlayService(PageInstance* page_instance, blink::WebLocalFrameImpl* frame_impl);
  // std::unique_ptr<service_manager::Service> CreatePageService(PageInstance* page_instance);
  // std::unique_ptr<service_manager::Service> CreateStorageService(PageInstance* page_instance);
  // std::unique_ptr<service_manager::Service> CreateSystemInfoService(PageInstance* page_instance);
  // std::unique_ptr<service_manager::Service> CreateTetheringService(PageInstance* page_instance);

  void SendProtocolResponse(int session_id,
                            int call_id,
                            const String& response,
                            const String& state) override;
  
  void SendProtocolNotification(int session_id,
                                const String& message) override;

  ApplicationWindowDispatcher* application_window_dispatcher_ = nullptr;
  IPC::SyncChannel* channel_ = nullptr;
  common::ServiceManagerConnection* service_manager_connection_ = nullptr;
  
  std::unique_ptr<AccessibilityDispatcher> accessibility_dispatcher_;
  std::unique_ptr<AnimationDispatcher> animation_dispatcher_;
  std::unique_ptr<ApplicationCacheDispatcher> application_cache_dispatcher_;
  std::unique_ptr<CacheStorageDispatcher> cache_storage_dispatcher_;
  std::unique_ptr<CSSDispatcher> css_dispatcher_;
  std::unique_ptr<DatabaseDispatcher> database_dispatcher_;
  std::unique_ptr<DeviceOrientationDispatcher> device_orientation_dispatcher_;
  std::unique_ptr<DOMDispatcher> dom_dispatcher_;
  std::unique_ptr<DOMSnapshotDispatcher> dom_snapshot_dispatcher_;
  std::unique_ptr<DOMStorageDispatcher> dom_storage_dispatcher_;
  std::unique_ptr<EmulationDispatcher> emulation_dispatcher_;
  std::unique_ptr<HeadlessDispatcher> headless_dispatcher_;
  std::unique_ptr<HostDispatcher> host_dispatcher_;
  std::unique_ptr<IndexedDBDispatcher> indexed_db_dispatcher_;
  std::unique_ptr<InputDispatcher> input_dispatcher_;
  std::unique_ptr<IODispatcher> io_dispatcher_;
  std::unique_ptr<LayerTreeDispatcher> layer_tree_dispatcher_;
  std::unique_ptr<NetworkDispatcher> network_dispatcher_;
  std::unique_ptr<OverlayDispatcher> overlay_dispatcher_;
  std::unique_ptr<PageDispatcher> page_dispatcher_;
  std::unique_ptr<ServiceWorkerAutomationDispatcher> service_worker_dispatcher_;
  std::unique_ptr<StorageDispatcher> storage_dispatcher_;
  std::unique_ptr<SystemInfoDispatcher> system_info_dispatcher_;
  std::unique_ptr<TargetDispatcher> target_dispatcher_;
  std::unique_ptr<TetheringDispatcher> tethering_dispatcher_;
  std::unique_ptr<PageInstance> page_instance_;

  blink::Member<blink::InspectorSession> session_;


  DISALLOW_COPY_AND_ASSIGN(AutomationContext); 
};

}

#endif