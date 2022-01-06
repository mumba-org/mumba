// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/automation_context.h"

#include "core/shared/application/automation/accessibility_dispatcher.h"
#include "core/shared/application/automation/animation_dispatcher.h"
#include "core/shared/application/automation/application_cache_dispatcher.h"
#include "core/shared/application/automation/cache_storage_dispatcher.h"
#include "core/shared/application/automation/css_dispatcher.h"
#include "core/shared/application/automation/database_dispatcher.h"
#include "core/shared/application/automation/device_orientation_dispatcher.h"
#include "core/shared/application/automation/dom_dispatcher.h"
#include "core/shared/application/automation/dom_snapshot_dispatcher.h"
#include "core/shared/application/automation/dom_storage_dispatcher.h"
#include "core/shared/application/automation/emulation_dispatcher.h"
#include "core/shared/application/automation/headless_dispatcher.h"
#include "core/shared/application/automation/host_dispatcher.h"
#include "core/shared/application/automation/indexed_db_dispatcher.h"
#include "core/shared/application/automation/input_dispatcher.h"
#include "core/shared/application/automation/io_dispatcher.h"
#include "core/shared/application/automation/layer_tree_dispatcher.h"
#include "core/shared/application/automation/network_dispatcher.h"
#include "core/shared/application/automation/overlay_dispatcher.h"
#include "core/shared/application/automation/page_dispatcher.h"
#include "core/shared/application/automation/page_instance.h"
#include "core/shared/application/automation/service_worker_automation_dispatcher.h"
#include "core/shared/application/automation/storage_dispatcher.h"
#include "core/shared/application/automation/system_info_dispatcher.h"
#include "core/shared/application/automation/target_dispatcher.h"
#include "core/shared/application/automation/tethering_dispatcher.h"
#include "core/shared/application/application_window_dispatcher.h"
#include "core/shared/common/service_manager/service_manager_connection_impl.h"
#include "services/service_manager/public/cpp/connector.h"
#include "services/service_manager/public/cpp/interface_provider.h"
#include "services/service_manager/runner/common/client_util.h"
#include "services/service_manager/sandbox/sandbox_type.h"
#include "services/service_manager/public/cpp/service_context.h"
#include "services/metrics/public/cpp/mojo_ukm_recorder.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/public/web/web_frame.h"
#include "third_party/blink/public/common/associated_interfaces/associated_interface_registry.h"
#include "third_party/blink/renderer/core/core_initializer.h"
#include "third_party/blink/renderer/core/CoreProbeSink.h"

namespace application {

AutomationContext::AutomationContext(IPC::SyncChannel* channel,
                                     ApplicationWindowDispatcher* application_window_dispatcher,
                                     common::ServiceManagerConnection* service_manager_connection):
                                     application_window_dispatcher_(application_window_dispatcher),
                                     channel_(channel) {
  service_manager_connection_ = service_manager_connection;
}

AutomationContext::~AutomationContext() {

}

void AutomationContext::Init(service_manager::BinderRegistry* registry,
                             blink::AssociatedInterfaceRegistry* associated_registry,
                             scoped_refptr<base::SingleThreadTaskRunner> task_runner) {

  //blink::WebFrame* web_frame = application_window_dispatcher_->GetMainWebFrame(); 
  page_instance_ = PageInstance::Create();

 // blink::WebLocalFrameImpl* frame_impl = static_cast<blink::WebLocalFrameImpl*>(
 //     blink::WebFrame::FromFrame(page_instance_->inspected_frames()->Root()));
  
  accessibility_dispatcher_.reset(new AccessibilityDispatcher(page_instance()));
  application_cache_dispatcher_.reset(new ApplicationCacheDispatcher(page_instance()));
  cache_storage_dispatcher_.reset(new CacheStorageDispatcher(page_instance()));
  database_dispatcher_.reset(new DatabaseDispatcher(this, page_instance()));
  device_orientation_dispatcher_.reset(new DeviceOrientationDispatcher(page_instance()));
  dom_dispatcher_.reset(new DOMDispatcher(page_instance()));
  css_dispatcher_.reset(new CSSDispatcher(this, page_instance()));
  dom_snapshot_dispatcher_.reset(new DOMSnapshotDispatcher(page_instance()));
  dom_storage_dispatcher_.reset(new DOMStorageDispatcher(page_instance()));
  emulation_dispatcher_.reset(new EmulationDispatcher(page_instance()));
  headless_dispatcher_.reset(new HeadlessDispatcher(page_instance()));
  host_dispatcher_.reset(new HostDispatcher(page_instance()));
  indexed_db_dispatcher_.reset(new IndexedDBDispatcher(page_instance()));
  input_dispatcher_.reset(new InputDispatcher(page_instance()));
  io_dispatcher_.reset(new IODispatcher(page_instance()));
  layer_tree_dispatcher_.reset(new LayerTreeDispatcher(page_instance()));
  network_dispatcher_.reset(new NetworkDispatcher(page_instance()));
  animation_dispatcher_.reset(new AnimationDispatcher(this, page_instance()));
  overlay_dispatcher_.reset(new OverlayDispatcher(
       page_instance(), 
       dom_dispatcher_.get()));
  page_dispatcher_.reset(new PageDispatcher(application_window_dispatcher_, page_instance()));
  //service_worker_dispatcher_.reset(new DispatcherWorkerAutomationDispatcher(page_instance()));
  storage_dispatcher_.reset(new StorageDispatcher(page_instance()));
  system_info_dispatcher_.reset(new SystemInfoDispatcher(page_instance()));
  //target_dispatcher_.reset(new TargetDispatcher(page_instance()));
  tethering_dispatcher_.reset(new TetheringDispatcher(page_instance()));
 
  associated_registry->AddInterface(
      base::BindRepeating(&AccessibilityDispatcher::Bind,
                          base::Unretained(accessibility_dispatcher())));

  associated_registry->AddInterface(
      base::BindRepeating(&AnimationDispatcher::Bind,
                          base::Unretained(animation_dispatcher())));

  associated_registry->AddInterface(
      base::BindRepeating(&ApplicationCacheDispatcher::Bind,
                          base::Unretained(application_cache_dispatcher())));

  associated_registry->AddInterface(
      base::BindRepeating(&CacheStorageDispatcher::Bind,
                          base::Unretained(cache_storage_dispatcher())));

  associated_registry->AddInterface(
      base::BindRepeating(&CSSDispatcher::Bind,
                          base::Unretained(css_dispatcher())));

  associated_registry->AddInterface(
      base::BindRepeating(&DatabaseDispatcher::Bind,
                          base::Unretained(database_dispatcher())));

  associated_registry->AddInterface(
      base::BindRepeating(&DeviceOrientationDispatcher::Bind,
                          base::Unretained(device_orientation_dispatcher())));

  associated_registry->AddInterface(
      base::BindRepeating(&DOMDispatcher::BindMojo,
                          base::Unretained(dom_dispatcher())));

  associated_registry->AddInterface(
      base::BindRepeating(&DOMStorageDispatcher::Bind,
                          base::Unretained(dom_storage_dispatcher())));

  associated_registry->AddInterface(
      base::BindRepeating(&EmulationDispatcher::Bind,
                          base::Unretained(emulation_dispatcher())));
  
  associated_registry->AddInterface(
      base::BindRepeating(&HeadlessDispatcher::Bind,
                          base::Unretained(headless_dispatcher())));
  
  associated_registry->AddInterface(
      base::BindRepeating(&HostDispatcher::Bind,
                          base::Unretained(host_dispatcher())));
  
  associated_registry->AddInterface(
      base::BindRepeating(&IndexedDBDispatcher::Bind,
                          base::Unretained(indexed_db_dispatcher())));
  
  associated_registry->AddInterface(
      base::BindRepeating(&InputDispatcher::Bind,
                          base::Unretained(input_dispatcher())));
  
  associated_registry->AddInterface(
      base::BindRepeating(&IODispatcher::Bind,
                          base::Unretained(io_dispatcher())));
  
  associated_registry->AddInterface(
      base::BindRepeating(&LayerTreeDispatcher::Bind,
                          base::Unretained(layer_tree_dispatcher())));

  associated_registry->AddInterface(
      base::BindRepeating(&NetworkDispatcher::Bind,
                          base::Unretained(network_dispatcher())));

  associated_registry->AddInterface(
      base::BindRepeating(&OverlayDispatcher::Bind,
                          base::Unretained(overlay_dispatcher())));

  associated_registry->AddInterface(
      base::BindRepeating(&PageDispatcher::Bind,
                          base::Unretained(page_dispatcher())));

  
//   associated_registry->AddInterface(
//       base::BindRepeating(&DispatcherrWorkerAutomationDispatcher::Bind,
//                           base::Unretained(service_worker_dispatcher())));


  associated_registry->AddInterface(
      base::BindRepeating(&StorageDispatcher::Bind,
                          base::Unretained(storage_dispatcher())));
  
  associated_registry->AddInterface(
      base::BindRepeating(&SystemInfoDispatcher::Bind,
                          base::Unretained(system_info_dispatcher())));

//   associated_registry->AddInterface(
//       base::BindRepeating(&TargetDispatcher::Bind,
//                           base::Unretained(target_dispatcher())));

  associated_registry->AddInterface(
      base::BindRepeating(&TetheringDispatcher::BindMojo,
                          base::Unretained(tethering_dispatcher())));

  accessibility_dispatcher()->Init(channel_);
  animation_dispatcher()->Init(channel_);
  page_dispatcher()->Init(channel_);
  application_cache_dispatcher()->Init(channel_);
  cache_storage_dispatcher()->Init(channel_);
  css_dispatcher()->Init(channel_);
  database_dispatcher()->Init(channel_);
  device_orientation_dispatcher()->Init(channel_);
  dom_dispatcher()->Init(channel_);
  dom_snapshot_dispatcher()->Init(channel_);
  dom_storage_dispatcher()->Init(channel_);
  emulation_dispatcher()->Init(channel_);
  headless_dispatcher()->Init(channel_);
  host_dispatcher()->Init(channel_);
  indexed_db_dispatcher()->Init(channel_);
  input_dispatcher()->Init(channel_);
  io_dispatcher()->Init(channel_);
  layer_tree_dispatcher()->Init(channel_);
  network_dispatcher()->Init(channel_);
  overlay_dispatcher()->Init(channel_);
  //page_dispatcher()->Init(channel_);
  //service_worker_dispatcher()->Init(channel_);
  storage_dispatcher()->Init(channel_);
  system_info_dispatcher()->Init(channel_);
  //target_dispatcher()->Init(channel_);
  tethering_dispatcher()->Init(channel_);
} 
  
  // service_manager::EmbeddedServiceInfo info;
  
  // info.use_own_thread = false;
  // info.task_runner = task_runner;
  // info.message_loop_type = base::MessageLoop::TYPE_IO;
  // info.thread_priority = base::ThreadPriority::BACKGROUND;

  // // Accessibility
  // info.factory = base::Bind(
  //     &AutomationContext::CreateAccessibilityService, 
  //     base::Unretained(this),
  //     base::Unretained(page_instance_.get()));
  // service_manager_connection_->AddEmbeddedService("automation.Accessibility", info);

  // // ApplicationCache
  // info.factory = base::Bind(
  //     &AutomationContext::CreateApplicationCacheService, 
  //     base::Unretained(this),
  //     base::Unretained(page_instance_.get()));
  // service_manager_connection_->AddEmbeddedService("automation.ApplicationCacheInterface", info);

  // // CacheStorage
  // info.factory = base::Bind(
  //     &AutomationContext::CreateCacheStorageService, 
  //     base::Unretained(this),
  //     base::Unretained(page_instance_.get()));
  // service_manager_connection_->AddEmbeddedService("automation.CacheStorage", info);

  // // Database
  // info.factory = base::Bind(
  //     &AutomationContext::CreateDatabaseService, 
  //     base::Unretained(this),
  //     base::Unretained(page_instance_.get()));
  // service_manager_connection_->AddEmbeddedService("automation.DatabaseInterface", info);

  // // DOMService
  // info.factory = base::Bind(
  //     &AutomationContext::CreateDOMService, 
  //     base::Unretained(this),
  //     base::Unretained(page_instance_.get()));
  // service_manager_connection_->AddEmbeddedService("automation.DOM", info);

  // // DeviceOrientationService
  // info.factory = base::Bind(
  //     &AutomationContext::CreateDeviceOrientationService, 
  //     base::Unretained(this),
  //     base::Unretained(page_instance_.get()));
  // service_manager_connection_->AddEmbeddedService("automation.DeviceOrientation", info);

  // // CSSService
  // info.factory = base::Bind(
  //     &AutomationContext::CreateCSSService, 
  //     base::Unretained(this),
  //     base::Unretained(page_instance_.get()));
  // service_manager_connection_->AddEmbeddedService("automation.CSS", info);

  // // DOMSnapshotService
  // info.factory = base::Bind(
  //     &AutomationContext::CreateDOMSnapshotService, 
  //     base::Unretained(this),
  //     base::Unretained(page_instance_.get()));
  // service_manager_connection_->AddEmbeddedService("automation.DOMSnapshot", info);

  // // DOMStorageService
  // info.factory = base::Bind(
  //     &AutomationContext::CreateDOMStorageService, 
  //     base::Unretained(this),
  //     base::Unretained(page_instance_.get()));
  // service_manager_connection_->AddEmbeddedService("automation.DOMStorage", info);

  // // EmulationService
  // info.factory = base::Bind(
  //     &AutomationContext::CreateEmulationService, 
  //     base::Unretained(this),
  //     base::Unretained(page_instance_.get()));
  // service_manager_connection_->AddEmbeddedService("automation.EmulationService", info);

  // // HeadlessService
  // info.factory = base::Bind(
  //     &AutomationContext::CreateHeadlessService, 
  //     base::Unretained(this),
  //     base::Unretained(page_instance_.get()));
  // service_manager_connection_->AddEmbeddedService("automation.Headless", info);

  // // HostService
  // info.factory = base::Bind(
  //     &AutomationContext::CreateHostService, 
  //     base::Unretained(this),
  //     base::Unretained(page_instance_.get()));
  // service_manager_connection_->AddEmbeddedService("automation.Host", info);

  // // IndexedDBService
  // info.factory = base::Bind(
  //     &AutomationContext::CreateIndexedDBService, 
  //     base::Unretained(this),
  //     base::Unretained(page_instance_.get()));
  // service_manager_connection_->AddEmbeddedService("automation.IndexedDB", info);

  // //InputService
  // info.factory = base::Bind(
  //     &AutomationContext::CreateInputService, 
  //     base::Unretained(this),
  //     base::Unretained(page_instance_.get()),
  //     base::Unretained(frame_impl));
  // service_manager_connection_->AddEmbeddedService("automation.InputService", info);

  // //IOService
  // info.factory = base::Bind(
  //     &AutomationContext::CreateIOService, 
  //     base::Unretained(this),
  //     base::Unretained(page_instance_.get()));
  // service_manager_connection_->AddEmbeddedService("automation.IO", info);

  // //LayerTreeService
  // info.factory = base::Bind(
  //     &AutomationContext::CreateLayerTreeService, 
  //     base::Unretained(this),
  //     base::Unretained(page_instance_.get()));
  // service_manager_connection_->AddEmbeddedService("automation.LayerTree", info);

  // //NetworkService
  // info.factory = base::Bind(
  //     &AutomationContext::CreateNetworkService, 
  //     base::Unretained(this),
  //     base::Unretained(page_instance_.get()));
  // service_manager_connection_->AddEmbeddedService("automation.Network", info);

  // //AnimationService
  // info.factory = base::Bind(
  //     &AutomationContext::CreateAnimationService, 
  //     base::Unretained(this),
  //     base::Unretained(page_instance_.get()));
  // service_manager_connection_->AddEmbeddedService("automation.Animation", info);  

  // //OverlayService
  // info.factory = base::Bind(
  //     &AutomationContext::CreateOverlayService, 
  //     base::Unretained(this),
  //     base::Unretained(page_instance_.get()),
  //     base::Unretained(frame_impl));
  // service_manager_connection_->AddEmbeddedService("automation.Overlay", info);

  // //PageService
  // info.factory = base::Bind(
  //     &AutomationContext::CreatePageService, 
  //     base::Unretained(this),
  //     base::Unretained(page_instance_.get()));
  // service_manager_connection_->AddEmbeddedService("automation.Page", info);

  // //StorageService
  // info.factory = base::Bind(
  //     &AutomationContext::CreateStorageService, 
  //     base::Unretained(this),
  //     base::Unretained(page_instance_.get()));
  // service_manager_connection_->AddEmbeddedService("automation.Storage", info);

  // //SystemInfoService
  // info.factory = base::Bind(
  //     &AutomationContext::CreateSystemInfoService, 
  //     base::Unretained(this),
  //     base::Unretained(page_instance_.get()));
  // service_manager_connection_->AddEmbeddedService("automation.SystemInfo", info);

  // //TetheringService
  // info.factory = base::Bind(
  //     &AutomationContext::CreateTetheringService, 
  //     base::Unretained(this),
  //     base::Unretained(page_instance_.get()));
  // service_manager_connection_->AddEmbeddedService("automation.Tethering", info);
//}

// std::unique_ptr<service_manager::Service> AutomationContext::CreateAccessibilityService(PageInstance* page_instance) {
//   auto result = std::make_unique<AccessibilityService>(page_instance);
//   accessibility_service_ = result.get();
//   return result;
// }

// std::unique_ptr<service_manager::Service> AutomationContext::CreateApplicationCacheService(PageInstance* page_instance) {
//   auto result = std::make_unique<ApplicationCacheService>(page_instance);
//   application_cache_service_ = result.get();
//   return result;
// }

// std::unique_ptr<service_manager::Service> AutomationContext::CreateCacheStorageService(PageInstance* page_instance) {
//   auto result = std::make_unique<CacheStorageService>(page_instance);
//   cache_storage_service_ = result.get();
//   return result;
// }

// std::unique_ptr<service_manager::Service> AutomationContext::CreateDatabaseService(PageInstance* page_instance) {
//   auto result = std::make_unique<DatabaseService>(this, page_instance);
//   database_service_ = result.get();
//   return result;
// }

// std::unique_ptr<service_manager::Service> AutomationContext::CreateDeviceOrientationService(PageInstance* page_instance) {
//   auto result = std::make_unique<DeviceOrientationService>(page_instance);
//   device_orientation_service_ = result.get();
//   return result;
// }

// std::unique_ptr<service_manager::Service> AutomationContext::CreateDOMService(PageInstance* page_instance) {
//   auto result = std::make_unique<DOMService>(page_instance);
//   dom_service_ = result.get();
//   return result;
// }

// std::unique_ptr<service_manager::Service> AutomationContext::CreateCSSService(PageInstance* page_instance) {
//   auto result = std::make_unique<CSSService>(this, page_instance);
//   css_service_ = result.get();
//   return result;
// }

// std::unique_ptr<service_manager::Service> AutomationContext::CreateDOMSnapshotService(PageInstance* page_instance) {
//   auto result = std::make_unique<DOMSnapshotService>(page_instance);
//   dom_snapshot_service_ = result.get();
//   return result;
// }

// std::unique_ptr<service_manager::Service> AutomationContext::CreateDOMStorageService(PageInstance* page_instance) {
//   auto result = std::make_unique<DOMStorageService>(page_instance);
//   dom_storage_service_ = result.get();
//   return result;
// }

// std::unique_ptr<service_manager::Service> AutomationContext::CreateEmulationService(PageInstance* page_instance) {
//   auto result = std::make_unique<EmulationService>(page_instance);
//   emulation_service_ = result.get();
//   return result;
// }

// std::unique_ptr<service_manager::Service> AutomationContext::CreateHeadlessService(PageInstance* page_instance) {
//   auto result = std::make_unique<HeadlessService>(page_instance);
//   headless_service_ = result.get();
//   return result;
// }

// std::unique_ptr<service_manager::Service> AutomationContext::CreateHostService(PageInstance* page_instance) {
//   auto result = std::make_unique<HostService>(page_instance);
//   host_service_ = result.get();
//   return result;
// }

// std::unique_ptr<service_manager::Service> AutomationContext::CreateIndexedDBService(PageInstance* page_instance) {
//   auto result = std::make_unique<IndexedDBService>(page_instance);
//   indexed_db_service_ = result.get();
//   return result;
// }

// std::unique_ptr<service_manager::Service> AutomationContext::CreateInputService(PageInstance* page_instance, blink::WebLocalFrameImpl* frame_impl) {
//   auto result = std::make_unique<InputService>(page_instance, frame_impl);
//   input_service_ = result.get();
//   return result;
// }

// std::unique_ptr<service_manager::Service> AutomationContext::CreateIOService(PageInstance* page_instance) {
//   auto result = std::make_unique<IOService>(page_instance);
//   io_service_ = result.get();
//   return result;
// }

// std::unique_ptr<service_manager::Service> AutomationContext::CreateLayerTreeService(PageInstance* page_instance) {
//   auto result = std::make_unique<LayerTreeService>(page_instance);
//   layer_tree_service_ = result.get();
//   return result;
// }

// std::unique_ptr<service_manager::Service> AutomationContext::CreateNetworkService(PageInstance* page_instance) {
//   auto result = std::make_unique<NetworkService>(page_instance);
//   network_service_ = result.get();
//   return result;
// }

// std::unique_ptr<service_manager::Service> AutomationContext::CreateAnimationService(PageInstance* page_instance) {
//   auto result = std::make_unique<AnimationService>(this, page_instance);
//   animation_service_ = result.get();
//   return result;
// }

// std::unique_ptr<service_manager::Service> AutomationContext::CreateOverlayService(PageInstance* page_instance, blink::WebLocalFrameImpl* frame_impl) {
//   auto result = std::make_unique<OverlayService>(page_instance, frame_impl, dom_service_);
//   overlay_service_ = result.get();
//   return result;
// }

// std::unique_ptr<service_manager::Service> AutomationContext::CreatePageService(PageInstance* page_instance) {
//   auto result = std::make_unique<PageService>(application_window_dispatcher_, page_instance);
//   page_service_ = result.get();
//   return result;
// }

// std::unique_ptr<service_manager::Service> AutomationContext::CreateStorageService(PageInstance* page_instance) {
//   auto result = std::make_unique<StorageService>(page_instance);
//   storage_service_ = result.get();
//   return result;
// }

// std::unique_ptr<service_manager::Service> AutomationContext::CreateSystemInfoService(PageInstance* page_instance) {
//   auto result = std::make_unique<SystemInfoService>(page_instance);
//   system_info_service_ = result.get();
//   return result;
// }

// std::unique_ptr<service_manager::Service> AutomationContext::CreateTetheringService(PageInstance* page_instance) {
//   auto result = std::make_unique<TetheringService>(page_instance);
//   tethering_service_ = result.get();
//   return result;
// }

void AutomationContext::SendProtocolResponse(int session_id,
                                             int call_id,
                                             const String& response,
                                             const String& state) {
  //DLOG(INFO) << "AutomationContext::SendProtocolResponse";
}
  
void AutomationContext::SendProtocolNotification(int session_id,
                                                 const String& message) {
  //DLOG(INFO) << "AutomationContext::SendProtocolNotification";
}

void AutomationContext::OnWebFrameCreated(blink::WebLocalFrame* frame) {
  //DLOG(INFO) << "\nAutomationContext::OnWebFrameCreated\n";
  page_instance()->OnWebFrameCreated(frame);
  
  overlay_dispatcher()->OnWebFrameCreated(frame);
  input_dispatcher()->OnWebFrameCreated(frame);
  accessibility_dispatcher()->OnWebFrameCreated(frame);
  animation_dispatcher()->OnWebFrameCreated(frame);
  application_cache_dispatcher()->OnWebFrameCreated(frame);
  cache_storage_dispatcher()->OnWebFrameCreated(frame);
  css_dispatcher()->OnWebFrameCreated(frame);
  database_dispatcher()->OnWebFrameCreated(frame);
  device_orientation_dispatcher()->OnWebFrameCreated(frame);
  dom_dispatcher()->OnWebFrameCreated(frame);
  dom_snapshot_dispatcher()->OnWebFrameCreated(frame);
  dom_storage_dispatcher()->OnWebFrameCreated(frame);
  emulation_dispatcher()->OnWebFrameCreated(frame);
  headless_dispatcher()->OnWebFrameCreated(frame);
  host_dispatcher()->OnWebFrameCreated(frame);
  indexed_db_dispatcher()->OnWebFrameCreated(frame);
  io_dispatcher()->OnWebFrameCreated(frame);
  layer_tree_dispatcher()->OnWebFrameCreated(frame);
  network_dispatcher()->OnWebFrameCreated(frame);
  page_dispatcher()->OnWebFrameCreated(frame);
  //service_worker_dispatcher()->OnWebFrameCreated(frame);
  storage_dispatcher()->OnWebFrameCreated(frame);
  system_info_dispatcher()->OnWebFrameCreated(frame);
  //target_dispatcher()->OnWebFrameCreated(frame);
  tethering_dispatcher()->OnWebFrameCreated(frame);

  //blink::WebLocalFrameImpl* root_frame = static_cast<blink::WebLocalFrameImpl*>(page_instance_->inspected_frames()->Root());

  // Call session init callbacks registered from higher layers
  // blink::CoreInitializer::GetInstance().InitInspectorAgentSession(
  //     session_.Get(), 
  //     true,//agent_->include_view_agents_, 
  //     dom_dispatcher()->dom_agent(),
  //     page_instance_->inspected_frames(), 
  //     nullptr);
  //     //root_frame->ViewImpl()->GetPage());
}


}
