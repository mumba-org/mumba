// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_APPLICATION_APPLICATION_CACHE_DISPATCHER_H_
#define MUMBA_APPLICATION_APPLICATION_CACHE_DISPATCHER_H_

#include "core/shared/common/mojom/automation.mojom.h"

#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "third_party/blink/renderer/platform/heap/heap.h"
#include "third_party/blink/renderer/platform/heap/heap_traits.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/core/loader/appcache/application_cache_host.h"

namespace blink {
class LocalFrame;
class WebLocalFrame;
}

namespace service_manager {
class InterfaceProvider;
}

namespace IPC {
class SyncChannel;
}

namespace application {
class InspectorApplicationCacheAgentImpl;
class PageInstance;
class ApplicationWindowDispatcher;

class ApplicationCacheDispatcher : public automation::ApplicationCacheInterface {
public:
  static void Create(automation::ApplicationCacheInterfaceRequest request, PageInstance* page_instance);

  ApplicationCacheDispatcher(automation::ApplicationCacheInterfaceRequest request, PageInstance* page_instance);
  ApplicationCacheDispatcher(PageInstance* page_instance);
  ~ApplicationCacheDispatcher() override;

  void Init(IPC::SyncChannel* channel);
  void Bind(automation::ApplicationCacheInterfaceAssociatedRequest request);

  void Register(int32_t application_id) override;
  void Enable() override;
  void GetApplicationCacheForFrame(const std::string& frameId, GetApplicationCacheForFrameCallback callback) override;
  void GetFramesWithManifests(GetFramesWithManifestsCallback callback) override;
  void GetManifestForFrame(const std::string& frame_id, GetManifestForFrameCallback callback) override;  

  automation::ApplicationCacheClient* GetClient() const;

  PageInstance* page_instance() const {
    return page_instance_;
  }

  void OnWebFrameCreated(blink::WebLocalFrame* web_frame);
  
private:
  friend class InspectorApplicationCacheAgentImpl;

  void UpdateApplicationCacheStatus(blink::LocalFrame*);
  void NetworkStateChanged(blink::LocalFrame*, bool online);

  bool AssertFrameWithDocumentLoader(String frame_id, blink::DocumentLoader*& result);
  automation::ApplicationCachePtr BuildObjectForApplicationCache(
    const blink::ApplicationCacheHost::ResourceInfoList& application_cache_resources,
    const blink::ApplicationCacheHost::CacheInfo& application_cache_info);
  automation::ApplicationCacheResourcePtr 
    BuildObjectForApplicationCacheResource(const blink::ApplicationCacheHost::ResourceInfo& resource_info);
  
  std::vector<automation::ApplicationCacheResourcePtr> BuildArrayForApplicationCacheResources(
    const blink::ApplicationCacheHost::ResourceInfoList& application_cache_resources);
  
  PageInstance* page_instance_;
  int32_t application_id_;
  mojo::AssociatedBinding<automation::ApplicationCacheInterface> binding_;
  automation::ApplicationCacheClientAssociatedPtr application_cache_client_ptr_;
  blink::Member<InspectorApplicationCacheAgentImpl> application_cache_agent_impl_;
  bool enabled_;

  DISALLOW_COPY_AND_ASSIGN(ApplicationCacheDispatcher); 
};

}

#endif