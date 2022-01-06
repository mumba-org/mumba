// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/application_cache_dispatcher.h"

#include "core/shared/application/automation/page_instance.h"
#include "core/shared/application/application_window_dispatcher.h"
#include "services/service_manager/public/cpp/interface_provider.h"
#include "third_party/blink/renderer/core/inspector/inspected_frames.h"
#include "third_party/blink/renderer/core/inspector/inspector_application_cache_agent.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/identifiers_factory.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/frame_loader.h"
#include "third_party/blink/renderer/platform/network/network_state_notifier.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "ipc/ipc_sync_channel.h"

namespace application {

class InspectorApplicationCacheAgentImpl : public blink::InspectorApplicationCacheAgent {
public:
  InspectorApplicationCacheAgentImpl(ApplicationCacheDispatcher* dispatcher,
                                     blink::InspectedFrames* inspected_frames): 
                                     InspectorApplicationCacheAgent(inspected_frames),
                                     dispatcher_(dispatcher) {
    
  }

  void UpdateApplicationCacheStatus(blink::LocalFrame* frame) override {
    dispatcher_->UpdateApplicationCacheStatus(frame);
  }
  
  void NetworkStateChanged(blink::LocalFrame* frame, bool online) override {
    dispatcher_->NetworkStateChanged(frame, online);
  }

private:
  ApplicationCacheDispatcher* dispatcher_;
  
  DISALLOW_COPY_AND_ASSIGN(InspectorApplicationCacheAgentImpl);
};

// static 
void ApplicationCacheDispatcher::Create(automation::ApplicationCacheInterfaceRequest request, PageInstance* page_instance) {
  new ApplicationCacheDispatcher(std::move(request), page_instance);
}

ApplicationCacheDispatcher::ApplicationCacheDispatcher(automation::ApplicationCacheInterfaceRequest request, PageInstance* page_instance): 
  page_instance_(page_instance),
  application_id_(-1),
  binding_(this),
  enabled_(false) {

}

ApplicationCacheDispatcher::ApplicationCacheDispatcher(PageInstance* page_instance): 
  page_instance_(page_instance),
  application_id_(-1),
  binding_(this),
  enabled_(false) {

}

ApplicationCacheDispatcher::~ApplicationCacheDispatcher() {

}

void ApplicationCacheDispatcher::Init(IPC::SyncChannel* channel) {
  //DLOG(INFO) << "ApplicationCacheDispatcher::Init:  channel->GetRemoteAssociatedInterface(&application_cache_client_ptr_)";
  channel->GetRemoteAssociatedInterface(&application_cache_client_ptr_);
}

void ApplicationCacheDispatcher::Bind(automation::ApplicationCacheInterfaceAssociatedRequest request) {
  //DLOG(INFO) << "ApplicationCacheDispatcher::Bind (application)";
  binding_.Bind(std::move(request));
}

automation::ApplicationCacheClient* ApplicationCacheDispatcher::GetClient() const {
  return application_cache_client_ptr_.get();
}

void ApplicationCacheDispatcher::Register(int32_t application_id) {
  application_id_ = application_id;
}

void ApplicationCacheDispatcher::Enable() {
  //DLOG(INFO) << "ApplicationCacheDispatcher::Enable (application process)";
  if (enabled_) {
    return;
  }
  page_instance_->probe_sink()->addInspectorApplicationCacheAgent(application_cache_agent_impl_.Get());
  enabled_ = true;
}

void ApplicationCacheDispatcher::GetApplicationCacheForFrame(const std::string& frame_id, GetApplicationCacheForFrameCallback callback) {
  blink::DocumentLoader* document_loader = nullptr;
  bool ok = AssertFrameWithDocumentLoader(String::FromUTF8(frame_id.data()), document_loader);
  if (!ok) {
    return;
  }
  blink::ApplicationCacheHost* host = document_loader->GetApplicationCacheHost();
  blink::ApplicationCacheHost::CacheInfo info = host->ApplicationCacheInfo();

  blink::ApplicationCacheHost::ResourceInfoList resources;
  host->FillResourceList(&resources);

  std::move(callback).Run(BuildObjectForApplicationCache(resources, info));
}

void ApplicationCacheDispatcher::GetFramesWithManifests(GetFramesWithManifestsCallback callback) {
  std::vector<automation::FrameWithManifestPtr> result;

  for (blink::LocalFrame* frame : *page_instance_->inspected_frames()) {
    blink::DocumentLoader* document_loader = frame->Loader().GetDocumentLoader();
    if (!document_loader)
      continue;

    blink::ApplicationCacheHost* host = document_loader->GetApplicationCacheHost();
    blink::ApplicationCacheHost::CacheInfo info = host->ApplicationCacheInfo();
    String manifest_url = info.manifest_.GetString();
    if (!manifest_url.IsEmpty()) {
      automation::FrameWithManifestPtr value = automation::FrameWithManifest::New();
      String frame_id_str = blink::IdentifiersFactory::FrameId(frame);
      value->frame_id = std::string(frame_id_str.Utf8().data(), frame_id_str.Utf8().length());
      value->manifest_url = std::string(manifest_url.Utf8().data(), manifest_url.Utf8().length());
      value->status = static_cast<int>(host->GetStatus());
      result.push_back(std::move(value));
    }
  }
  std::move(callback).Run(std::move(result));
}

void ApplicationCacheDispatcher::GetManifestForFrame(const std::string& frame_id, GetManifestForFrameCallback callback) {
  blink::DocumentLoader* document_loader = nullptr;
  bool ok = AssertFrameWithDocumentLoader(String::FromUTF8(frame_id.data()), document_loader);
  if (!ok)
    return;

  blink::ApplicationCacheHost::CacheInfo info =
      document_loader->GetApplicationCacheHost()->ApplicationCacheInfo();
  String manifest_url_str = info.manifest_.GetString();
  std::move(callback).Run(std::string(manifest_url_str.Utf8().data(), manifest_url_str.Utf8().length()));
}

void ApplicationCacheDispatcher::UpdateApplicationCacheStatus(blink::LocalFrame* frame) {
  blink::DocumentLoader* document_loader = frame->Loader().GetDocumentLoader();
  if (!document_loader)
    return;

  blink::ApplicationCacheHost* host = document_loader->GetApplicationCacheHost();
  blink::ApplicationCacheHost::Status status = host->GetStatus();
  blink::ApplicationCacheHost::CacheInfo info = host->ApplicationCacheInfo();

  String manifest_url = info.manifest_.GetString();
  String frame_id_str = blink::IdentifiersFactory::FrameId(frame);
  GetClient()->OnApplicationCacheStatusUpdated(std::string(frame_id_str.Utf8().data(), frame_id_str.Utf8().length()), 
                                               std::string(manifest_url.Utf8().data(), manifest_url.Utf8().length()),
                                               static_cast<int>(status));
}

void ApplicationCacheDispatcher::NetworkStateChanged(blink::LocalFrame* frame, bool online) {
  if (frame == page_instance_->inspected_frames()->Root())
    GetClient()->OnNetworkStateUpdated(online);
}

bool ApplicationCacheDispatcher::AssertFrameWithDocumentLoader(String frame_id, blink::DocumentLoader*& result) {
  blink::LocalFrame* frame = blink::IdentifiersFactory::FrameById(page_instance_->inspected_frames(), frame_id);
  if (!frame) {
    //DLOG(INFO) << "No frame for given id found";
    return false;
  }

  result = frame->Loader().GetDocumentLoader();
  if (!result) {
    //DLOG(INFO) << "No documentLoader for given frame found";
    return false;
  }
  return true;
}

automation::ApplicationCachePtr ApplicationCacheDispatcher::BuildObjectForApplicationCache(
  const blink::ApplicationCacheHost::ResourceInfoList& application_cache_resources,
  const blink::ApplicationCacheHost::CacheInfo& application_cache_info) {
  String manifest_url = application_cache_info.manifest_.GetString();
  automation::ApplicationCachePtr result = automation::ApplicationCache::New();
  result->manifest_url = std::string(manifest_url.Utf8().data(), manifest_url.Utf8().length());
  result->size = application_cache_info.size_;
  result->creation_time = application_cache_info.creation_time_;
  result->update_time = application_cache_info.update_time_;
  result->resources = BuildArrayForApplicationCacheResources(application_cache_resources);
  return result;
}

std::vector<automation::ApplicationCacheResourcePtr> ApplicationCacheDispatcher::BuildArrayForApplicationCacheResources(
  const blink::ApplicationCacheHost::ResourceInfoList& application_cache_resources) {
  std::vector<automation::ApplicationCacheResourcePtr> resources;
  blink::ApplicationCacheHost::ResourceInfoList::const_iterator end = application_cache_resources.end();
  blink::ApplicationCacheHost::ResourceInfoList::const_iterator it = application_cache_resources.begin();
  for (int i = 0; it != end; ++it, i++)
    resources.push_back(BuildObjectForApplicationCacheResource(*it));

  return resources;
}

automation::ApplicationCacheResourcePtr 
  ApplicationCacheDispatcher::BuildObjectForApplicationCacheResource(const blink::ApplicationCacheHost::ResourceInfo& resource_info) {
  StringBuilder builder;
  if (resource_info.is_master_)
    builder.Append("Master ");

  if (resource_info.is_manifest_)
    builder.Append("Manifest ");

  if (resource_info.is_fallback_)
    builder.Append("Fallback ");

  if (resource_info.is_foreign_)
    builder.Append("Foreign ");

  if (resource_info.is_explicit_)
    builder.Append("Explicit ");

  String resource_str = builder.ToString();
  String resource_name = resource_info.resource_.GetString(); 

  automation::ApplicationCacheResourcePtr value = automation::ApplicationCacheResource::New();
  value->url = std::string(resource_name.Utf8().data(), resource_name.Utf8().length());
  value->size = static_cast<int>(resource_info.size_);
  value->type = std::string(resource_str.Utf8().data(), resource_str.Utf8().length());
  return value;
}

void ApplicationCacheDispatcher::OnWebFrameCreated(blink::WebLocalFrame* web_frame) {
   application_cache_agent_impl_ = new InspectorApplicationCacheAgentImpl(
    this, 
    page_instance_->inspected_frames());
   application_cache_agent_impl_->Init(
    page_instance_->probe_sink(), 
    page_instance_->inspector_backend_dispatcher(),
    page_instance_->state());
   Enable();
}

}