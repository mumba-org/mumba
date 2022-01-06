// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/target_dispatcher.h"

#include "services/service_manager/public/cpp/interface_provider.h"
#include "ipc/ipc_sync_channel.h"

namespace application {

// static 
void TargetDispatcher::Create(automation::TargetRequest request, PageInstance* page_instance) {
  new TargetDispatcher(std::move(request), page_instance);
}

TargetDispatcher::TargetDispatcher(automation::TargetRequest request, PageInstance* page_instance): 
  application_id_(-1),
  page_instance_(page_instance),
  binding_(this) {
  
}

TargetDispatcher::TargetDispatcher(PageInstance* page_instance): 
  application_id_(-1),
  page_instance_(page_instance),
  binding_(this) {
  
}

TargetDispatcher::~TargetDispatcher() {

}

void TargetDispatcher::Init(IPC::SyncChannel* channel) {
  channel->GetRemoteAssociatedInterface(&target_client_ptr_);
}

void TargetDispatcher::Bind(automation::TargetAssociatedRequest request) {
  //DLOG(INFO) << "TargetDispatcher::Bind (application)";
  binding_.Bind(std::move(request));
}

void TargetDispatcher::Register(int32_t application_id) {
  application_id_ = application_id;
}

void TargetDispatcher::ActivateTarget(const std::string& target_id) {

}

void TargetDispatcher::AttachToTarget(const std::string& targetId, AttachToTargetCallback callback) {

}

void TargetDispatcher::CloseTarget(const std::string& target_id, CloseTargetCallback callback) {

}

void TargetDispatcher::CreateBrowserContext(CreateBrowserContextCallback callback) {

}

void TargetDispatcher::CreateTarget(const std::string& url, int32_t width, int32_t height, const base::Optional<std::string>& browser_context_id, bool enable_begin_frame_control, CreateTargetCallback callback) {

}

void TargetDispatcher::DetachFromTarget(const base::Optional<std::string>& session_id, const base::Optional<std::string>& target_id) {

}

void TargetDispatcher::DisposeBrowserContext(const std::string& browser_context_id, DisposeBrowserContextCallback callback) {

}

void TargetDispatcher::GetTargetInfo(const std::string& targetId, GetTargetInfoCallback callback) {

}

void TargetDispatcher::GetTargets(GetTargetsCallback callback) {

}

void TargetDispatcher::SendMessageToTarget(const std::string& message, const base::Optional<std::string>& session_id, const base::Optional<std::string>& target_id) {

}

void TargetDispatcher::SetAutoAttach(bool auto_attach, bool wait_for_debugger_on_start) {

}

void TargetDispatcher::SetDiscoverTargets(bool discover) {

}

void TargetDispatcher::SetRemoteLocations(std::vector<automation::RemoteLocationPtr> locations) {

}

void TargetDispatcher::OnWebFrameCreated(blink::WebLocalFrame* web_frame) {

}

}