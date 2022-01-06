// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/host_dispatcher.h"

#include "services/service_manager/public/cpp/interface_provider.h"
#include "ipc/ipc_sync_channel.h"

namespace application {

// static 
void HostDispatcher::Create(automation::HostRequest request, PageInstance* page_instance) {
  new HostDispatcher(std::move(request), page_instance);
}

HostDispatcher::HostDispatcher(automation::HostRequest request, PageInstance* page_instance): 
  application_id_(-1),
  page_instance_(page_instance),
  binding_(this) {

}

HostDispatcher::HostDispatcher(PageInstance* page_instance): 
  application_id_(-1),
  page_instance_(page_instance),
  binding_(this) {

}

HostDispatcher::~HostDispatcher() {

}

void HostDispatcher::Init(IPC::SyncChannel* channel) {
  
}

void HostDispatcher::Bind(automation::HostAssociatedRequest request) {
  //DLOG(INFO) << "HostDispatcher::Bind (application)";
  binding_.Bind(std::move(request));  
}

void HostDispatcher::Close() {

}

void HostDispatcher::Register(int32_t application_id) {
  application_id_ = application_id;
}

void HostDispatcher::GetVersion(GetVersionCallback callback) {

}

void HostDispatcher::GetHostCommandLine(GetHostCommandLineCallback callback) {

}

void HostDispatcher::GetHistograms(const base::Optional<std::string>& query, GetHistogramsCallback callback) {

}

void HostDispatcher::GetHistogram(const std::string& name, GetHistogramCallback callback) {

}

void HostDispatcher::GetWindowBounds(int32_t window_id, GetWindowBoundsCallback callback) {

}

void HostDispatcher::GetWindowForTarget(const std::string& target_id, GetWindowForTargetCallback callback) {

}

void HostDispatcher::SetWindowBounds(int32_t window_id, automation::BoundsPtr bounds) {

}

void HostDispatcher::OnWebFrameCreated(blink::WebLocalFrame* web_frame) {

}

}