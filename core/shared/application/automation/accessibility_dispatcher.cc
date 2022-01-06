// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/accessibility_dispatcher.h"

#include "services/service_manager/public/cpp/interface_provider.h"
#include "ipc/ipc_sync_channel.h"

namespace application {

// static
void AccessibilityDispatcher::Create(automation::AccessibilityRequest request,
                                     PageInstance* page_instance) {
  new AccessibilityDispatcher(std::move(request), page_instance);
}

AccessibilityDispatcher::AccessibilityDispatcher(
    automation::AccessibilityRequest request,
    PageInstance* page_instance): 
  page_instance_(page_instance),
  application_id_(-1),
  binding_(this) {

}

AccessibilityDispatcher::AccessibilityDispatcher(
    PageInstance* page_instance): 
  page_instance_(page_instance),
  application_id_(-1),
  binding_(this) {

}

AccessibilityDispatcher::~AccessibilityDispatcher() {

}

void AccessibilityDispatcher::Init(IPC::SyncChannel* channel) {
  
}

void AccessibilityDispatcher::Bind(automation::AccessibilityAssociatedRequest request) {
  //DLOG(INFO) << "AccessibilityDispatcher::Bind (application)";
  binding_.Bind(std::move(request));
}

void AccessibilityDispatcher::Register(int32_t application_id) {
  application_id_ = application_id;
}

void AccessibilityDispatcher::GetPartialAXTree(const base::Optional<std::string>& node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id, bool fetch_relatives, GetPartialAXTreeCallback callback) {

}

void AccessibilityDispatcher::OnWebFrameCreated(blink::WebLocalFrame* web_frame) {

}

}