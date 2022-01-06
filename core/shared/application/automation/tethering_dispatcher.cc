// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/tethering_dispatcher.h"

#include "services/service_manager/public/cpp/interface_provider.h"
#include "ipc/ipc_sync_channel.h"

namespace application {

// static 
void TetheringDispatcher::Create(automation::TetheringRequest request, PageInstance* page_instance) {
  new TetheringDispatcher(std::move(request), page_instance);
}

TetheringDispatcher::TetheringDispatcher(automation::TetheringRequest request, PageInstance* page_instance): 
  application_id_(-1),
  page_instance_(page_instance),
  binding_(this) {
  
}

TetheringDispatcher::TetheringDispatcher(PageInstance* page_instance): 
  application_id_(-1),
  page_instance_(page_instance),
  binding_(this) {
  
}

TetheringDispatcher::~TetheringDispatcher() {

}

void TetheringDispatcher::Init(IPC::SyncChannel* channel) {
  channel->GetRemoteAssociatedInterface(&tethering_client_ptr_);
}

void TetheringDispatcher::BindMojo(automation::TetheringAssociatedRequest request) {
  //DLOG(INFO) << "TetheringDispatcher::Bind (application)";
  binding_.Bind(std::move(request));
}

void TetheringDispatcher::Register(int32_t application_id) {
  application_id_ = application_id;
}

void TetheringDispatcher::Bind(int32_t port) {

}

void TetheringDispatcher::Unbind(int32_t port) {

}

void TetheringDispatcher::OnWebFrameCreated(blink::WebLocalFrame* web_frame) {

}

}