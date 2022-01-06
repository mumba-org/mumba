// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/system_info_dispatcher.h"

#include "services/service_manager/public/cpp/interface_provider.h"
#include "ipc/ipc_sync_channel.h"

namespace application {

// static 
void SystemInfoDispatcher::Create(automation::SystemInfoRequest request, PageInstance* page_instance) {
    new SystemInfoDispatcher(std::move(request), page_instance);
}

SystemInfoDispatcher::SystemInfoDispatcher(automation::SystemInfoRequest request, PageInstance* page_instance): 
  application_id_(-1),
  page_instance_(page_instance),
  binding_(this) {

}

SystemInfoDispatcher::SystemInfoDispatcher(PageInstance* page_instance): 
  application_id_(-1),
  page_instance_(page_instance),
  binding_(this) {

}

SystemInfoDispatcher::~SystemInfoDispatcher() {

}

void SystemInfoDispatcher::Init(IPC::SyncChannel* channel) {
  
}

void SystemInfoDispatcher::Bind(automation::SystemInfoAssociatedRequest request) {
  //DLOG(INFO) << "SystemInfoDispatcher::Bind (application)";
  binding_.Bind(std::move(request));
}

void SystemInfoDispatcher::Register(int32_t application_id) {
  application_id_ = application_id;
}

void SystemInfoDispatcher::GetInfo(GetInfoCallback callback) {}


void SystemInfoDispatcher::OnWebFrameCreated(blink::WebLocalFrame* web_frame) {

}

}