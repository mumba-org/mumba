// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/io_dispatcher.h"

#include "services/service_manager/public/cpp/interface_provider.h"
#include "ipc/ipc_sync_channel.h"

namespace application {

// static 
void IODispatcher::Create(automation::IORequest request, PageInstance* page_instance) {
    new IODispatcher(std::move(request), page_instance);
}

IODispatcher::IODispatcher(automation::IORequest request, PageInstance* page_instance):  
  application_id_(-1),
  page_instance_(page_instance),
  binding_(this) {

}

IODispatcher::IODispatcher(PageInstance* page_instance):  
  application_id_(-1),
  page_instance_(page_instance),
  binding_(this) {

}

IODispatcher::~IODispatcher() {

}

void IODispatcher::Init(IPC::SyncChannel* channel) {
  
}

void IODispatcher::Bind(automation::IOAssociatedRequest request) {
  //DLOG(INFO) << "IODispatcher::Bind (application)";
  binding_.Bind(std::move(request));
}

void IODispatcher::Register(int32_t application_id) {
  application_id_ = application_id;
}

void IODispatcher::Close(const std::string& handl) {}
void IODispatcher::Read(const std::string& handl, int32_t offset, int32_t size, ReadCallback callback) {}
void IODispatcher::ResolveBlob(const std::string& object_id, ResolveBlobCallback callback) {}

void IODispatcher::OnWebFrameCreated(blink::WebLocalFrame* web_frame) {

}

}