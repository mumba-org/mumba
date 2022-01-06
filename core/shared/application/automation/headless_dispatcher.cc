// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/headless_dispatcher.h"

#include "services/service_manager/public/cpp/interface_provider.h"
#include "ipc/ipc_sync_channel.h"

namespace application {

// static 
void HeadlessDispatcher::Create(automation::HeadlessRequest request, PageInstance* page_instance) {
  new HeadlessDispatcher(std::move(request), page_instance);
}

HeadlessDispatcher::HeadlessDispatcher(automation::HeadlessRequest request, PageInstance* page_instance): 
  application_id_(-1),
  page_instance_(page_instance),
  binding_(this) {

}

HeadlessDispatcher::HeadlessDispatcher(PageInstance* page_instance): 
  application_id_(-1),
  page_instance_(page_instance),
  binding_(this) {

}

HeadlessDispatcher::~HeadlessDispatcher() {

}

void HeadlessDispatcher::Init(IPC::SyncChannel* channel) {
  channel->GetRemoteAssociatedInterface(&headless_client_ptr_);
}

void HeadlessDispatcher::Bind(automation::HeadlessAssociatedRequest request) {
  //DLOG(INFO) << "HeadlessDispatcher::Bind (application)";
  binding_.Bind(std::move(request));  
}

void HeadlessDispatcher::Register(int32_t application_id) {
  application_id_ = application_id;
}

void HeadlessDispatcher::BeginFrame(int64_t frame_time, int32_t frame_time_ticks, int64_t deadline, int32_t deadline_ticks, int32_t interval, bool no_display_updates, automation::ScreenshotParamsPtr screenshot, BeginFrameCallback callback) {
 
}

void HeadlessDispatcher::EnterDeterministicMode(int32_t initial_date) {

}

void HeadlessDispatcher::Disable() {

}

void HeadlessDispatcher::Enable() {
  //DLOG(INFO) << "HeadlessDispatcher::Enable (application process)";
}

void HeadlessDispatcher::OnWebFrameCreated(blink::WebLocalFrame* web_frame) {
  Enable();
}

}