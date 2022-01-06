// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/device_orientation_dispatcher.h"

#include "services/service_manager/public/cpp/interface_provider.h"
#include "core/shared/application/automation/page_dispatcher.h"
#include "third_party/blink/renderer/modules/device_orientation/device_orientation_inspector_agent.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/inspected_frames.h"
#include "core/shared/application/automation/page_instance.h"
#include "third_party/blink/renderer/modules/device_orientation/device_orientation_controller.h"
#include "third_party/blink/renderer/modules/device_orientation/device_orientation_data.h"
#include "ipc/ipc_sync_channel.h"

namespace application {

class DeviceOrientationInspectorAgentImpl : public blink::DeviceOrientationInspectorAgent {
public: 
  DeviceOrientationInspectorAgentImpl(DeviceOrientationDispatcher* dispatcher): 
    DeviceOrientationInspectorAgent(
      dispatcher->page_instance_->inspected_frames()),
    dispatcher_(dispatcher) {}

  void Restore() override {
    dispatcher_->Restore();
  }

  void DidCommitLoadForLocalFrame(blink::LocalFrame* frame) override {
    dispatcher_->DidCommitLoadForLocalFrame(frame);
  }

private:
  DeviceOrientationDispatcher* dispatcher_;
};

// static 
void DeviceOrientationDispatcher::Create(automation::DeviceOrientationRequest request, PageInstance* page_instance) {
  new DeviceOrientationDispatcher(std::move(request), page_instance);
}

DeviceOrientationDispatcher::DeviceOrientationDispatcher(automation::DeviceOrientationRequest request, PageInstance* page_instance): 
  page_instance_(page_instance),
  application_id_(-1),
  binding_(this),
  alpha_(0),
  beta_(0),
  gamma_(0),
  enabled_(false) {
  
}

DeviceOrientationDispatcher::DeviceOrientationDispatcher(PageInstance* page_instance): 
  page_instance_(page_instance),
  application_id_(-1),
  binding_(this),
  alpha_(0),
  beta_(0),
  gamma_(0),
  enabled_(false) {
  

}

DeviceOrientationDispatcher::~DeviceOrientationDispatcher() {

}

void DeviceOrientationDispatcher::Init(IPC::SyncChannel* channel) {
 
}

void DeviceOrientationDispatcher::Bind(automation::DeviceOrientationAssociatedRequest request) {
  //DLOG(INFO) << "DeviceOrientationDispatcher::Bind (application)";
  binding_.Bind(std::move(request));
}

void DeviceOrientationDispatcher::Register(int32_t application_id) {
  application_id_ = application_id;
}

void DeviceOrientationDispatcher::ClearDeviceOrientationOverride() {
  enabled_ = false;
  if (Controller())
    Controller()->ClearOverride();
}

void DeviceOrientationDispatcher::SetDeviceOrientationOverride(int32_t alpha, int32_t beta, int32_t gamma) {
  enabled_ = true;
  alpha_ = alpha;
  beta_ = beta;
  gamma_ = gamma;
  //page_instance_->probe_sink()->addDeviceOrientationInspectorAgent(device_orientation_inspector_agent_.Get());
  if (Controller()) {
    Controller()->SetOverride(
      blink::DeviceOrientationData::Create(alpha, beta, gamma, false));
  }
}

void DeviceOrientationDispatcher::Restore() {
  if (!Controller())
    return;
  if (enabled_) {
    Controller()->SetOverride(
      blink::DeviceOrientationData::Create(alpha_, beta_, gamma_, false));
  }
}

void DeviceOrientationDispatcher::DidCommitLoadForLocalFrame(blink::LocalFrame* frame) {
  if (frame == page_instance_->inspected_frames()->Root()) {
    // New document in main frame - apply override there.
    // No need to cleanup previous one, as it's already gone.
    Restore();
  }
}

blink::DeviceOrientationController* DeviceOrientationDispatcher::Controller() {
  blink::Document* document = page_instance_->inspected_frames()->Root()->GetDocument();
  return document ? &blink::DeviceOrientationController::From(*document) : nullptr;
}

void DeviceOrientationDispatcher::OnWebFrameCreated(blink::WebLocalFrame* web_frame) {
  device_orientation_inspector_agent_ = new DeviceOrientationInspectorAgentImpl(this);
  device_orientation_inspector_agent_->Init(
    page_instance_->probe_sink(), 
    page_instance_->inspector_backend_dispatcher(),
    page_instance_->state());
}

}