// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/page_instance.h"

#define INSIDE_BLINK 1

#include "base/single_thread_task_runner.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_float_rect.h"
#include "third_party/blink/public/platform/web_rect.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/web/web_settings.h"
#include "third_party/blink/public/web/web_view_client.h"
#include "third_party/blink/renderer/core/CoreProbeSink.h"
#include "third_party/blink/renderer/core/core_initializer.h"
#include "third_party/blink/renderer/core/events/web_input_event_conversion.h"
#include "third_party/blink/renderer/core/exported/web_settings_impl.h"
#include "third_party/blink/renderer/core/exported/web_view_impl.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/web_frame_widget_base.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/core/inspector/inspector_resource_content_loader.h"
#include "third_party/blink/renderer/core/inspector/inspector_resource_container.h"
#include "third_party/blink/renderer/core/inspector/inspected_frames.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/platform/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_controller.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/layout_test_support.h"
#include "third_party/blink/renderer/platform/web_task_runner.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"


namespace application {

// static 
std::unique_ptr<PageInstance> PageInstance::Create() {
  return std::make_unique<PageInstance>();
}

PageInstance::PageInstance(): 
    inspector_resource_content_loader_id_(-1) {
  state_ = blink::protocol::DictionaryValue::create();
  inspector_backend_dispatcher_.reset(new blink::protocol::UberDispatcher(this));
}

PageInstance::~PageInstance() {
  inspected_frames_ = nullptr;
}

blink::CoreProbeSink* PageInstance::probe_sink() const {
  blink::LocalFrame* frame = inspected_frames()->Root();
  return frame ? frame->GetProbeSink() : nullptr;
}

void PageInstance::AddScript(const std::string& identifier, const std::string& script) {
  scripts_.emplace(std::make_pair(identifier, script));
}

void PageInstance::RemoveScript(const std::string& identifier) {
  auto it = scripts_.find(identifier);
  if (it != scripts_.end()) {
    scripts_.erase(it);
  }
}

void PageInstance::OnWebFrameCreated(blink::WebLocalFrame* web_frame) {
  blink::LocalFrame* main_frame = static_cast<blink::LocalFrame *>(blink::WebFrame::ToCoreFrame(*web_frame));
  blink::InspectorResourceContentLoader* resource_content_loader = blink::InspectorResourceContentLoader::Create(main_frame);
  inspector_resource_content_loader_ = resource_content_loader;
  inspector_resource_content_loader_id_ = resource_content_loader->CreateClientId();
  inspected_frames_ = new blink::InspectedFrames(main_frame);
  inspector_resource_container_ = new blink::InspectorResourceContainer(inspected_frames_.Get());
}

void PageInstance::sendProtocolResponse(
  int call_id,
  std::unique_ptr<blink::protocol::Serializable> message) {
  //DLOG(INFO) << "PageInstance::sendProtocolResponse (protocol::FrontendChannel)";
}

void PageInstance::sendProtocolNotification(
      std::unique_ptr<blink::protocol::Serializable> message) {
  //DLOG(INFO) << "PageInstance::sendProtocolNotification (protocol::FrontendChannel)";
}

void PageInstance::flushProtocolNotifications() {
  //DLOG(INFO) << "PageInstance::flushProtocolNotifications (protocol::FrontendChannel)"; 
}

}