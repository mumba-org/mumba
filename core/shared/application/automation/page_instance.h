// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_APPLICATION_PAGE_INSTANCE_H_
#define MUMBA_APPLICATION_PAGE_INSTANCE_H_

#include <string>
#include <unordered_map>

#include "third_party/blink/renderer/core/inspector/inspected_frames.h"
#include "third_party/blink/public/web/web_frame.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/CoreProbeSink.h"
#include "third_party/blink/renderer/core/inspector/protocol/Protocol.h"
#include "third_party/blink/renderer/platform/heap/handle.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"

namespace blink {
class LocalFrame;
class InspectedFrames;
class InspectorResourceContentLoader;
class InspectorResourceContainer;
class CoreProbeSink;
class WorkerGlobalScope;
class WebFrame;
class WebLocalFrame;
}

namespace application {

class PageInstance : public blink::protocol::FrontendChannel {
public:

  static std::unique_ptr<PageInstance> Create();

  PageInstance();
  ~PageInstance();

  blink::InspectedFrames* inspected_frames() const {
    return inspected_frames_.Get();
  }

  blink::InspectorResourceContentLoader* inspector_resource_content_loader() const {
    return inspector_resource_content_loader_.Get();
  }

  blink::InspectorResourceContainer* inspector_resource_container() const {
    return inspector_resource_container_.Get();
  }
  
  blink::CoreProbeSink* probe_sink() const;

  int inspector_resource_content_loader_id() const {
    return inspector_resource_content_loader_id_;
  }

  void AddScript(const std::string& identifier, const std::string& script);
  void RemoveScript(const std::string& identifier);

  bool bypass_csp_enabled() const {
    return bypass_csp_enabled_;
  }

  void set_bypass_csp_enabled(bool bypass_csp_enabled) {
    bypass_csp_enabled_ = bypass_csp_enabled;
  }

  size_t script_count() const {
    return scripts_.size();
  }

  const std::string& script_at(size_t index) {
    auto it = scripts_.begin();
    std::advance(it, index);
    return it->second;
  }

  blink::WorkerGlobalScope* worker_global_scope() const {
    return worker_global_scope_.Get();
  }

  blink::protocol::UberDispatcher* inspector_backend_dispatcher() const {
    return inspector_backend_dispatcher_.get();
  }

  blink::protocol::DictionaryValue* state() const {
    return state_.get();
  }

  void OnWebFrameCreated(blink::WebLocalFrame* web_frame);

  // FrontendChannel
  void sendProtocolResponse(
      int call_id,
      std::unique_ptr<blink::protocol::Serializable> message) override;
  void sendProtocolNotification(
      std::unique_ptr<blink::protocol::Serializable> message) override;

  void flushProtocolNotifications() override;

private:

  std::unordered_map<std::string, std::string> scripts_;
  blink::Persistent<blink::InspectedFrames> inspected_frames_;
  blink::Member<blink::InspectorResourceContentLoader> inspector_resource_content_loader_;
  blink::Member<blink::InspectorResourceContainer> inspector_resource_container_;
  blink::Member<blink::WorkerGlobalScope> worker_global_scope_;

  //blink::Member<blink::CoreProbeSink> instrumenting_agents_;
  std::unique_ptr<blink::protocol::UberDispatcher> inspector_backend_dispatcher_;
  std::unique_ptr<blink::protocol::DictionaryValue> state_;
  
  int inspector_resource_content_loader_id_;
  bool bypass_csp_enabled_;

  DISALLOW_COPY_AND_ASSIGN(PageInstance); 
};

}

#endif