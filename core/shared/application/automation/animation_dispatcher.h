// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_APPLICATION_ANIMATION_DISPATCHER_H_
#define MUMBA_APPLICATION_ANIMATION_DISPATCHER_H_

#include "core/shared/common/mojom/automation.mojom.h"

#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "third_party/blink/renderer/platform/heap/heap.h"
#include "third_party/blink/renderer/platform/heap/heap_traits.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/core/animation/animation.h"

namespace service_manager {
class InterfaceProvider;
}

namespace blink {
class LocalFrame;
class DocumentTimeline;
class WebLocalFrame;
}

namespace IPC {
class SyncChannel;
}

namespace application {
class PageInstance;
class ApplicationWindowDispatcher;
class InspectorAnimationAgentImpl;
class AutomationContext;
class CSSDispatcher;
class ApplicationThread;

class AnimationDispatcher : public automation::AnimationInterface {
public:

  static void Create(automation::AnimationInterfaceRequest request, AutomationContext* context, PageInstance* page_instance);

  AnimationDispatcher(automation::AnimationInterfaceRequest request, AutomationContext* context, PageInstance* page_instance);
  AnimationDispatcher(AutomationContext* context, PageInstance* page_instance);
  ~AnimationDispatcher() override;

  void Init(IPC::SyncChannel* channel);
  void Bind(automation::AnimationInterfaceAssociatedRequest request);

  void Register(int32_t application_id) override;
  void Disable() override;
  void Enable() override;
  void GetCurrentTime(const std::string& id, GetCurrentTimeCallback callback) override;
  void GetPlaybackRate(GetPlaybackRateCallback callback) override;
  void ReleaseAnimations(const std::vector<std::string>& animations) override;
  void ResolveAnimation(const std::string& animation_id, ResolveAnimationCallback callback) override;
  void SeekAnimations(const std::vector<std::string>& animations, int32_t current_time) override;
  void SetPaused(const std::vector<std::string>& animations, bool paused) override;
  void SetPlaybackRate(int32_t playback_rate) override;
  void SetTiming(const std::string& animation_id, int32_t duration, int32_t delay) override;

  automation::AnimationClient* GetClient() const;
  PageInstance* page_instance() const {
    return page_instance_;
  }

  void OnWebFrameCreated(blink::WebLocalFrame* web_frame);
  
private:
  friend class InspectorAnimationAgentImpl;
  friend class ApplicationThread;

  void DidCreateAnimation(unsigned);
  void AnimationPlayStateChanged(blink::Animation*,
                                 blink::Animation::AnimationPlayState,
                                 blink::Animation::AnimationPlayState);
  void DidClearDocumentOfWindowObject(blink::LocalFrame*);

  blink::DocumentTimeline& ReferenceTimeline();
  automation::AnimationPtr BuildObjectForAnimation(blink::Animation& animation);
  double NormalizedStartTime(blink::Animation& animation);
  String CreateCSSId(blink::Animation& animation);
  bool AssertAnimation(const String& id, blink::Animation*& result);
  blink::Animation* AnimationClone(blink::Animation* animation);
  
  PageInstance* page_instance_;
  CSSDispatcher* css_dispatcher_;
  int32_t application_id_;
  mojo::AssociatedBinding<automation::AnimationInterface> binding_;
  automation::AnimationClientAssociatedPtr animation_client_ptr_;
  blink::HeapHashMap<String, blink::Member<blink::Animation>> id_to_animation_;
  blink::HeapHashMap<String, blink::Member<blink::Animation>> id_to_animation_clone_;
  HashMap<String, automation::AnimationType> id_to_animation_type_;
  HashSet<String> cleared_animations_;
  blink::Member<InspectorAnimationAgentImpl> animation_agent_impl_;
  int32_t playback_rate_;
  bool enabled_;
  bool is_cloning_;

  DISALLOW_COPY_AND_ASSIGN(AnimationDispatcher); 
};

}

#endif