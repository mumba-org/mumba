// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/animation_dispatcher.h"

#include "base/strings/string_number_conversions.h"
#include "services/service_manager/public/cpp/interface_provider.h"
#include "core/shared/application/automation/automation_context.h"
#include "core/shared/application/automation/page_instance.h"
#include "core/shared/application/automation/css_dispatcher.h"
#include "core/shared/application/automation/css_service.h"
#include "core/shared/application/application_window_dispatcher.h"
#include "third_party/blink/renderer/core/animation/animation.h"
#include "third_party/blink/renderer/core/animation/animation_effect.h"
#include "third_party/blink/renderer/core/animation/computed_effect_timing.h"
#include "third_party/blink/renderer/core/animation/css/css_animations.h"
#include "third_party/blink/renderer/core/animation/effect_model.h"
#include "third_party/blink/renderer/core/animation/element_animation.h"
#include "third_party/blink/renderer/core/animation/element_animations.h"
#include "third_party/blink/renderer/core/animation/keyframe_effect.h"
#include "third_party/blink/renderer/core/animation/keyframe_effect_model.h"
#include "third_party/blink/renderer/core/animation/optional_effect_timing.h"
#include "third_party/blink/renderer/core/animation/string_keyframe.h"
#include "third_party/blink/renderer/core/css/css_keyframe_rule.h"
#include "third_party/blink/renderer/core/css/css_keyframes_rule.h"
#include "third_party/blink/renderer/core/css/css_rule_list.h"
#include "third_party/blink/renderer/core/css/css_style_rule.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/add_string_to_digestor.h"
#include "third_party/blink/renderer/core/inspector/inspected_frames.h"
#include "core/shared/application/automation/inspector_style_sheet.h"
#include "third_party/blink/renderer/platform/animation/timing_function.h"
#include "third_party/blink/renderer/platform/decimal.h"
#include "third_party/blink/renderer/platform/wtf/text/base64.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/inspector/inspector_animation_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_css_agent.h"
#include "third_party/blink/renderer/core/inspector/inspected_frames.h"
#include "third_party/blink/renderer/core/inspector/add_string_to_digestor.h"
#include "ipc/ipc_sync_channel.h"


namespace application {

static automation::AnimationEffectPtr BuildObjectForAnimationEffect(blink::KeyframeEffect* effect, bool is_transition) {
  blink::ComputedEffectTiming computed_timing = effect->getComputedTiming();
  double delay = computed_timing.delay();
  double duration = computed_timing.duration().GetAsUnrestrictedDouble();
  String easing = effect->SpecifiedTiming().timing_function->ToString();

  if (is_transition) {
    // Obtain keyframes and convert keyframes back to delay
    DCHECK(effect->Model()->IsKeyframeEffectModel());
    const blink::KeyframeVector& keyframes = effect->Model()->GetFrames();
    if (keyframes.size() == 3) {
      delay = keyframes.at(1)->CheckedOffset() * duration;
      duration -= delay;
      easing = keyframes.at(1)->Easing().ToString();
    } else {
      easing = keyframes.at(0)->Easing().ToString();
    }
  }

  automation::AnimationEffectPtr animation_object = automation::AnimationEffect::New();
  animation_object->delay = delay;
  animation_object->end_delay = computed_timing.endDelay();
  animation_object->iteration_start = computed_timing.iterationStart();
  animation_object->iterations = computed_timing.iterations();
  animation_object->duration = duration;
  animation_object->direction = std::string(computed_timing.direction().Utf8().data(), computed_timing.direction().Utf8().length());
  animation_object->fill = std::string(computed_timing.fill().Utf8().data(), computed_timing.fill().Utf8().length());
  animation_object->easing = std::string(easing.Utf8().data(), easing.Utf8().length());
  if (effect->target())
    animation_object->backend_node_id = blink::DOMNodeIds::IdForNode(effect->target());
  return animation_object;
}

static automation::KeyframeStylePtr BuildObjectForStringKeyframe(
  const blink::StringKeyframe* keyframe,
  double computed_offset) {
  
  String offset = String::NumberToStringECMAScript(computed_offset * 100);
  offset.append('%');

  automation::KeyframeStylePtr keyframe_object = automation::KeyframeStyle::New();
  keyframe_object->offset = std::string(offset.Utf8().data(), offset.Utf8().length());
  String easing_str = keyframe->Easing().ToString();
  keyframe_object->easing = std::string(easing_str.Utf8().data(), easing_str.Utf8().length());
  return keyframe_object;
}

static automation::KeyframesRulePtr BuildObjectForAnimationKeyframes(const blink::KeyframeEffect* effect) {
  if (!effect || !effect->Model() || !effect->Model()->IsKeyframeEffectModel())
    return nullptr;
  const blink::KeyframeEffectModelBase* model = effect->Model();
  Vector<double> computed_offsets =
      blink::KeyframeEffectModelBase::GetComputedOffsets(model->GetFrames());
  std::vector<automation::KeyframeStylePtr> keyframes;

  for (size_t i = 0; i < model->GetFrames().size(); i++) {
    const blink::Keyframe* keyframe = model->GetFrames().at(i).get();
    // Ignore CSS Transitions
    if (!keyframe->IsStringKeyframe())
      continue;
    const blink::StringKeyframe* string_keyframe = ToStringKeyframe(keyframe);
    keyframes.push_back(BuildObjectForStringKeyframe(string_keyframe, computed_offsets.at(i)));
  }
  automation::KeyframesRulePtr result = automation::KeyframesRule::New();
  result->keyframes = std::move(keyframes);
  return result;
}

static String AnimationTypeToString(automation::AnimationType type) {
  switch (type) {
    case automation::AnimationType::kANIMATION_TYPE_CSS_TRANSITION:
      return "CSSTransition";
    case automation::AnimationType::kANIMATION_TYPE_CSS_ANIMATION:
      return "CSSAnimation";
    case automation::AnimationType::kANIMATION_TYPE_WEB_ANIMATION:
      return "WebAnimation";
  }
  return "WebAnimation";
}

class InspectorAnimationAgentImpl : public blink::InspectorAnimationAgent {
public:
  InspectorAnimationAgentImpl(AnimationDispatcher* dispatcher, 
                              blink::InspectedFrames* inspected_frames,
                              CSSDispatcher* css_dispatcher): 
    InspectorAnimationAgent(inspected_frames, css_dispatcher->css_agent(), nullptr),
    dispatcher_(dispatcher) {
    
  }

  void DidCreateAnimation(unsigned sequence_number) override {
    dispatcher_->DidCreateAnimation(sequence_number);
  }

  void AnimationPlayStateChanged(
    blink::Animation* animation,
    blink::Animation::AnimationPlayState old_play_state,
    blink::Animation::AnimationPlayState new_play_state) override {
    dispatcher_->AnimationPlayStateChanged(animation, old_play_state, new_play_state);
  }

  void DidClearDocumentOfWindowObject(blink::LocalFrame* frame) override {
    dispatcher_->DidClearDocumentOfWindowObject(frame);
  }
  
private:
  AnimationDispatcher* dispatcher_;
  DISALLOW_COPY_AND_ASSIGN(InspectorAnimationAgentImpl);
};

// static
void AnimationDispatcher::Create(automation::AnimationInterfaceRequest request, AutomationContext* context, PageInstance* page_instance) {
  new AnimationDispatcher(std::move(request), context, page_instance);
}

AnimationDispatcher::AnimationDispatcher(
  automation::AnimationInterfaceRequest request,
  AutomationContext* context,
  PageInstance* page_instance): 
    page_instance_(page_instance),
    css_dispatcher_(context->css_dispatcher()),
    application_id_(-1),
    binding_(this),
    playback_rate_(0),
    enabled_(false),
    is_cloning_(false) {
  
}

AnimationDispatcher::AnimationDispatcher(
  AutomationContext* context,
  PageInstance* page_instance): 
    page_instance_(page_instance),
    css_dispatcher_(context->css_dispatcher()),
    application_id_(-1),
    binding_(this),
    playback_rate_(0),
    enabled_(false),
    is_cloning_(false) {
  
}

AnimationDispatcher::~AnimationDispatcher() {

}

void AnimationDispatcher::Init(IPC::SyncChannel* channel) {
  //DLOG(INFO) << "AnimationDispatcher::Init:  channel->GetRemoteAssociatedInterface(&animation_client_ptr_)";
  channel->GetRemoteAssociatedInterface(&animation_client_ptr_);
}

void AnimationDispatcher::Bind(automation::AnimationInterfaceAssociatedRequest request) {
  //DLOG(INFO) << "AnimationDispatcher::Bind (application)";
  binding_.Bind(std::move(request));
}

void AnimationDispatcher::Register(int32_t application_id) {
  application_id_ = application_id;
}

void AnimationDispatcher::Disable() {
  enabled_ = false;
  page_instance_->probe_sink()->removeInspectorAnimationAgent(animation_agent_impl_.Get());
}

void AnimationDispatcher::Enable() {
  //DLOG(INFO) << "AnimationDispatcher::Enable (application process)";
  if (enabled_) {
    return;
  }
  page_instance_->probe_sink()->addInspectorAnimationAgent(animation_agent_impl_.Get());
  enabled_ = true;
}

automation::AnimationClient* AnimationDispatcher::GetClient() const {
  return animation_client_ptr_.get();  
}

void AnimationDispatcher::GetCurrentTime(const std::string& id, GetCurrentTimeCallback callback) {
  blink::Animation* animation = nullptr;
  String animation_id = String::FromUTF8(id.data());
  bool ok = AssertAnimation(animation_id, animation);
  if (!ok) {
    //DLOG(ERROR) << "No animation with id " << id << " found";
    return;
  }
  if (id_to_animation_clone_.at(animation_id))
    animation = id_to_animation_clone_.at(animation_id);

  if (animation->Paused()) {
    std::move(callback).Run(animation->currentTime());
  } else {
    // Use startTime where possible since currentTime is limited.
    std::move(callback).Run(animation->TimelineInternal()->currentTime() -
                            animation->startTime().value_or(blink::NullValue()));
  }
}

void AnimationDispatcher::GetPlaybackRate(GetPlaybackRateCallback callback) {
  std::move(callback).Run(ReferenceTimeline().PlaybackRate());
}

void AnimationDispatcher::SetPlaybackRate(int32_t playback_rate) {
  for (blink::LocalFrame* frame : *page_instance_->inspected_frames())
    frame->GetDocument()->Timeline().SetPlaybackRate(playback_rate);
  
  playback_rate_ = playback_rate;
}

void AnimationDispatcher::ReleaseAnimations(const std::vector<std::string>& animation_ids) {
  for (size_t i = 0; i < animation_ids.size(); ++i) {
    String animation_id = String::FromUTF8(animation_ids[i].data());
    blink::Animation* animation = id_to_animation_.at(animation_id);
    if (animation)
      animation->SetEffectSuppressed(false);
    blink::Animation* clone = id_to_animation_clone_.at(animation_id);
    if (clone)
      clone->cancel();
    id_to_animation_clone_.erase(animation_id);
    id_to_animation_.erase(animation_id);
    id_to_animation_type_.erase(animation_id);
    cleared_animations_.insert(animation_id);
  }
}

void AnimationDispatcher::ResolveAnimation(const std::string& id, ResolveAnimationCallback callback) {
  blink::Animation* animation = nullptr;
  String animation_id = String::FromUTF8(id.data());
  bool ok = AssertAnimation(animation_id, animation);
  if (!ok) {
    //DLOG(ERROR) << "No animation with id " << id << " found";
    return;
  }
  if (id_to_animation_clone_.at(animation_id))
    animation = id_to_animation_clone_.at(animation_id);

  DCHECK(animation);

  std::move(callback).Run(BuildObjectForAnimation(*animation));
  // const blink::Element* element = blink::ToKeyframeEffect(animation->effect())->target();
  // blink::Document* document = element->ownerDocument();
  // blink::LocalFrame* frame = document ? document->GetFrame() : nullptr;
  // blink::ScriptState* script_state =
  //     frame ? blink::ToScriptStateForMainWorld(frame) : nullptr;
  // if (!script_state) {
  //   //DLOG(ERROR) << "Element not associated with a document.";
  //   return;
  // }

  // blink::ScriptState::Scope scope(script_state);
  // static const char kAnimationObjectGroup[] = "animation";
  // v8_session_->releaseObjectGroup(
  //     ToV8InspectorStringView(kAnimationObjectGroup));
  // *result = v8_session_->wrapObject(
  //     script_state->GetContext(),
  //     ToV8(animation, script_state->GetContext()->Global(),
  //          script_state->GetIsolate()),
  //     ToV8InspectorStringView(kAnimationObjectGroup),
  //     false /* generatePreview */);
  // if (!*result)
  //   return Response::Error("Element not associated with a document.");
}

void AnimationDispatcher::SeekAnimations(const std::vector<std::string>& animation_ids, int32_t current_time) {
  for (size_t i = 0; i < animation_ids.size(); ++i) {
    String animation_id = String::FromUTF8(animation_ids[i].data());
    blink::Animation* animation = nullptr;
    bool ok = AssertAnimation(animation_id, animation);
    if (!ok) {
      //DLOG(ERROR) << "No animation with id " << animation_ids[i] << " found";
      return;
    }
    blink::Animation* clone = AnimationClone(animation);
    if (!clone) {
      //DLOG(ERROR) << "Failed to clone a detached animation.";
      return;
    }
    if (!clone->Paused()) {
      clone->play();
    }
    clone->setCurrentTime(current_time, false);
  }
}

void AnimationDispatcher::SetPaused(const std::vector<std::string>& animation_ids, bool paused) {
  for (size_t i = 0; i < animation_ids.size(); ++i) {
    String animation_id = String::FromUTF8(animation_ids[i].data());
    blink::Animation* animation = nullptr;
    bool ok = AssertAnimation(animation_id, animation);
    if (!ok) {
      // FIXME
      //DLOG(ERROR) << "No animation with id " << animation_ids[i] << " found";
      return;
    }
    blink::Animation* clone = AnimationClone(animation);
    if (!clone) {
      // FIXME
      //DLOG(ERROR) << "Failed to clone detached animation";
      return;
    }
    if (paused && !clone->Paused()) {
      // Ensure we restore a current time if the animation is limited.
      double current_time = clone->TimelineInternal()->currentTime() -
                            clone->startTime().value_or(blink::NullValue());
      clone->pause();
      clone->setCurrentTime(current_time, false);
    } else if (!paused && clone->Paused()) {
      clone->Unpause();
    }
  }
}

void AnimationDispatcher::SetTiming(const std::string& id, int32_t duration, int32_t delay) {
  blink::Animation* animation = nullptr;
  String animation_id = String::FromUTF8(id.data());
  bool ok = AssertAnimation(animation_id, animation);
  if (!ok) {
    //DLOG(ERROR) << "No animation with id " << id << " found";
    return;
  }
  animation = AnimationClone(animation);
  blink::NonThrowableExceptionState exception_state;

  automation::AnimationType type = id_to_animation_type_.at(animation_id);
  if (type == automation::AnimationType::kANIMATION_TYPE_CSS_TRANSITION) {
    blink::KeyframeEffect* effect = blink::ToKeyframeEffect(animation->effect());
    const blink::TransitionKeyframeEffectModel* old_model =
        blink::ToTransitionKeyframeEffectModel(effect->Model());
    // Refer to CSSAnimations::calculateTransitionUpdateForProperty() for the
    // structure of transitions.
    const blink::KeyframeVector& frames = old_model->GetFrames();
    DCHECK(frames.size() == 3);
    blink::KeyframeVector new_frames;
    for (int i = 0; i < 3; i++)
      new_frames.push_back(ToTransitionKeyframe(frames[i]->Clone().get()));
    // Update delay, represented by the distance between the first two
    // keyframes.
    new_frames[1]->SetOffset(delay / (delay + duration));
    effect->Model()->SetFrames(new_frames);

    blink::UnrestrictedDoubleOrString unrestricted_duration;
    unrestricted_duration.SetUnrestrictedDouble(duration + delay);
    blink::OptionalEffectTiming timing;
    timing.setDuration(unrestricted_duration);
    effect->updateTiming(timing, exception_state);
  } else {
    blink::OptionalEffectTiming timing;
    blink::UnrestrictedDoubleOrString unrestricted_duration;
    unrestricted_duration.SetUnrestrictedDouble(duration);
    timing.setDuration(unrestricted_duration);
    timing.setDelay(delay);
    animation->effect()->updateTiming(timing, exception_state);
  }
}

void AnimationDispatcher::DidCreateAnimation(unsigned sequence_number) {
  GetClient()->OnAnimationCreated(base::NumberToString(sequence_number));
}

void AnimationDispatcher::AnimationPlayStateChanged(
  blink::Animation* animation,
  blink::Animation::AnimationPlayState old_play_state,
  blink::Animation::AnimationPlayState new_play_state) {
  const String& animation_id = String::Number(animation->SequenceNumber());

  // We no longer care about animations that have been released.
  if (cleared_animations_.Contains(animation_id))
    return;

  // Record newly starting animations only once, as |buildObjectForAnimation|
  // constructs and caches our internal representation of the given |animation|.
  if ((new_play_state == blink::Animation::kRunning ||
       new_play_state == blink::Animation::kFinished) &&
      !id_to_animation_.Contains(animation_id)) {
    GetClient()->OnAnimationStarted(BuildObjectForAnimation(*animation));
  }
  else if (new_play_state == blink::Animation::kIdle ||
           new_play_state == blink::Animation::kPaused) {
    GetClient()->OnAnimationCanceled(std::string(animation_id.Utf8().data(), animation_id.Utf8().length()));
  }
}

void AnimationDispatcher::DidClearDocumentOfWindowObject(blink::LocalFrame* frame) {
  if (!enabled_) {
    return;
  }
  DCHECK(frame->GetDocument());
  frame->GetDocument()->Timeline().SetPlaybackRate(
      ReferenceTimeline().PlaybackRate());
}

blink::DocumentTimeline& AnimationDispatcher::ReferenceTimeline() {
  return page_instance_->inspected_frames()->Root()->GetDocument()->Timeline();
}

automation::AnimationPtr AnimationDispatcher::BuildObjectForAnimation(blink::Animation& animation) {
  automation::AnimationType animation_type;
  automation::AnimationEffectPtr animation_effect_object;

  if (!animation.effect()) {
    animation_type = automation::AnimationType::kANIMATION_TYPE_WEB_ANIMATION;
  } else {
    const blink::Element* element = ToKeyframeEffect(animation.effect())->target();
    automation::KeyframesRulePtr keyframe_rule = automation::KeyframesRule::New();

    if (!element) {
      animation_type = automation::AnimationType::kANIMATION_TYPE_WEB_ANIMATION;
    } else {
      blink::CSSAnimations& css_animations =
          element->GetElementAnimations()->CssAnimations();

      if (css_animations.IsTransitionAnimationForInspector(animation)) {
        // CSS Transitions
        animation_type = automation::AnimationType::kANIMATION_TYPE_CSS_TRANSITION;
      } else {
        // Keyframe based animations
        keyframe_rule = BuildObjectForAnimationKeyframes(
            ToKeyframeEffect(animation.effect()));
        animation_type = css_animations.IsAnimationForInspector(animation)
                             ? automation::AnimationType::kANIMATION_TYPE_CSS_ANIMATION
                             : automation::AnimationType::kANIMATION_TYPE_WEB_ANIMATION;
      }
    }

    animation_effect_object = BuildObjectForAnimationEffect(
        ToKeyframeEffect(animation.effect()),
        animation_type == automation::AnimationType::kANIMATION_TYPE_CSS_TRANSITION);
    animation_effect_object->keyframes_rule = std::move(keyframe_rule);
  }

  String id = String::Number(animation.SequenceNumber());
  id_to_animation_.Set(id, &animation);
  id_to_animation_type_.Set(id, animation_type);

  automation::AnimationPtr animation_object = automation::Animation::New();
  animation_object->id = std::string(animation.id().Utf8().data(), animation.id().Utf8().length());;
  animation_object->name = std::string(animation.id().Utf8().data(), animation.id().Utf8().length());
  animation_object->paused_state = animation.Paused();
  animation_object->play_state = std::string(animation.playState().Utf8().data(), animation.playState().Utf8().length());
  animation_object->playback_rate = animation.playbackRate();
  animation_object->start_time = NormalizedStartTime(animation);
  animation_object->current_time = animation.currentTime();
  animation_object->type = animation_type;
      
  if (animation_type != automation::AnimationType::kANIMATION_TYPE_WEB_ANIMATION) {
    String css_id_str = CreateCSSId(animation);
    animation_object->css_id = std::string(css_id_str.Utf8().data(), css_id_str.Utf8().length());
  }
  if (animation_effect_object) {
    animation_object->source = std::move(animation_effect_object);
  }
  return animation_object;
}

double AnimationDispatcher::NormalizedStartTime(blink::Animation& animation) {
  if (ReferenceTimeline().PlaybackRate() == 0) {
    return animation.startTime().value_or(blink::NullValue()) +
           ReferenceTimeline().currentTime() -
           animation.TimelineInternal()->currentTime();
  }
  return animation.startTime().value_or(blink::NullValue()) +
         (animation.TimelineInternal()->ZeroTime() -
          ReferenceTimeline().ZeroTime()) *
             1000 * ReferenceTimeline().PlaybackRate();
}

String AnimationDispatcher::CreateCSSId(blink::Animation& animation) {
  static const blink::CSSProperty* g_animation_properties[] = {
      &blink::GetCSSPropertyAnimationDelay(),
      &blink::GetCSSPropertyAnimationDirection(),
      &blink::GetCSSPropertyAnimationDuration(),
      &blink::GetCSSPropertyAnimationFillMode(),
      &blink::GetCSSPropertyAnimationIterationCount(),
      &blink::GetCSSPropertyAnimationName(),
      &blink::GetCSSPropertyAnimationTimingFunction(),
  };
  static const blink::CSSProperty* g_transition_properties[] = {
      &blink::GetCSSPropertyTransitionDelay(), 
      &blink::GetCSSPropertyTransitionDuration(),
      &blink::GetCSSPropertyTransitionProperty(),
      &blink::GetCSSPropertyTransitionTimingFunction(),
  };
  automation::AnimationType type =
      id_to_animation_type_.at(String::Number(animation.SequenceNumber()));
  DCHECK_NE(type, automation::AnimationType::kANIMATION_TYPE_WEB_ANIMATION);

  blink::KeyframeEffect* effect = ToKeyframeEffect(animation.effect());
  Vector<const blink::CSSProperty*> css_properties;
  if (type == automation::AnimationType::kANIMATION_TYPE_CSS_ANIMATION) {
    for (const blink::CSSProperty* property : g_animation_properties)
      css_properties.push_back(property);
  } else {
    for (const blink::CSSProperty* property : g_transition_properties)
      css_properties.push_back(property);
    css_properties.push_back(&blink::CSSProperty::Get(blink::cssPropertyID(animation.id())));
  }

  blink::Element* element = effect->target();
  blink::HeapVector<blink::Member<blink::CSSStyleDeclaration>> styles = css_dispatcher_->css_agent()->MatchingStyles(element);
  std::unique_ptr<blink::WebCryptoDigestor> digestor =
      CreateDigestor(blink::kHashAlgorithmSha1);
  blink::AddStringToDigestor(digestor.get(), AnimationTypeToString(type));
  blink::AddStringToDigestor(digestor.get(), animation.id());
  for (const blink::CSSProperty* property : css_properties) {
    blink::CSSStyleDeclaration* style =
        css_dispatcher_->css_agent()->FindEffectiveDeclaration(*property, styles);
    // Ignore inline styles.
    if (!style || !style->ParentStyleSheet() || !style->parentRule() ||
        style->parentRule()->type() != blink::CSSRule::kStyleRule)
      continue;
    blink::AddStringToDigestor(digestor.get(), property->GetPropertyNameString());
    blink::AddStringToDigestor(digestor.get(),
                        css_dispatcher_->StyleSheetId(style->ParentStyleSheet()));
    blink::AddStringToDigestor(digestor.get(),
                        ToCSSStyleRule(style->parentRule())->selectorText());
  }
  blink::DigestValue digest_result;
  FinishDigestor(digestor.get(), digest_result);
  return Base64Encode(reinterpret_cast<const char*>(digest_result.data()), 10);
}

bool AnimationDispatcher::AssertAnimation(const String& id,
                                          blink::Animation*& result) {
  result = id_to_animation_.at(id);
  if (!result)
    return false;
  return true;
}

blink::Animation* AnimationDispatcher::AnimationClone(blink::Animation* animation) {
  const String id = String::Number(animation->SequenceNumber());
  if (!id_to_animation_clone_.at(id)) {
    blink::KeyframeEffect* old_effect = blink::ToKeyframeEffect(animation->effect());
    DCHECK(old_effect->Model()->IsKeyframeEffectModel());
    blink::KeyframeEffectModelBase* old_model = old_effect->Model();
    blink::KeyframeEffectModelBase* new_model = nullptr;
    // Clone EffectModel.
    // TODO(samli): Determine if this is an animations bug.
    if (old_model->IsStringKeyframeEffectModel()) {
      blink::StringKeyframeEffectModel* old_string_keyframe_model =
          blink::ToStringKeyframeEffectModel(old_model);
      blink::KeyframeVector old_keyframes = old_string_keyframe_model->GetFrames();
      blink::StringKeyframeVector new_keyframes;
      for (auto& old_keyframe : old_keyframes)
        new_keyframes.push_back(ToStringKeyframe(old_keyframe.get()));
      new_model = blink::StringKeyframeEffectModel::Create(new_keyframes);
    } else if (old_model->IsTransitionKeyframeEffectModel()) {
      blink::TransitionKeyframeEffectModel* old_transition_keyframe_model =
          blink::ToTransitionKeyframeEffectModel(old_model);
      blink::KeyframeVector old_keyframes = old_transition_keyframe_model->GetFrames();
      blink::TransitionKeyframeVector new_keyframes;
      for (auto& old_keyframe : old_keyframes)
        new_keyframes.push_back(ToTransitionKeyframe(old_keyframe.get()));
      new_model = blink::TransitionKeyframeEffectModel::Create(new_keyframes);
    }

    blink::KeyframeEffect* new_effect = blink::KeyframeEffect::Create(
        old_effect->target(), new_model, old_effect->SpecifiedTiming());
    is_cloning_ = true;
    blink::Animation* clone =
        blink::Animation::Create(new_effect, animation->timeline());
    is_cloning_ = false;
    id_to_animation_clone_.Set(id, clone);
    id_to_animation_.Set(String::Number(clone->SequenceNumber()), clone);
    clone->play();
    clone->setStartTime(animation->startTime().value_or(blink::NullValue()), false);

    animation->SetEffectSuppressed(true);
  }
  return id_to_animation_clone_.at(id);
}

void AnimationDispatcher::OnWebFrameCreated(blink::WebLocalFrame* web_frame) {
  animation_agent_impl_ = new InspectorAnimationAgentImpl(this, page_instance_->inspected_frames(), css_dispatcher_);
  animation_agent_impl_->Init(
    page_instance_->probe_sink(), 
    page_instance_->inspector_backend_dispatcher(),
    page_instance_->state());
  Enable();
}

}