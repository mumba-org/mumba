// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/emulation_dispatcher.h"

#include "core/shared/application/automation/page_instance.h"
#include "services/service_manager/public/cpp/interface_provider.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_float_point.h"
#include "third_party/blink/public/platform/web_thread.h"
#include "third_party/blink/public/platform/web_touch_event.h"
#include "third_party/blink/public/web/web_frame.h"
#include "third_party/blink/renderer/core/inspector/inspected_frames.h"
#include "third_party/blink/renderer/core/exported/web_view_impl.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/inspector/dev_tools_emulator.h"
#include "third_party/blink/renderer/core/inspector/inspector_emulation_agent.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/platform/geometry/double_rect.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/scheduler/util/thread_cpu_throttler.h"
#include "third_party/blink/renderer/platform/wtf/time.h"
#include "ipc/ipc_sync_channel.h"

namespace application {

class InspectorEmulationAgentImpl : public blink::InspectorEmulationAgent {
public: 
  InspectorEmulationAgentImpl(EmulationDispatcher* dispatcher, blink::WebLocalFrameImpl* local_frame): 
    InspectorEmulationAgent(local_frame),
    dispatcher_(dispatcher) {}
  
  void FrameStartedLoading(blink::LocalFrame* frame, blink::FrameLoadType type) override {
    dispatcher_->FrameStartedLoading(frame, type);
  }

private:
  EmulationDispatcher* dispatcher_;
};

// static 
void EmulationDispatcher::Create(automation::EmulationRequest request, PageInstance* page_instance) {
  new EmulationDispatcher(std::move(request), page_instance);
}

EmulationDispatcher::EmulationDispatcher(automation::EmulationRequest request, PageInstance* page_instance): 
  application_id_(-1),
  page_instance_(page_instance),
  binding_(this),
  virtual_time_offset_(0),
  max_touch_points_(0),
  script_execution_disabled_(false),
  touch_event_emulation_enabled_(false) {
  
}

EmulationDispatcher::EmulationDispatcher(PageInstance* page_instance): 
  application_id_(-1),
  page_instance_(page_instance),
  binding_(this),
  virtual_time_offset_(0),
  max_touch_points_(0),
  script_execution_disabled_(false),
  touch_event_emulation_enabled_(false) {
  
  
}

EmulationDispatcher::~EmulationDispatcher() {
  page_instance_->probe_sink()->removeInspectorEmulationAgent(inspector_emulation_agent_.Get());
  web_local_frame_->View()->Scheduler()->RemoveVirtualTimeObserver(this);
}

void EmulationDispatcher::Init(IPC::SyncChannel* channel) {
  channel->GetRemoteAssociatedInterface(&emulation_client_ptr_);
}

void EmulationDispatcher::Bind(automation::EmulationAssociatedRequest request) {
  //DLOG(INFO) << "EmulationDispatcher::Bind (application)";
  binding_.Bind(std::move(request));
}

void EmulationDispatcher::Register(int32_t application_id) {
  application_id_ = application_id;
}

blink::WebViewImpl* EmulationDispatcher::GetWebViewImpl() {
  return web_local_frame_->ViewImpl();
}

void EmulationDispatcher::CanEmulate(CanEmulateCallback callback) {
  std::move(callback).Run(true);
}

void EmulationDispatcher::ResetPageScaleFactor() {
  GetWebViewImpl()->ResetScaleStateImmediately();
}

void EmulationDispatcher::SetCPUThrottlingRate(int32_t rate) {
  blink::scheduler::ThreadCPUThrottler::GetInstance()->SetThrottlingRate(rate);
}

void EmulationDispatcher::SetDefaultBackgroundColorOverride(automation::RGBAPtr color) {
  if (!color.get()) {
    // Clear the override and state.
    GetWebViewImpl()->ClearBaseBackgroundColorOverride();
    default_background_color_override_rgba_.reset();
    return;
  }

  // Clamping of values is done by Color() constructor.
  float input_alpha = color->a == -1.0 ? 1.0f : color->a;
  int alpha = lroundf(255.0f * input_alpha);
  
  default_background_color_override_rgba_ = blink::Color(color->r, color->g, color->b, alpha).Rgb();
  
  GetWebViewImpl()->SetBaseBackgroundColorOverride(default_background_color_override_rgba_.value());
}

void EmulationDispatcher::SetDeviceMetricsOverride(int32_t width, int32_t height, float device_scale_factor, bool mobile, float scale, int32_t screen_width, int32_t screen_height, int32_t position_x, int32_t position_y, bool dont_set_visible_size, automation::ScreenOrientationPtr screen_orientation, automation::ViewportPtr viewport) {}
void EmulationDispatcher::ClearDeviceMetricsOverride() {}
void EmulationDispatcher::SetEmitTouchEventsForMouse(bool enabled, automation::TouchEventForMouseConfiguration configuration) {}
void EmulationDispatcher::SetGeolocationOverride(int64_t latitude, int64_t longitude, int64_t accuracy) {}
void EmulationDispatcher::ClearGeolocationOverride() {}
void EmulationDispatcher::SetVisibleSize(int32_t width, int32_t height) {}

void EmulationDispatcher::SetEmulatedMedia(const std::string& media) {
  emulated_media_ = media;
  GetWebViewImpl()->GetPage()->GetSettings().SetMediaTypeOverride(String::FromUTF8((media.data())));
}

void EmulationDispatcher::SetNavigatorOverrides(const std::string& platform) {
  navigator_platform_ = platform;
  GetWebViewImpl()->GetPage()->GetSettings().SetNavigatorPlatformOverride(String::FromUTF8(platform.data()));
}

void EmulationDispatcher::SetPageScaleFactor(float page_scale_factor) {
  GetWebViewImpl()->SetPageScaleFactor(static_cast<float>(page_scale_factor));
}

void EmulationDispatcher::SetScriptExecutionDisabled(bool value) {
  script_execution_disabled_ = value;
  GetWebViewImpl()->GetDevToolsEmulator()->SetScriptExecutionDisabled(value);
}

void EmulationDispatcher::SetTouchEmulationEnabled(bool enabled, int32_t max_touch_points) {
  int max_points = max_touch_points == - 1 ? 1 : max_touch_points;
  if (max_points < 1 || max_points > blink::WebTouchEvent::kTouchesLengthCap) {
    //DLOG(ERROR) << "Touch points must be between 1 and " << String::Number(blink::WebTouchEvent::kTouchesLengthCap);
    return;
  }
  touch_event_emulation_enabled_ = enabled;
  max_touch_points_ = max_points;
  GetWebViewImpl()->GetDevToolsEmulator()->SetTouchEventEmulationEnabled(enabled, max_points);
}

void EmulationDispatcher::SetVirtualTimePolicy(
  automation::VirtualTimePolicy policy, 
  int32_t virtual_time_budget_ms, 
  int32_t max_virtual_time_task_starvation_count, 
  bool wait_for_navigation, 
  SetVirtualTimePolicyCallback callback) {
  
  virtual_time_policy_ = policy;

  double virtual_time_base_ms = 0;
  double virtual_time_ticks_base_ms = 0;

  PendingVirtualTimePolicy new_policy;
  new_policy.policy = blink::PageScheduler::VirtualTimePolicy::kPause;
  if (policy == automation::VirtualTimePolicy::kVIRTUAL_TIME_POLICY_ADVANCE) {
    new_policy.policy = blink::PageScheduler::VirtualTimePolicy::kAdvance;
  } else if (policy == automation::VirtualTimePolicy::kVIRTUAL_TIME_POLICY_PAUSE_IF_NETWORK_FETCHES_PENDING) {
    new_policy.policy = blink::PageScheduler::VirtualTimePolicy::kDeterministicLoading;
  }

  if (virtual_time_budget_ms != -1) {
    new_policy.virtual_time_budget_ms = virtual_time_budget_ms;
    virtual_time_budget_ = *new_policy.virtual_time_budget_ms;
    // Record the current virtual time offset so Restore can compute how much
    // budget is left.
    virtual_time_offset_ = 0.0;
  } else {
    virtual_time_budget_.reset();
  }

  if (max_virtual_time_task_starvation_count != -1) {
    new_policy.max_virtual_time_task_starvation_count = max_virtual_time_task_starvation_count;
    virtual_time_task_starvation_count_ = *new_policy.max_virtual_time_task_starvation_count;
  } else {
    virtual_time_task_starvation_count_.reset();
  }

  // if (!virtual_time_setup_) {
  //   instrumenting_agents_->addInspectorEmulationAgent(this);
  //   web_local_frame_->View()->Scheduler()->AddVirtualTimeObserver(this);
  //   virtual_time_setup_ = true;
  // }

  if (wait_for_navigation) {
    pending_virtual_time_policy_ = std::move(new_policy);
  } else {
    ApplyVirtualTimePolicy(new_policy);
  }

  if (virtual_time_base_ticks_.is_null()) {
    virtual_time_base_ms = 0;
    virtual_time_ticks_base_ms = 0;
  } else {
    WTF::TimeDelta virtual_time_base_delta =
        virtual_time_base_ticks_ - WTF::TimeTicks::UnixEpoch();
    virtual_time_base_ms = virtual_time_base_delta.InMillisecondsF();
    virtual_time_ticks_base_ms =
        (virtual_time_base_ticks_ - WTF::TimeTicks()).InMillisecondsF();
  }
  std::move(callback).Run(virtual_time_base_ms, virtual_time_ticks_base_ms);
}

void EmulationDispatcher::ApplyVirtualTimePolicy(const PendingVirtualTimePolicy& new_policy) {
  web_local_frame_->View()->Scheduler()->SetVirtualTimePolicy(
      new_policy.policy);
  virtual_time_base_ticks_ =
      web_local_frame_->View()->Scheduler()->EnableVirtualTime();
  if (new_policy.virtual_time_budget_ms) {
    TRACE_EVENT_ASYNC_BEGIN1("renderer.scheduler", "VirtualTimeBudget", this,
                             "budget", *new_policy.virtual_time_budget_ms);
    WTF::TimeDelta budget_amount =
        WTF::TimeDelta::FromMillisecondsD(*new_policy.virtual_time_budget_ms);
    web_local_frame_->View()->Scheduler()->GrantVirtualTimeBudget(
        budget_amount,
        WTF::Bind(&EmulationDispatcher::VirtualTimeBudgetExpired,
                  WTF::Unretained(this)));
  }
  if (new_policy.max_virtual_time_task_starvation_count) {
    web_local_frame_->View()->Scheduler()->SetMaxVirtualTimeTaskStarvationCount(
        *new_policy.max_virtual_time_task_starvation_count);
  }
}

void EmulationDispatcher::VirtualTimeBudgetExpired() {
  TRACE_EVENT_ASYNC_END0("renderer.scheduler", "VirtualTimeBudget", this);
  web_local_frame_->View()->Scheduler()->SetVirtualTimePolicy(blink::PageScheduler::VirtualTimePolicy::kPause);
  GetClient()->OnVirtualTimeBudgetExpired();
}

void EmulationDispatcher::OnVirtualTimeAdvanced(WTF::TimeDelta virtual_time_offset) {
  virtual_time_offset_ = virtual_time_offset.InMillisecondsF();
  GetClient()->OnVirtualTimeAdvanced(virtual_time_offset.InMillisecondsF());
}

void EmulationDispatcher::OnVirtualTimePaused(WTF::TimeDelta virtual_time_offset) {
  virtual_time_offset_ = virtual_time_offset.InMillisecondsF();
  GetClient()->OnVirtualTimePaused(virtual_time_offset.InMillisecondsF());
}

automation::EmulationClient* EmulationDispatcher::GetClient() const {
  return emulation_client_ptr_.get();
}

void EmulationDispatcher::FrameStartedLoading(blink::LocalFrame*, blink::FrameLoadType) {
  if (pending_virtual_time_policy_) {
    ApplyVirtualTimePolicy(*pending_virtual_time_policy_);
    pending_virtual_time_policy_ = base::nullopt;
  }
}

void EmulationDispatcher::OnWebFrameCreated(blink::WebLocalFrame* web_frame) {
  web_local_frame_ = static_cast<blink::WebLocalFrameImpl*>(blink::WebFrame::FromFrame(page_instance_->inspected_frames()->Root()));
  inspector_emulation_agent_ = new InspectorEmulationAgentImpl(this, web_local_frame_.Get());
  inspector_emulation_agent_->Init(
    page_instance_->probe_sink(), 
    page_instance_->inspector_backend_dispatcher(),
    page_instance_->state());
  page_instance_->probe_sink()->addInspectorEmulationAgent(inspector_emulation_agent_.Get());
  web_local_frame_->View()->Scheduler()->AddVirtualTimeObserver(this);

}

}