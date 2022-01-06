// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_APPLICATION_EMULATION_DISPATCHER_H_
#define MUMBA_APPLICATION_EMULATION_DISPATCHER_H_

#include "core/shared/common/mojom/automation.mojom.h"

#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "third_party/blink/renderer/core/loader/frame_loader_types.h"
#include "third_party/blink/renderer/platform/scheduler/public/page_scheduler.h"
#include "third_party/blink/renderer/platform/wtf/time.h"
#include "third_party/blink/renderer/platform/heap/heap.h"
#include "third_party/blink/renderer/platform/heap/heap_traits.h"
#include "third_party/blink/renderer/platform/graphics/color.h"
#include "third_party/blink/public/platform/web_color.h"

namespace blink {
class WebLocalFrameImpl;
class WebViewImpl;
class LocalFrame;
class WebLocalFrame;
}

namespace service_manager {
class InterfaceProvider;
}

namespace IPC {
class SyncChannel;
}

namespace application {
class PageInstance;
class InspectorEmulationAgentImpl;

class EmulationDispatcher : public automation::Emulation,
                            public blink::PageScheduler::VirtualTimeObserver {
public:

  static void Create(automation::EmulationRequest request, PageInstance* page_instance);

  EmulationDispatcher(automation::EmulationRequest request, PageInstance* page_instance);
  EmulationDispatcher(PageInstance* page_instance);
  ~EmulationDispatcher() override;

  void Init(IPC::SyncChannel* channel);
  void Bind(automation::EmulationAssociatedRequest request);

  void Register(int32_t application_id) override;
  void CanEmulate(CanEmulateCallback callback) override;
  void ClearDeviceMetricsOverride() override;
  void ClearGeolocationOverride() override;
  void ResetPageScaleFactor() override;
  void SetCPUThrottlingRate(int32_t rate) override;
  void SetDefaultBackgroundColorOverride(automation::RGBAPtr color) override;
  void SetDeviceMetricsOverride(int32_t width, int32_t height, float device_scale_factor, bool mobile, float scale, int32_t screen_width, int32_t screen_height, int32_t position_x, int32_t position_y, bool dont_set_visible_size, automation::ScreenOrientationPtr screen_orientation, automation::ViewportPtr viewport) override;
  void SetEmitTouchEventsForMouse(bool enabled, automation::TouchEventForMouseConfiguration configuration) override;
  void SetEmulatedMedia(const std::string& media) override;
  void SetGeolocationOverride(int64_t latitude, int64_t longitude, int64_t accuracy) override;
  void SetNavigatorOverrides(const std::string& platform) override;
  void SetPageScaleFactor(float page_scale_factor) override;
  void SetScriptExecutionDisabled(bool value) override;
  void SetTouchEmulationEnabled(bool enabled, int32_t max_touch_points) override;
  void SetVirtualTimePolicy(automation::VirtualTimePolicy policy, int32_t budget, int32_t max_virtual_time_task_starvation_count, bool wait_for_navigation, SetVirtualTimePolicyCallback callback) override;
  void SetVisibleSize(int32_t width, int32_t height) override;

  PageInstance* page_instance() const {
    return page_instance_;
  }

  automation::EmulationClient* GetClient() const;

  void OnWebFrameCreated(blink::WebLocalFrame* web_frame);
  
private:
  friend class InspectorEmulationAgentImpl;

  struct PendingVirtualTimePolicy {
    blink::PageScheduler::VirtualTimePolicy policy;
    base::Optional<double> virtual_time_budget_ms;
    base::Optional<int> max_virtual_time_task_starvation_count;
  };

  void ApplyVirtualTimePolicy(const PendingVirtualTimePolicy& new_policy);
  void VirtualTimeBudgetExpired();
  void OnVirtualTimeAdvanced(WTF::TimeDelta virtual_time_offset) override;
  void OnVirtualTimePaused(WTF::TimeDelta virtual_time_offset) override;
  void FrameStartedLoading(blink::LocalFrame*, blink::FrameLoadType);
  blink::WebViewImpl* GetWebViewImpl();

  int32_t application_id_;
  PageInstance* page_instance_;
  automation::VirtualTimePolicy virtual_time_policy_;
  mojo::AssociatedBinding<automation::Emulation> binding_;
  automation::EmulationClientAssociatedPtr emulation_client_ptr_;
  std::string emulated_media_;
  std::string navigator_platform_;
  base::Optional<blink::WebColor> default_background_color_override_rgba_;
  base::Optional<PendingVirtualTimePolicy> pending_virtual_time_policy_;
  blink::Member<blink::WebLocalFrameImpl> web_local_frame_;
  blink::Persistent<InspectorEmulationAgentImpl> inspector_emulation_agent_;
  WTF::TimeTicks virtual_time_base_ticks_;
  double virtual_time_offset_;
  base::Optional<double> virtual_time_budget_;
  base::Optional<int> virtual_time_task_starvation_count_;
  int max_touch_points_;
  bool script_execution_disabled_;
  bool touch_event_emulation_enabled_;
  
  DISALLOW_COPY_AND_ASSIGN(EmulationDispatcher); 
};

}

#endif