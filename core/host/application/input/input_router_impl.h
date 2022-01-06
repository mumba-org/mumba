// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_INPUT_INPUT_ROUTER_IMPL_H_
#define MUMBA_HOST_APPLICATION_INPUT_INPUT_ROUTER_IMPL_H_

#include <stdint.h>

#include <memory>
#include <queue>

#include "base/containers/flat_map.h"
#include "base/gtest_prod_util.h"
#include "base/macros.h"
#include "base/time/time.h"
#include "cc/input/touch_action.h"
#include "core/host/application/input/gesture_event_queue.h"
#include "core/host/application/input/input_router.h"
#include "core/host/application/input/input_router_client.h"
#include "core/host/application/input/mouse_wheel_event_queue.h"
#include "core/host/application/input/passthrough_touch_event_queue.h"
#include "core/host/application/input/touch_action_filter.h"
#include "core/host/application/input/touchpad_tap_suppression_controller.h"
#include "core/shared/common/input/input_event_stream_validator.h"
#include "core/shared/common/input/input_handler.mojom.h"
#include "core/shared/common/mojom/application.mojom.h"
#include "core/host/application/native_web_keyboard_event.h"
#include "core/host/host_thread.h"
#include "core/common/input_event_ack_source.h"
#include "mojo/public/cpp/bindings/binding.h"

namespace ui {
class LatencyInfo;
struct DidOverscrollParams;
}  // namespace ui

namespace host {

class InputDispositionHandler;

class MockApplicationWindowHost;

class CONTENT_EXPORT InputRouterImplClient : public InputRouterClient {
 public:
  virtual common::mojom::WindowInputHandler* GetWindowInputHandler() = 0;
  virtual void OnImeCancelComposition() = 0;
  virtual void OnImeCompositionRangeChanged(
      const gfx::Range& range,
      const std::vector<gfx::Rect>& bounds) = 0;
};

// A default implementation for browser input event routing.
class CONTENT_EXPORT InputRouterImpl
    : public InputRouter,
      public GestureEventQueueClient,
      public FlingControllerClient,
      public MouseWheelEventQueueClient,
      public PassthroughTouchEventQueueClient,
      public TouchpadTapSuppressionControllerClient,
      public common::mojom::WindowInputHandlerHost {
 public:
  InputRouterImpl(InputRouterImplClient* client,
                  InputDispositionHandler* disposition_handler,
                  const Config& config);
  ~InputRouterImpl() override;

  // InputRouter
  void SendMouseEvent(const common::MouseEventWithLatencyInfo& mouse_event) override;
  void SendWheelEvent(
      const common::MouseWheelEventWithLatencyInfo& wheel_event) override;
  void SendKeyboardEvent(
      const NativeWebKeyboardEventWithLatencyInfo& key_event) override;
  void SendGestureEvent(
      const common::GestureEventWithLatencyInfo& gesture_event) override;
  void SendTouchEvent(const common::TouchEventWithLatencyInfo& touch_event) override;
  void NotifySiteIsMobileOptimized(bool is_mobile_optimized) override;
  bool HasPendingEvents() const override;
  void SetDeviceScaleFactor(float device_scale_factor) override;
  void SetFrameTreeNodeId(int frame_tree_node_id) override;
  void SetForceEnableZoom(bool enabled) override;
  cc::TouchAction AllowedTouchAction() override;
  void BindHost(common::mojom::WindowInputHandlerHostRequest request,
                bool frame_handler) override;
  void ProgressFling(base::TimeTicks current_time) override;
  void StopFling() override;
  bool FlingCancellationIsDeferred() override;
  void DidStopFlingingOnBrowser() override;

  // InputHandlerHost impl
  void CancelTouchTimeout() override;
  void SetWhiteListedTouchAction(cc::TouchAction touch_action,
                                 uint32_t unique_touch_event_id,
                                 common::InputEventAckState state) override;
  void DidOverscroll(const ui::DidOverscrollParams& params) override;
  void DidStopFlinging() override;
  void ImeCancelComposition() override;
  void DidStartScrollingViewport() override;
  void ImeCompositionRangeChanged(
      const gfx::Range& range,
      const std::vector<gfx::Rect>& bounds) override;

  // IPC::Listener
  bool OnMessageReceived(const IPC::Message& message) override;

 private:
  friend class InputRouterImplTest;
  friend class MockApplicationWindowHost;

  void SendKeyboardEventOnIO(
      const NativeWebKeyboardEventWithLatencyInfo& key_event,
      common::mojom::WindowInputHandler::DispatchEventCallback callback);

  void SendMouseEventOnIO(const common::MouseEventWithLatencyInfo& mouse_event,
      common::mojom::WindowInputHandler::DispatchEventCallback callback);
  
  // Keeps track of last position of touch points and sets MovementXY for them.
  void SetMovementXYForTouchPoints(blink::WebTouchEvent* event);

  // TouchpadTapSuppressionControllerClient
  void SendMouseEventImmediately(
      const common::MouseEventWithLatencyInfo& mouse_event) override;

  void SendMouseEventImmediatelyImpl(
      const common::MouseEventWithLatencyInfo& mouse_event,
      common::mojom::WindowInputHandler::DispatchEventCallback callback);

  // PassthroughTouchEventQueueClient
  void SendTouchEventImmediately(
      const common::TouchEventWithLatencyInfo& touch_event) override;
  void OnTouchEventAck(const common::TouchEventWithLatencyInfo& event,
                       common::InputEventAckSource ack_source,
                       common::InputEventAckState ack_result) override;
  void OnFilteringTouchEvent(const blink::WebTouchEvent& touch_event) override;
  bool TouchscreenFlingInProgress() override;

  void SendTouchEventImmediatelyImpl(
      const common::TouchEventWithLatencyInfo& touch_event,
      common::mojom::WindowInputHandler::DispatchEventCallback callback);

  // GestureEventFilterClient
  void SendGestureEventImmediately(
      const common::GestureEventWithLatencyInfo& gesture_event) override;
  void OnGestureEventAck(const common::GestureEventWithLatencyInfo& event,
                         common::InputEventAckSource ack_source,
                         common::InputEventAckState ack_result) override;

  void SendGestureEventImmediatelyImpl(
      const common::GestureEventWithLatencyInfo& gesture_event,
      common::mojom::WindowInputHandler::DispatchEventCallback callback);

  // FlingControllerClient
  void SendGeneratedWheelEvent(
      const common::MouseWheelEventWithLatencyInfo& wheel_event) override;
  void SendGeneratedGestureScrollEvents(
      const common::GestureEventWithLatencyInfo& gesture_event) override;
  void SetNeedsBeginFrameForFlingProgress() override;

  // MouseWheelEventQueueClient
  void SendMouseWheelEventImmediately(
      const common::MouseWheelEventWithLatencyInfo& touch_event) override;
  void OnMouseWheelEventAck(const common::MouseWheelEventWithLatencyInfo& event,
                            common::InputEventAckSource ack_source,
                            common::InputEventAckState ack_result) override;
  void ForwardGestureEventWithLatencyInfo(
      const blink::WebGestureEvent& gesture_event,
      const ui::LatencyInfo& latency_info) override;

  void SendMouseWheelEventImmediatelyImpl(
      const common::MouseWheelEventWithLatencyInfo& touch_event,
      common::mojom::WindowInputHandler::DispatchEventCallback callback);

  bool FilterWebInputEvent(
    const blink::WebInputEvent& input_event,
    const ui::LatencyInfo& latency_info,
    common::InputEventAckState* filtered_state);

  void SendWebInputEvent(
      const blink::WebInputEvent& input_event,
      const ui::LatencyInfo& latency_info,
      common::mojom::WindowInputHandler::DispatchEventCallback callback);

  void KeyboardEventHandled(
      const NativeWebKeyboardEventWithLatencyInfo& event,
      common::InputEventAckSource source,
      const ui::LatencyInfo& latency,
      common::InputEventAckState state,
      const base::Optional<ui::DidOverscrollParams>& overscroll,
      const base::Optional<cc::TouchAction>& touch_action);
  void MouseEventHandled(
      const common::MouseEventWithLatencyInfo& event,
      common::InputEventAckSource source,
      const ui::LatencyInfo& latency,
      common::InputEventAckState state,
      const base::Optional<ui::DidOverscrollParams>& overscroll,
      const base::Optional<cc::TouchAction>& touch_action);
  void TouchEventHandled(
      const common::TouchEventWithLatencyInfo& touch_event,
      common::InputEventAckSource source,
      const ui::LatencyInfo& latency,
      common::InputEventAckState state,
      const base::Optional<ui::DidOverscrollParams>& overscroll,
      const base::Optional<cc::TouchAction>& touch_action);
  void GestureEventHandled(
      const common::GestureEventWithLatencyInfo& gesture_event,
      common::InputEventAckSource source,
      const ui::LatencyInfo& latency,
      common::InputEventAckState state,
      const base::Optional<ui::DidOverscrollParams>& overscroll,
      const base::Optional<cc::TouchAction>& touch_action);
  
  void MouseWheelEventHandled(
      const common::MouseWheelEventWithLatencyInfo& event,
      common::InputEventAckSource source,
      const ui::LatencyInfo& latency,
      common::InputEventAckState state,
      const base::Optional<ui::DidOverscrollParams>& overscroll,
      const base::Optional<cc::TouchAction>& touch_action);

  void KeyboardEventHandledImpl(
      const NativeWebKeyboardEventWithLatencyInfo& event,
      common::InputEventAckSource source,
      const ui::LatencyInfo& latency,
      common::InputEventAckState state,
      const base::Optional<ui::DidOverscrollParams>& overscroll,
      const base::Optional<cc::TouchAction>& touch_action);

   void MouseEventHandledImpl(
      const common::MouseEventWithLatencyInfo& event,
      common::InputEventAckSource source,
      const ui::LatencyInfo& latency,
      common::InputEventAckState state,
      const base::Optional<ui::DidOverscrollParams>& overscroll,
      const base::Optional<cc::TouchAction>& touch_action);

     void TouchEventHandledImpl(
      const common::TouchEventWithLatencyInfo& touch_event,
      common::InputEventAckSource source,
      const ui::LatencyInfo& latency,
      common::InputEventAckState state,
      const base::Optional<ui::DidOverscrollParams>& overscroll,
      const base::Optional<cc::TouchAction>& touch_action);
    
     void GestureEventHandledImpl(
      const common::GestureEventWithLatencyInfo& gesture_event,
      common::InputEventAckSource source,
      const ui::LatencyInfo& latency,
      common::InputEventAckState state,
      const base::Optional<ui::DidOverscrollParams>& overscroll,
      const base::Optional<cc::TouchAction>& touch_action);

    void MouseWheelEventHandledImpl(
      const common::MouseWheelEventWithLatencyInfo& event,
      common::InputEventAckSource source,
      const ui::LatencyInfo& latency,
      common::InputEventAckState state,
      const base::Optional<ui::DidOverscrollParams>& overscroll,
      const base::Optional<cc::TouchAction>& touch_action);

  // IPC message handlers
  void HasTouchEventHandlers(bool has_handlers) override;

  void OnSetTouchAction(cc::TouchAction touch_action);

  // Called when a touch timeout-affecting bit has changed, in turn toggling the
  // touch ack timeout feature of the |touch_event_queue_| as appropriate. Input
  // to that determination includes current view properties and the allowed
  // touch action. Note that this will only affect platforms that have a
  // non-zero touch timeout configuration.
  void UpdateTouchAckTimeoutEnabled();

  InputRouterImplClient* client_;
  InputDispositionHandler* disposition_handler_;
  int frame_tree_node_id_;

  // Whether there are any active flings in the renderer. As the fling
  // end notification is asynchronous, we use a count rather than a boolean
  // to avoid races in bookkeeping when starting a new fling.
  int active_renderer_fling_count_;

  // Whether the TouchScrollStarted event has been sent for the current
  // gesture scroll yet.
  bool touch_scroll_started_sent_;

  bool wheel_scroll_latching_enabled_;
  MouseWheelEventQueue wheel_event_queue_;
  PassthroughTouchEventQueue touch_event_queue_;
  GestureEventQueue gesture_event_queue_;
  TouchActionFilter touch_action_filter_;
  common::InputEventStreamValidator input_stream_validator_;
  common::InputEventStreamValidator output_stream_validator_;

  float device_scale_factor_;

  gfx::Vector2dF current_fling_velocity_;

  // Last touch position relative to screen. Used to compute movementX/Y.
  base::flat_map<int, gfx::Point> global_touch_position_;

  // The host binding associated with the widget input handler from
  // the widget.
  mojo::Binding<common::mojom::WindowInputHandlerHost> host_binding_;

  // The host binding associated with the widget input handler from
  // the frame.
  mojo::Binding<common::mojom::WindowInputHandlerHost> frame_host_binding_;

  base::WeakPtr<InputRouterImpl> weak_this_;
  base::WeakPtrFactory<InputRouterImpl> weak_ptr_factory_;
  std::unique_ptr<base::WeakPtrFactory<InputRouterImpl>, HostThread::DeleteOnIOThread> io_weak_ptr_factory_;

  DISALLOW_COPY_AND_ASSIGN(InputRouterImpl);
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_INPUT_INPUT_ROUTER_IMPL_H_
