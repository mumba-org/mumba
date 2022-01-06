// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/input/input_router_impl.h"

#include <math.h>

#include <utility>

#include "base/auto_reset.h"
#include "base/command_line.h"
#include "base/metrics/histogram_macros.h"
#include "base/strings/string_number_conversions.h"
#include "core/host/application/input/gesture_event_queue.h"
#include "core/host/application/input/input_disposition_handler.h"
#include "core/host/application/input/input_router_client.h"
#include "core/host/application/input/touchpad_tap_suppression_controller.h"
//#include "core/shared/common/content_constants_internal.h"
#include "core/shared/common/edit_command.h"
#include "core/shared/common/input/input_handler.mojom.h"
#include "core/shared/common/input/web_touch_event_traits.h"
#include "core/shared/common/input_messages.h"
//#include "core/shared/common/view_messages.h"
#include "core/host/notification_service.h"
#include "core/host/notification_types.h"
#include "core/host/host_thread.h"
#include "core/shared/common/content_features.h"
#include "core/shared/common/switches.h"
#include "core/shared/common/input_event_ack_state.h"
#include "ipc/ipc_sender.h"
#include "ui/events/blink/blink_event_util.h"
#include "ui/events/blink/web_input_event_traits.h"
#include "ui/events/event.h"
#include "ui/events/keycodes/keyboard_codes.h"

namespace host {

using base::Time;
using base::TimeDelta;
using base::TimeTicks;
using blink::WebGestureEvent;
using blink::WebInputEvent;
using blink::WebKeyboardEvent;
using blink::WebMouseEvent;
using blink::WebMouseWheelEvent;
using blink::WebTouchEvent;
using ui::WebInputEventTraits;

namespace {

bool WasHandled(common::InputEventAckState state) {
  switch (state) {
    case common::INPUT_EVENT_ACK_STATE_CONSUMED:
    case common::INPUT_EVENT_ACK_STATE_NO_CONSUMER_EXISTS:
    case common::INPUT_EVENT_ACK_STATE_UNKNOWN:
      return true;
    default:
      return false;
  }
}

ui::WebScopedInputEvent ScaleEvent(const WebInputEvent& event, double scale) {
  std::unique_ptr<blink::WebInputEvent> event_in_viewport =
      ui::ScaleWebInputEvent(event, scale);
  if (event_in_viewport)
    return ui::WebScopedInputEvent(event_in_viewport.release());
  return ui::WebInputEventTraits::Clone(event);
}

}  // namespace

InputRouterImpl::InputRouterImpl(InputRouterImplClient* client,
                                 InputDispositionHandler* disposition_handler,
                                 const Config& config)
    : client_(client),
      disposition_handler_(disposition_handler),
      frame_tree_node_id_(-1),
      active_renderer_fling_count_(0),
      touch_scroll_started_sent_(false),
      wheel_scroll_latching_enabled_(base::FeatureList::IsEnabled(
          features::kTouchpadAndWheelScrollLatching)),
      wheel_event_queue_(this, wheel_scroll_latching_enabled_),
      touch_event_queue_(this, config.touch_config),
      gesture_event_queue_(this, this, this, config.gesture_config),
      device_scale_factor_(1.f),
      host_binding_(this),
      frame_host_binding_(this),
      weak_ptr_factory_(this),
      // used for weak_ptrs that lives on IO_THREAD
      // need to be heap allocated so the desctruction goes on
      // the IO thread
      io_weak_ptr_factory_(new base::WeakPtrFactory<InputRouterImpl>(this)) {
  weak_this_ = weak_ptr_factory_.GetWeakPtr();

  DCHECK(client);
  DCHECK(disposition_handler);
  UpdateTouchAckTimeoutEnabled();
}

InputRouterImpl::~InputRouterImpl() {
  // HostThread::GetTaskRunnerForThread(HostThread::IO)->DeleteSoon(
  //   FROM_HERE,
  //   io_weak_ptr_factory_.release());
}

void InputRouterImpl::SendMouseEvent(
    const common::MouseEventWithLatencyInfo& mouse_event) {
  if (mouse_event.event.GetType() == WebInputEvent::kMouseDown &&
      gesture_event_queue_.GetTouchpadTapSuppressionController()
          ->ShouldDeferMouseDown(mouse_event))
    return;
  
  if (mouse_event.event.GetType() == WebInputEvent::kMouseUp &&
      gesture_event_queue_.GetTouchpadTapSuppressionController()
          ->ShouldSuppressMouseUp())
    return;

  common::InputEventAckState filtered_state;
  if (FilterWebInputEvent(mouse_event.event, mouse_event.latency, &filtered_state)) {
    if (filtered_state != common::INPUT_EVENT_ACK_STATE_UNKNOWN) {
      MouseEventHandled(mouse_event, common::InputEventAckSource::BROWSER, mouse_event.latency,
                        filtered_state, base::nullopt, base::nullopt);
    }
    return;
  }

  common::mojom::WindowInputHandler::DispatchEventCallback callback = base::BindOnce(
      &InputRouterImpl::MouseEventHandled, io_weak_ptr_factory_->GetWeakPtr(), mouse_event);//weak_this_, mouse_event);

  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE,
    base::BindOnce(&InputRouterImpl::SendMouseEventOnIO,
     //weak_this_,
     io_weak_ptr_factory_->GetWeakPtr(),
     mouse_event,
     base::Passed(std::move(callback))));
}

void InputRouterImpl::SendMouseEventOnIO(
    const common::MouseEventWithLatencyInfo& mouse_event,
    common::mojom::WindowInputHandler::DispatchEventCallback callback) {
      
  SendMouseEventImmediatelyImpl(mouse_event, std::move(callback));
}

void InputRouterImpl::SendWheelEvent(
    const common::MouseWheelEventWithLatencyInfo& wheel_event) {
  wheel_event_queue_.QueueEvent(wheel_event);
}

void InputRouterImpl::SendKeyboardEvent(
    const NativeWebKeyboardEventWithLatencyInfo& key_event) {
  gesture_event_queue_.StopFling();
  gesture_event_queue_.FlingHasBeenHalted();
  common::InputEventAckState filtered_state;
  if (FilterWebInputEvent(key_event.event, key_event.latency, &filtered_state)) {
    if (filtered_state != common::INPUT_EVENT_ACK_STATE_UNKNOWN) {
      KeyboardEventHandled(key_event, common::InputEventAckSource::BROWSER, key_event.latency,
                           filtered_state, base::nullopt, base::nullopt);
    }
    return;
  }
  common::mojom::WindowInputHandler::DispatchEventCallback callback = base::BindOnce(
      &InputRouterImpl::KeyboardEventHandled, io_weak_ptr_factory_->GetWeakPtr(), /* weak_this_ ,*/ key_event);
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE,
    base::BindOnce(&InputRouterImpl::SendKeyboardEventOnIO,
     //weak_this_,
     io_weak_ptr_factory_->GetWeakPtr(),
     key_event,
     base::Passed(std::move(callback))));
}

void InputRouterImpl::SendKeyboardEventOnIO(
    const NativeWebKeyboardEventWithLatencyInfo& key_event,
    common::mojom::WindowInputHandler::DispatchEventCallback callback) {
  SendWebInputEvent(key_event.event, key_event.latency, std::move(callback));
}

void InputRouterImpl::SendGestureEvent(
    const common::GestureEventWithLatencyInfo& original_gesture_event) {
  input_stream_validator_.Validate(original_gesture_event.event,
                                   FlingCancellationIsDeferred());

  common::GestureEventWithLatencyInfo gesture_event(original_gesture_event);

  if (touch_action_filter_.FilterGestureEvent(&gesture_event.event)) {
    disposition_handler_->OnGestureEventAck(gesture_event,
                                            common::InputEventAckSource::BROWSER,
                                            common::INPUT_EVENT_ACK_STATE_CONSUMED);
    return;
  }

  wheel_event_queue_.OnGestureScrollEvent(gesture_event);

  if (gesture_event.event.SourceDevice() ==
      blink::kWebGestureDeviceTouchscreen) {
    if (gesture_event.event.GetType() ==
        blink::WebInputEvent::kGestureScrollBegin) {
      touch_scroll_started_sent_ = false;
    } else if (!touch_scroll_started_sent_ &&
               gesture_event.event.GetType() ==
                   blink::WebInputEvent::kGestureScrollUpdate) {
      // A touch scroll hasn't really started until the first
      // GestureScrollUpdate event.  Eg. if the page consumes all touchmoves
      // then no scrolling really ever occurs (even though we still send
      // GestureScrollBegin).
      touch_scroll_started_sent_ = true;
      touch_event_queue_.PrependTouchScrollNotification();
    }
    touch_event_queue_.OnGestureScrollEvent(gesture_event);
  }

  if (!gesture_event_queue_.QueueEvent(gesture_event)) {
    disposition_handler_->OnGestureEventAck(gesture_event,
                                            common::InputEventAckSource::BROWSER,
                                            common::INPUT_EVENT_ACK_STATE_CONSUMED);
  }
}

void InputRouterImpl::SendTouchEvent(
    const common::TouchEventWithLatencyInfo& touch_event) {
  common::TouchEventWithLatencyInfo updatd_touch_event = touch_event;
  SetMovementXYForTouchPoints(&updatd_touch_event.event);
  input_stream_validator_.Validate(updatd_touch_event.event);
  touch_event_queue_.QueueEvent(updatd_touch_event);
}

void InputRouterImpl::NotifySiteIsMobileOptimized(bool is_mobile_optimized) {
  touch_event_queue_.SetIsMobileOptimizedSite(is_mobile_optimized);
}

bool InputRouterImpl::HasPendingEvents() const {
  return !touch_event_queue_.Empty() || !gesture_event_queue_.empty() ||
         wheel_event_queue_.has_pending() || active_renderer_fling_count_ > 0;
}

void InputRouterImpl::SetDeviceScaleFactor(float device_scale_factor) {
  device_scale_factor_ = device_scale_factor;
}

void InputRouterImpl::SetFrameTreeNodeId(int frame_tree_node_id) {
  frame_tree_node_id_ = frame_tree_node_id;
}

void InputRouterImpl::SetForceEnableZoom(bool enabled) {
  touch_action_filter_.SetForceEnableZoom(enabled);
}

cc::TouchAction InputRouterImpl::AllowedTouchAction() {
  return touch_action_filter_.allowed_touch_action();
}

void InputRouterImpl::BindHost(common::mojom::WindowInputHandlerHostRequest request,
                               bool frame_handler) {
  if (frame_handler) {
    frame_host_binding_.Close();
    frame_host_binding_.Bind(std::move(request));
  } else {
    host_binding_.Close();
    host_binding_.Bind(std::move(request));
  }
}

void InputRouterImpl::ProgressFling(base::TimeTicks current_time) {
  current_fling_velocity_ = gesture_event_queue_.ProgressFling(current_time);
}

void InputRouterImpl::StopFling() {
  gesture_event_queue_.StopFling();
}

bool InputRouterImpl::FlingCancellationIsDeferred() {
  return gesture_event_queue_.FlingCancellationIsDeferred();
}

void InputRouterImpl::DidStopFlingingOnBrowser() {
  current_fling_velocity_ = gfx::Vector2dF();
  client_->DidStopFlinging();
}

void InputRouterImpl::CancelTouchTimeout() {
  touch_event_queue_.SetAckTimeoutEnabled(false);
}

void InputRouterImpl::SetWhiteListedTouchAction(cc::TouchAction touch_action,
                                                uint32_t unique_touch_event_id,
                                                common::InputEventAckState state) {
  // TODO(hayleyferr): Catch the cases that we have filtered out sending the
  // touchstart.

  touch_action_filter_.OnSetWhiteListedTouchAction(touch_action);
  client_->OnSetWhiteListedTouchAction(touch_action);
}

void InputRouterImpl::DidOverscroll(const ui::DidOverscrollParams& params) {
  // Touchpad and Touchscreen flings are handled on the browser side.
  ui::DidOverscrollParams fling_updated_params = params;
  fling_updated_params.current_fling_velocity = current_fling_velocity_;
  client_->DidOverscroll(fling_updated_params);
}

void InputRouterImpl::DidStopFlinging() {
  DCHECK_GT(active_renderer_fling_count_, 0);
  // Note that we're only guaranteed to get a fling end notification from the
  // renderer, not from any other consumers. Consequently, the GestureEventQueue
  // cannot use this bookkeeping for logic like tap suppression.
  --active_renderer_fling_count_;
  client_->DidStopFlinging();
}

void InputRouterImpl::DidStartScrollingViewport() {
  client_->DidStartScrollingViewport();
}

void InputRouterImpl::ImeCancelComposition() {
  client_->OnImeCancelComposition();
}

void InputRouterImpl::ImeCompositionRangeChanged(
    const gfx::Range& range,
    const std::vector<gfx::Rect>& bounds) {
  client_->OnImeCompositionRangeChanged(range, bounds);
}

bool InputRouterImpl::OnMessageReceived(const IPC::Message& message) {
  // TODO(dtapuska): Move these to mojo
  // bool handled = true;
  // IPC_BEGIN_MESSAGE_MAP(InputRouterImpl, message)
  //   IPC_MESSAGE_HANDLER(ViewHostMsg_HasTouchEventHandlers,
  //                       OnHasTouchEventHandlers)
  //   IPC_MESSAGE_UNHANDLED(handled = false)
  // IPC_END_MESSAGE_MAP()

  // return handled;
  return false;
}

void InputRouterImpl::SetMovementXYForTouchPoints(blink::WebTouchEvent* event) {
  for (size_t i = 0; i < event->touches_length; ++i) {
    blink::WebTouchPoint* touch_point = &event->touches[i];
    if (touch_point->state == blink::WebTouchPoint::kStateMoved) {
      const gfx::Point& last_position = global_touch_position_[touch_point->id];
      touch_point->movement_x =
          touch_point->PositionInScreen().x - last_position.x();
      touch_point->movement_y =
          touch_point->PositionInScreen().y - last_position.y();
      global_touch_position_[touch_point->id].SetPoint(
          touch_point->PositionInScreen().x, touch_point->PositionInScreen().y);
    } else {
      touch_point->movement_x = 0;
      touch_point->movement_y = 0;
      if (touch_point->state == blink::WebTouchPoint::kStateReleased ||
          touch_point->state == blink::WebTouchPoint::kStateCancelled) {
        global_touch_position_.erase(touch_point->id);
      } else if (touch_point->state == blink::WebTouchPoint::kStatePressed) {
        DCHECK(global_touch_position_.find(touch_point->id) ==
               global_touch_position_.end());
        global_touch_position_[touch_point->id] =
            gfx::Point(touch_point->PositionInScreen().x,
                       touch_point->PositionInScreen().y);
      }
    }
  }
}

// Forwards MouseEvent without passing it through
// TouchpadTapSuppressionController.
void InputRouterImpl::SendMouseEventImmediately(
    const common::MouseEventWithLatencyInfo& mouse_event) {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));
  common::mojom::WindowInputHandler::DispatchEventCallback callback = base::BindOnce(
      &InputRouterImpl::MouseEventHandled, io_weak_ptr_factory_->GetWeakPtr(), /* weak_this_ ,*/ mouse_event);
  if (HostThread::CurrentlyOn(HostThread::IO)) {
    SendMouseEventImmediatelyImpl(mouse_event, std::move(callback));
  } else {
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(&InputRouterImpl::SendMouseEventImmediatelyImpl,
        //weak_this_,
        io_weak_ptr_factory_->GetWeakPtr(),
        mouse_event,
        base::Passed(std::move(callback))));
  }
}

void InputRouterImpl::SendMouseEventImmediatelyImpl(
    const common::MouseEventWithLatencyInfo& mouse_event,
    common::mojom::WindowInputHandler::DispatchEventCallback callback) {
  DCHECK(HostThread::CurrentlyOn(HostThread::IO));
  SendWebInputEvent(mouse_event.event, mouse_event.latency,
                    std::move(callback));
}

void InputRouterImpl::SendTouchEventImmediately(const common::TouchEventWithLatencyInfo& touch_event) {
  common::InputEventAckState filtered_state;
  if (FilterWebInputEvent(touch_event.event, touch_event.latency, &filtered_state)) {
    if (filtered_state != common::INPUT_EVENT_ACK_STATE_UNKNOWN) {
      TouchEventHandled(touch_event, common::InputEventAckSource::BROWSER, touch_event.latency,
                        filtered_state, base::nullopt, base::nullopt);
    }
    return;
  }
  
  common::mojom::WindowInputHandler::DispatchEventCallback callback = base::BindOnce(
      &InputRouterImpl::TouchEventHandled, io_weak_ptr_factory_->GetWeakPtr(), /* weak_this_ ,*/ touch_event);

  if (HostThread::CurrentlyOn(HostThread::IO)) {
    SendTouchEventImmediatelyImpl(touch_event, std::move(callback));
  } else {
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(&InputRouterImpl::SendTouchEventImmediatelyImpl,
        //weak_this_,
        io_weak_ptr_factory_->GetWeakPtr(),
        touch_event,
        base::Passed(std::move(callback))));
  }
}

void InputRouterImpl::SendTouchEventImmediatelyImpl(
    const common::TouchEventWithLatencyInfo& touch_event,
    common::mojom::WindowInputHandler::DispatchEventCallback callback) {
  DCHECK(HostThread::CurrentlyOn(HostThread::IO));
  SendWebInputEvent(touch_event.event, touch_event.latency, std::move(callback));
}

void InputRouterImpl::OnTouchEventAck(const common::TouchEventWithLatencyInfo& event,
                                      common::InputEventAckSource ack_source,
                                      common::InputEventAckState ack_result) {
  // Touchstart events sent to the renderer indicate a new touch sequence, but
  // in some cases we may filter out sending the touchstart - catch those here.
  if (common::WebTouchEventTraits::IsTouchSequenceStart(event.event) &&
      ack_result == common::INPUT_EVENT_ACK_STATE_NO_CONSUMER_EXISTS) {
    touch_action_filter_.ResetTouchAction();
    UpdateTouchAckTimeoutEnabled();
  }
  disposition_handler_->OnTouchEventAck(event, ack_source, ack_result);

  // Reset the touch action at the end of a touch-action sequence.
  if (common::WebTouchEventTraits::IsTouchSequenceEnd(event.event)) {
    touch_action_filter_.ReportAndResetTouchAction();
    UpdateTouchAckTimeoutEnabled();
  }
}

void InputRouterImpl::OnFilteringTouchEvent(const WebTouchEvent& touch_event) {
  // The event stream given to the renderer is not guaranteed to be
  // valid based on the current TouchEventStreamValidator rules. This event will
  // never be given to the renderer, but in order to ensure that the event
  // stream |output_stream_validator_| sees is valid, we give events which are
  // filtered out to the validator. crbug.com/589111 proposes adding an
  // additional validator for the events which are actually sent to the
  // renderer.
  output_stream_validator_.Validate(touch_event);
}

bool InputRouterImpl::TouchscreenFlingInProgress() {
  return gesture_event_queue_.TouchscreenFlingInProgress();
}

void InputRouterImpl::SendGestureEventImmediately(
    const common::GestureEventWithLatencyInfo& gesture_event) {
  common::InputEventAckState filtered_state;    
  if (FilterWebInputEvent(gesture_event.event, gesture_event.latency, &filtered_state)) {
    if (filtered_state != common::INPUT_EVENT_ACK_STATE_UNKNOWN) {
      GestureEventHandled(gesture_event, common::InputEventAckSource::BROWSER, gesture_event.latency,
                          filtered_state, base::nullopt, base::nullopt);
    }
    return;
  }
  common::mojom::WindowInputHandler::DispatchEventCallback callback = base::BindOnce(
       &InputRouterImpl::GestureEventHandled, io_weak_ptr_factory_->GetWeakPtr(), /* weak_this_ ,*/ gesture_event);

  if (HostThread::CurrentlyOn(HostThread::IO)) {
    SendGestureEventImmediatelyImpl(gesture_event, std::move(callback));
  } else {
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(&InputRouterImpl::SendGestureEventImmediatelyImpl,
        //weak_this_,
        io_weak_ptr_factory_->GetWeakPtr(),
        gesture_event,
        base::Passed(std::move(callback))));
  }
}

void InputRouterImpl::SendGestureEventImmediatelyImpl(
    const common::GestureEventWithLatencyInfo& gesture_event,
    common::mojom::WindowInputHandler::DispatchEventCallback callback) {
  DCHECK(HostThread::CurrentlyOn(HostThread::IO));
  SendWebInputEvent(gesture_event.event, gesture_event.latency,
                    std::move(callback));
}

void InputRouterImpl::OnGestureEventAck(
    const common::GestureEventWithLatencyInfo& event,
    common::InputEventAckSource ack_source,
    common::InputEventAckState ack_result) {
  touch_event_queue_.OnGestureEventAck(event, ack_result);
  disposition_handler_->OnGestureEventAck(event, ack_source, ack_result);
}

void InputRouterImpl::SendGeneratedWheelEvent(
    const common::MouseWheelEventWithLatencyInfo& wheel_event) {
  client_->ForwardWheelEventWithLatencyInfo(wheel_event.event,
                                            wheel_event.latency);
}

void InputRouterImpl::SendGeneratedGestureScrollEvents(
    const common::GestureEventWithLatencyInfo& gesture_event) {
  client_->ForwardGestureEventWithLatencyInfo(gesture_event.event,
                                              gesture_event.latency);
}

void InputRouterImpl::SetNeedsBeginFrameForFlingProgress() {
  client_->SetNeedsBeginFrameForFlingProgress();
}

void InputRouterImpl::SendMouseWheelEventImmediately(
    const common::MouseWheelEventWithLatencyInfo& wheel_event) {
  common::InputEventAckState filtered_state;
  if (FilterWebInputEvent(wheel_event.event, wheel_event.latency, &filtered_state)) {
    if (filtered_state != common::INPUT_EVENT_ACK_STATE_UNKNOWN) {
      MouseWheelEventHandled(wheel_event, common::InputEventAckSource::BROWSER, wheel_event.latency,
                             filtered_state, base::nullopt, base::nullopt);
    }
    return;
  }
  common::mojom::WindowInputHandler::DispatchEventCallback callback = base::BindOnce(
      &InputRouterImpl::MouseWheelEventHandled, io_weak_ptr_factory_->GetWeakPtr(), /* weak_this_ ,*/ wheel_event);
  if (HostThread::CurrentlyOn(HostThread::IO)) {
    SendMouseWheelEventImmediatelyImpl(wheel_event, std::move(callback));
  } else {
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(&InputRouterImpl::SendMouseWheelEventImmediatelyImpl,
        //weak_this_,
        io_weak_ptr_factory_->GetWeakPtr(),
        wheel_event, 
        base::Passed(std::move(callback))));
  }
}

void InputRouterImpl::SendMouseWheelEventImmediatelyImpl(
    const common::MouseWheelEventWithLatencyInfo& wheel_event,
    common::mojom::WindowInputHandler::DispatchEventCallback callback) {
  DCHECK(HostThread::CurrentlyOn(HostThread::IO));
  SendWebInputEvent(wheel_event.event, wheel_event.latency, std::move(callback));
}

void InputRouterImpl::OnMouseWheelEventAck(
    const common::MouseWheelEventWithLatencyInfo& event,
    common::InputEventAckSource ack_source,
    common::InputEventAckState ack_result) {
  disposition_handler_->OnWheelEventAck(event, ack_source, ack_result);
}

void InputRouterImpl::ForwardGestureEventWithLatencyInfo(
    const blink::WebGestureEvent& event,
    const ui::LatencyInfo& latency_info) {
  client_->ForwardGestureEventWithLatencyInfo(event, latency_info);
}

bool InputRouterImpl::FilterWebInputEvent(
    const WebInputEvent& input_event,
    const ui::LatencyInfo& latency_info,
    common::InputEventAckState* filtered_state) {
  TRACE_EVENT1("input", "InputRouterImpl::FilterWebInputEvent", "type",
               WebInputEvent::GetName(input_event.GetType()));
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));
  output_stream_validator_.Validate(input_event);
  *filtered_state =
      client_->FilterInputEvent(input_event, latency_info);
  if (WasHandled(*filtered_state)) {
    TRACE_EVENT_INSTANT0("input", "InputEventFiltered",
                         TRACE_EVENT_SCOPE_THREAD);
    return true;
  }
  return false;
}

void InputRouterImpl::SendWebInputEvent(
    const WebInputEvent& input_event,
    const ui::LatencyInfo& latency_info,
    common::mojom::WindowInputHandler::DispatchEventCallback callback) {
  TRACE_EVENT1("input", "InputRouterImpl::SendWebInputEvent", "type",
               WebInputEvent::GetName(input_event.GetType()));
  TRACE_EVENT_WITH_FLOW2(
      "input,benchmark,devtools.timeline", "LatencyInfo.Flow",
      TRACE_ID_DONT_MANGLE(latency_info.trace_id()),
      TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT, "step",
      "SendInputEventUI", "frameTreeNodeId", frame_tree_node_id_);
  DCHECK(HostThread::CurrentlyOn(HostThread::IO));
  std::unique_ptr<common::InputEvent> event = std::make_unique<common::InputEvent>(
      ScaleEvent(input_event, device_scale_factor_), latency_info);
  if (WebInputEventTraits::ShouldBlockEventStream(
          input_event, wheel_scroll_latching_enabled_)) {
    TRACE_EVENT_INSTANT0("input", "InputEventSentBlocking",
                         TRACE_EVENT_SCOPE_THREAD);
    client_->IncrementInFlightEventCount();
    client_->GetWindowInputHandler()->DispatchEvent(std::move(event), std::move(callback));
  } else {
    TRACE_EVENT_INSTANT0("input", "InputEventSentNonBlocking",
                         TRACE_EVENT_SCOPE_THREAD);
    client_->GetWindowInputHandler()->DispatchNonBlockingEvent(std::move(event));
    std::move(callback).Run(common::InputEventAckSource::BROWSER, latency_info,
                            common::INPUT_EVENT_ACK_STATE_IGNORED, base::nullopt,
                            base::nullopt);
  }
}

void InputRouterImpl::KeyboardEventHandled(
    const NativeWebKeyboardEventWithLatencyInfo& event,
    common::InputEventAckSource source,
    const ui::LatencyInfo& latency,
    common::InputEventAckState state,
    const base::Optional<ui::DidOverscrollParams>& overscroll,
    const base::Optional<cc::TouchAction>& touch_action) {
  if (!HostThread::CurrentlyOn(HostThread::UI)) {
    HostThread::PostTask(
      HostThread::UI,
      FROM_HERE, 
      base::BindOnce(&InputRouterImpl::KeyboardEventHandledImpl,
        //io_weak_ptr_factory_->GetWeakPtr(),
        base::Unretained(this),
        event,
        source,
        latency,
        state,
        overscroll,
        touch_action));
  } else {
    KeyboardEventHandledImpl(event, source, latency, state, overscroll, touch_action);
  }
}

void InputRouterImpl::KeyboardEventHandledImpl(
    const NativeWebKeyboardEventWithLatencyInfo& event,
    common::InputEventAckSource source,
    const ui::LatencyInfo& latency,
    common::InputEventAckState state,
    const base::Optional<ui::DidOverscrollParams>& overscroll,
    const base::Optional<cc::TouchAction>& touch_action) {
  TRACE_EVENT2("input", "InputRouterImpl::KeboardEventHandled", "type",
               WebInputEvent::GetName(event.event.GetType()), "ack",
               common::InputEventAckStateToString(state));

  if (source != common::InputEventAckSource::BROWSER)
    client_->DecrementInFlightEventCount(source);
  event.latency.AddNewLatencyFrom(latency);
  disposition_handler_->OnKeyboardEventAck(event, source, state);

  // WARNING: This InputRouterImpl can be deallocated at this point
  // (i.e.  in the case of Ctrl+W, where the call to
  // HandleKeyboardEvent destroys this InputRouterImpl).
  // TODO(jdduke): crbug.com/274029 - Make ack-triggered shutdown async.
}

void InputRouterImpl::MouseEventHandled(
    const common::MouseEventWithLatencyInfo& event,
    common::InputEventAckSource source,
    const ui::LatencyInfo& latency,
    common::InputEventAckState state,
    const base::Optional<ui::DidOverscrollParams>& overscroll,
    const base::Optional<cc::TouchAction>& touch_action) {
  if (!HostThread::CurrentlyOn(HostThread::UI)) {
    HostThread::PostTask(
      HostThread::UI,
      FROM_HERE, 
      base::BindOnce(&InputRouterImpl::MouseEventHandledImpl,
        //io_weak_ptr_factory_->GetWeakPtr(),
        base::Unretained(this),
        event,
        source,
        latency,
        state,
        overscroll,
        touch_action));
  } else {
    MouseEventHandledImpl(event, source, latency, state, overscroll, touch_action);
  }
}

void InputRouterImpl::MouseEventHandledImpl(
    const common::MouseEventWithLatencyInfo& event,
    common::InputEventAckSource source,
    const ui::LatencyInfo& latency,
    common::InputEventAckState state,
    const base::Optional<ui::DidOverscrollParams>& overscroll,
    const base::Optional<cc::TouchAction>& touch_action) {
  TRACE_EVENT2("input", "InputRouterImpl::MouseEventHandled", "type",
               WebInputEvent::GetName(event.event.GetType()), "ack",
               common::InputEventAckStateToString(state));

  if (source != common::InputEventAckSource::BROWSER)
    client_->DecrementInFlightEventCount(source);
  event.latency.AddNewLatencyFrom(latency);
  disposition_handler_->OnMouseEventAck(event, source, state);
}

void InputRouterImpl::TouchEventHandled(
    const common::TouchEventWithLatencyInfo& touch_event,
    common::InputEventAckSource source,
    const ui::LatencyInfo& latency,
    common::InputEventAckState state,
    const base::Optional<ui::DidOverscrollParams>& overscroll,
    const base::Optional<cc::TouchAction>& touch_action) {
  if (!HostThread::CurrentlyOn(HostThread::UI)) {
    HostThread::PostTask(
      HostThread::UI,
      FROM_HERE, 
      base::BindOnce(&InputRouterImpl::TouchEventHandledImpl,
        //io_weak_ptr_factory_->GetWeakPtr(),
        base::Unretained(this),
        touch_event,
        source,
        latency,
        state,
        overscroll,
        touch_action));
  } else {
    TouchEventHandledImpl(touch_event, source, latency, state, overscroll, touch_action);
  }
}

void InputRouterImpl::TouchEventHandledImpl(
    const common::TouchEventWithLatencyInfo& touch_event,
    common::InputEventAckSource source,
    const ui::LatencyInfo& latency,
    common::InputEventAckState state,
    const base::Optional<ui::DidOverscrollParams>& overscroll,
    const base::Optional<cc::TouchAction>& touch_action) {
  TRACE_EVENT2("input", "InputRouterImpl::TouchEventHandled", "type",
               WebInputEvent::GetName(touch_event.event.GetType()), "ack",
               common::InputEventAckStateToString(state));
  if (source != common::InputEventAckSource::BROWSER)
    client_->DecrementInFlightEventCount(source);
  touch_event.latency.AddNewLatencyFrom(latency);

  // The SetTouchAction IPC occurs on a different channel so always
  // send it in the input event ack to ensure it is available at the
  // time the ACK is handled.
  if (touch_action.has_value())
    OnSetTouchAction(touch_action.value());

  // |touch_event_queue_| will forward to OnTouchEventAck when appropriate.
  touch_event_queue_.ProcessTouchAck(source, state, latency,
                                     touch_event.event.unique_touch_event_id);
}

void InputRouterImpl::GestureEventHandled(
    const common::GestureEventWithLatencyInfo& gesture_event,
    common::InputEventAckSource source,
    const ui::LatencyInfo& latency,
    common::InputEventAckState state,
    const base::Optional<ui::DidOverscrollParams>& overscroll,
    const base::Optional<cc::TouchAction>& touch_action) {
  if (!HostThread::CurrentlyOn(HostThread::UI)) {
    HostThread::PostTask(
      HostThread::UI,
      FROM_HERE, 
      base::BindOnce(&InputRouterImpl::GestureEventHandledImpl,
        //io_weak_ptr_factory_->GetWeakPtr(),
        base::Unretained(this),
        gesture_event,
        source,
        latency,
        state,
        overscroll,
        touch_action));
  } else {
    GestureEventHandledImpl(gesture_event, source, latency, state, overscroll, touch_action);
  }
}

void InputRouterImpl::GestureEventHandledImpl(
    const common::GestureEventWithLatencyInfo& gesture_event,
    common::InputEventAckSource source,
    const ui::LatencyInfo& latency,
    common::InputEventAckState state,
    const base::Optional<ui::DidOverscrollParams>& overscroll,
    const base::Optional<cc::TouchAction>& touch_action) {
  TRACE_EVENT2("input", "InputRouterImpl::GestureEventHandled", "type",
               WebInputEvent::GetName(gesture_event.event.GetType()), "ack",
               common::InputEventAckStateToString(state));
  if (source != common::InputEventAckSource::BROWSER)
    client_->DecrementInFlightEventCount(source);
  if (gesture_event.event.GetType() ==
          blink::WebInputEvent::kGestureFlingStart &&
      state == common::INPUT_EVENT_ACK_STATE_CONSUMED) {
    ++active_renderer_fling_count_;
  }

  if (overscroll) {
    DCHECK_EQ(WebInputEvent::kGestureScrollUpdate,
              gesture_event.event.GetType());
    DidOverscroll(overscroll.value());
  }

  // |gesture_event_queue_| will forward to OnGestureEventAck when appropriate.
  gesture_event_queue_.ProcessGestureAck(
      source, state, gesture_event.event.GetType(), latency);
}

void InputRouterImpl::MouseWheelEventHandled(
    const common::MouseWheelEventWithLatencyInfo& event,
    common::InputEventAckSource source,
    const ui::LatencyInfo& latency,
    common::InputEventAckState state,
    const base::Optional<ui::DidOverscrollParams>& overscroll,
    const base::Optional<cc::TouchAction>& touch_action) {
  if (!HostThread::CurrentlyOn(HostThread::UI)) {
    HostThread::PostTask(
      HostThread::UI,
      FROM_HERE, 
      base::BindOnce(&InputRouterImpl::MouseWheelEventHandledImpl,
        //io_weak_ptr_factory_->GetWeakPtr(),
        base::Unretained(this),
        event,
        source,
        latency,
        state,
        overscroll,
        touch_action));
  } else {
    MouseWheelEventHandledImpl(event, source, latency, state, overscroll, touch_action);
  }    
}

void InputRouterImpl::MouseWheelEventHandledImpl(
    const common::MouseWheelEventWithLatencyInfo& event,
    common::InputEventAckSource source,
    const ui::LatencyInfo& latency,
    common::InputEventAckState state,
    const base::Optional<ui::DidOverscrollParams>& overscroll,
    const base::Optional<cc::TouchAction>& touch_action) {
  
  TRACE_EVENT2("input", "InputRouterImpl::MouseWheelEventHandled", "type",
               WebInputEvent::GetName(event.event.GetType()), "ack",
               common::InputEventAckStateToString(state));
  if (source != common::InputEventAckSource::BROWSER)
    client_->DecrementInFlightEventCount(source);
  event.latency.AddNewLatencyFrom(latency);

  if (overscroll)
    DidOverscroll(overscroll.value());

  wheel_event_queue_.ProcessMouseWheelAck(source, state, event.latency);
}

void InputRouterImpl::HasTouchEventHandlers(bool has_handlers) {
  TRACE_EVENT1("input", "InputRouterImpl::OnHasTouchEventHandlers",
               "has_handlers", has_handlers);

  // Lack of a touch handler indicates that the page either has no touch-action
  // modifiers or that all its touch-action modifiers are auto. Resetting the
  // touch-action here allows forwarding of subsequent gestures even if the
  // underlying touches never reach the router.
  if (!has_handlers)
    touch_action_filter_.ResetTouchAction();

  touch_event_queue_.OnHasTouchEventHandlers(has_handlers);
  client_->OnHasTouchEventHandlers(has_handlers);
}

void InputRouterImpl::OnSetTouchAction(cc::TouchAction touch_action) {
  TRACE_EVENT1("input", "InputRouterImpl::OnSetTouchAction", "action",
               touch_action);

  // It is possible we get a touch action for a touch start that is no longer
  // in the queue. eg. Events that have fired the Touch ACK timeout.
  if (!touch_event_queue_.IsPendingAckTouchStart())
    return;

  touch_action_filter_.OnSetTouchAction(touch_action);

  // kTouchActionNone should disable the touch ack timeout.
  UpdateTouchAckTimeoutEnabled();
}

void InputRouterImpl::UpdateTouchAckTimeoutEnabled() {
  // kTouchActionNone will prevent scrolling, in which case the timeout serves
  // little purpose. It's also a strong signal that touch handling is critical
  // to page functionality, so the timeout could do more harm than good.
  const bool touch_ack_timeout_enabled =
      touch_action_filter_.allowed_touch_action() != cc::kTouchActionNone;
  touch_event_queue_.SetAckTimeoutEnabled(touch_ack_timeout_enabled);
}

}  // namespace host
