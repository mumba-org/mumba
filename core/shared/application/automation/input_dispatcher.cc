// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/input_dispatcher.h"

#include "services/service_manager/public/cpp/interface_provider.h"
#include "core/shared/application/automation/page_instance.h"
#include "services/service_manager/public/cpp/interface_provider.h"
#include "ui/events/keycodes/dom/keycode_converter.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/platform/web_data.h"
#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/script_source_code.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_inspector_overlay_host.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/static_node_list.h"
#include "third_party/blink/renderer/core/events/web_input_event_conversion.h"
#include "third_party/blink/renderer/core/exported/web_view_impl.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/inspector/identifiers_factory.h"
#include "third_party/blink/renderer/core/inspector/inspected_frames.h"
#include "third_party/blink/renderer/core/inspector/inspector_dom_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_overlay_host.h"
#include "third_party/blink/renderer/core/inspector/inspector_overlay_agent.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/loader/frame_load_request.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/page_overlay.h"
#include "third_party/blink/renderer/platform/bindings/script_forbidden_scope.h"
#include "third_party/blink/renderer/platform/graphics/color.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/paint/cull_rect.h"
#include "third_party/blink/renderer/platform/wtf/auto_reset.h"
#include "v8/include/v8.h"
#include "ipc/ipc_sync_channel.h"

namespace application {

namespace {

const size_t kTextLengthCap = 4;

blink::WebInputEvent::Type FromKeyEvent(automation::KeyEventType type) {
  switch (type) {
    case automation::KeyEventType::kKEY_EVENT_TYPE_KEY_DOWN:
      return blink::WebInputEvent::Type::kRawKeyDown;
    case automation::KeyEventType::kKEY_EVENT_TYPE_RAW_KEY_DOWN:
      return blink::WebInputEvent::Type::kKeyDown;
    case automation::KeyEventType::kKEY_EVENT_TYPE_KEY_UP:  
      return blink::WebInputEvent::Type::kKeyUp;
    case automation::KeyEventType::kKEY_EVENT_TYPE_CHAR:
      return blink::WebInputEvent::Type::kChar;
  }
  return blink::WebInputEvent::Type::kRawKeyDown;
}

blink::WebInputEvent::Type FromMouseEvent(automation::MouseEventType type) {
  switch (type) {
    case automation::MouseEventType::kMOUSE_EVENT_TYPE_MOUSE_PRESSED:
      return blink::WebInputEvent::Type::kMouseDown;
    case automation::MouseEventType::kMOUSE_EVENT_TYPE_MOUSE_RELEASED:
      return blink::WebInputEvent::Type::kMouseUp;
    case automation::MouseEventType::kMOUSE_EVENT_TYPE_MOUSE_MOVED:
      return blink::WebInputEvent::Type::kMouseMove;
    case automation::MouseEventType::kMOUSE_EVENT_TYPE_MOUSE_WHEEL:
      return blink::WebInputEvent::Type::kMouseWheel;
  }
  return blink::WebInputEvent::Type::kMouseMove;
}

blink::WebInputEvent::Type FromTouchEvent(automation::TouchEventType type) {
  switch (type) {
    case automation::TouchEventType::kTOUCH_EVENT_TYPE_TOUCH_START:
      return blink::WebInputEvent::Type::kTouchStart;
    case automation::TouchEventType::kTOUCH_EVENT_TYPE_TOUCH_END:
      return blink::WebInputEvent::Type::kTouchEnd;
    case automation::TouchEventType::kTOUCH_EVENT_TYPE_TOUCH_MOVE:
      return blink::WebInputEvent::Type::kTouchMove;
    case automation::TouchEventType::kTOUCH_EVENT_TYPE_TOUCH_CANCEL:
      return blink::WebInputEvent::Type::kTouchCancel;
  }
  return blink::WebInputEvent::Type::kTouchCancel;
}

blink::WebInputEvent::Type FromMouseEventToTouch(automation::MouseEventType type) {
  switch (type) {
    case automation::MouseEventType::kMOUSE_EVENT_TYPE_MOUSE_PRESSED:
      return blink::WebInputEvent::Type::kTouchStart;
    case automation::MouseEventType::kMOUSE_EVENT_TYPE_MOUSE_RELEASED:
      return blink::WebInputEvent::Type::kTouchEnd;
    case automation::MouseEventType::kMOUSE_EVENT_TYPE_MOUSE_MOVED:
      return blink::WebInputEvent::Type::kTouchMove;
    case automation::MouseEventType::kMOUSE_EVENT_TYPE_MOUSE_WHEEL:
      return blink::WebInputEvent::Type::kTouchEnd;    
  }
  return blink::WebInputEvent::Type::kTouchEnd;
}

blink::WebPointerProperties::Button FromMouseButton(automation::MouseButton button) {
  switch (button) {
    case automation::MouseButton::kMOUSE_BUTTON_NONE:
      return blink::WebPointerProperties::Button::kNoButton;
    case automation::MouseButton::kMOUSE_BUTTON_LEFT:
      return blink::WebPointerProperties::Button::kLeft;
    case automation::MouseButton::kMOUSE_BUTTON_MIDDLE:
      return blink::WebPointerProperties::Button::kMiddle;
    case automation::MouseButton::kMOUSE_BUTTON_RIGHT:
      return blink::WebPointerProperties::Button::kRight;
  }
  return blink::WebPointerProperties::Button::kNoButton;
}

}

// static 
void InputDispatcher::Create(automation::InputRequest request, PageInstance* page_instance) {//, blink::WebLocalFrameImpl* frame_impl) {
  new InputDispatcher(std::move(request), page_instance);//, frame_impl);
}

InputDispatcher::InputDispatcher(automation::InputRequest request, 
                                 PageInstance* page_instance)://,
                                 //blink::WebLocalFrameImpl* frame_impl): 
  application_id_(-1),
  page_instance_(page_instance),
  binding_(this) {//,
  //frame_impl_(frame_impl) {

}

InputDispatcher::InputDispatcher(PageInstance* page_instance)://,
                                 //blink::WebLocalFrameImpl* frame_impl): 
  application_id_(-1),
  page_instance_(page_instance),
  binding_(this) {//,
  //frame_impl_(frame_impl) {

}

InputDispatcher::~InputDispatcher() {

}

void InputDispatcher::Init(IPC::SyncChannel* channel) {
  
}

void InputDispatcher::Bind(automation::InputAssociatedRequest request) {
  //DLOG(INFO) << "InputDispatcher::Bind (application)";
  binding_.Bind(std::move(request));
}

blink::LocalFrame* InputDispatcher::GetMainFrame() {
  return page_instance_->inspected_frames()->Root();
}

void InputDispatcher::Register(int32_t application_id) {
  application_id_ = application_id;
}

void InputDispatcher::DispatchKeyEvent(automation::KeyEventType type, int32_t modifiers, int64_t timestamp, const base::Optional<std::string>& text, const base::Optional<std::string>& unmodified_text, const base::Optional<std::string>& key_identifier, const base::Optional<std::string>& code, const base::Optional<std::string>& key, int32_t windows_virtual_key_code, int32_t native_virtual_key_code, bool auto_repeat, bool is_keypad, bool is_system_key, int32_t location, DispatchKeyEventCallback callback) {    
  blink::WebKeyboardEvent input_event(FromKeyEvent(type), modifiers, base::TimeTicks::FromInternalValue(timestamp));
  if (text.has_value()) {
    size_t len = std::max(text.value().size(), kTextLengthCap);
    memcpy(input_event.text, text.value().data(), len);
  }
  if (unmodified_text.has_value()) {
    size_t len = std::max(unmodified_text.value().size(), kTextLengthCap);
    memcpy(input_event.unmodified_text, unmodified_text.value().data(), len);
  }
  if (code.has_value()) {
    ui::DomCode dom_code = ui::KeycodeConverter::CodeStringToDomCode(code.value());
    input_event.dom_code = ui::KeycodeConverter::DomCodeToNativeKeycode(dom_code);
  }
  if (key.has_value()) {
    ui::DomKey dom_key = ui::KeycodeConverter::KeyStringToDomKey(key.value());
    input_event.dom_key = dom_key;
  }

  if (windows_virtual_key_code != -1) {
    input_event.windows_key_code = windows_virtual_key_code;
  }
  if (native_virtual_key_code != -1) {
    input_event.native_key_code = native_virtual_key_code;
  }
  input_event.is_system_key = is_system_key;

  if (is_keypad || auto_repeat) {
    int modifiers = 0;
    if (is_keypad)
      modifiers |= blink::WebInputEvent::kIsKeyPad;
    if (auto_repeat)
      modifiers |= blink::WebInputEvent::kIsAutoRepeat;

    input_event.SetModifiers(modifiers);  
  }

  bool handled = HandleInputEvent(input_event);
  std::move(callback).Run(handled);
}

void InputDispatcher::DispatchMouseEvent(automation::MouseEventType type, int32_t x, int32_t y, int32_t modifiers, int64_t timestamp, automation::MouseButton button, int32_t click_count, int32_t delta_x, int32_t delta_y, DispatchMouseEventCallback callback) {
  blink::WebMouseEvent input_event(FromMouseEvent(type),
                                   blink::WebFloatPoint(x, y),
                                   blink::WebFloatPoint(delta_x, delta_y),
                                   FromMouseButton(button),
                                   click_count,
                                   modifiers,
                                   base::TimeTicks::FromInternalValue(timestamp));
  bool handled = HandleInputEvent(input_event);
  std::move(callback).Run(handled);
}

void InputDispatcher::DispatchTouchEvent(automation::TouchEventType type, std::vector<automation::TouchPointPtr> touch_points, int32_t modifiers, int64_t timestamp, DispatchTouchEventCallback callback) {
  blink::WebTouchEvent input_event(FromTouchEvent(type),
                                   modifiers,
                                   base::TimeTicks::FromInternalValue(timestamp));
  for (size_t i = 0; i < touch_points.size(); i++) {
    input_event.touches[i].radius_x = touch_points[i]->radius_x;
    input_event.touches[i].radius_y = touch_points[i]->radius_y; 
    input_event.touches[i].rotation_angle = touch_points[i]->rotation_angle; 
    input_event.touches[i].SetPositionInScreen(touch_points[i]->x, touch_points[i]->y);
    input_event.touches[i].force = touch_points[i]->force;
  }
  bool handled = HandleInputEvent(input_event);
  std::move(callback).Run(handled);
}

void InputDispatcher::EmulateTouchFromMouseEvent(automation::MouseEventType type, int32_t x, int32_t y, automation::MouseButton button, int64_t timestamp, int32_t delta_x, int32_t delta_y, int32_t modifiers, int32_t click_count, EmulateTouchFromMouseEventCallback callback) {
  blink::WebTouchEvent input_event(FromMouseEventToTouch(type),
                                   modifiers,
                                   base::TimeTicks::FromInternalValue(timestamp));
  
  input_event.touches[0].SetPositionInScreen(x, y);

  bool handled = HandleInputEvent(input_event);
  std::move(callback).Run(handled);
}

void InputDispatcher::SetIgnoreInputEvents(bool ignore) {

}

void InputDispatcher::SynthesizePinchGesture(int32_t x, int32_t y, int32_t scale_factor, int32_t relative_speed, automation::GestureSourceType gesture_source_type, SynthesizePinchGestureCallback callback) {
  blink::WebGestureEvent input_event;
  bool handled = HandleInputEvent(input_event);
  std::move(callback).Run(handled);
}

void InputDispatcher::SynthesizeScrollGesture(int32_t x, int32_t y, int32_t x_distance, int32_t y_distance, int32_t x_overscroll, int32_t y_overscroll, bool prevent_fling, int32_t speed, automation::GestureSourceType gesture_source_type, int32_t repeat_count, int32_t repeat_delay_ms, const base::Optional<std::string>& interaction_marker_name, SynthesizeScrollGestureCallback callback) {
  blink::WebGestureEvent input_event;
  bool handled = HandleInputEvent(input_event);
  std::move(callback).Run(handled);
}

void InputDispatcher::SynthesizeTapGesture(int32_t x, int32_t y, int32_t duration, int32_t tap_count, automation::GestureSourceType gesture_source_type, SynthesizeTapGestureCallback callback) {
  //blink::WebGestureEvent input_event(blink::WebInputEvent::Type::kGestureTap);
  blink::WebGestureEvent input_event;
  bool handled = HandleInputEvent(input_event);
  std::move(callback).Run(handled);
}

bool InputDispatcher::HandleInputEvent(const blink::WebInputEvent& input_event) {
  bool handled = false;

  if (input_event.GetType() == blink::WebInputEvent::kGestureTap) {
    // We only have a use for gesture tap.
    blink::WebGestureEvent transformed_event = TransformWebGestureEvent(
        frame_impl_->GetFrameView(),
        static_cast<const blink::WebGestureEvent&>(input_event));
    GetMainFrame()->GetEventHandler().HandleGestureEvent(transformed_event);
  }
  if (blink::WebInputEvent::IsMouseEventType(input_event.GetType())) {
    blink::WebMouseEvent mouse_event =
        TransformWebMouseEvent(frame_impl_->GetFrameView(),
                               static_cast<const blink::WebMouseEvent&>(input_event));

    if (mouse_event.GetType() == blink::WebInputEvent::kMouseMove) {
      handled = GetMainFrame()->GetEventHandler().HandleMouseMoveEvent(
                    mouse_event, TransformWebMouseEventVector(
                                     frame_impl_->GetFrameView(),
                                     std::vector<const blink::WebInputEvent*>())) !=
                blink::WebInputEventResult::kNotHandled;
    }
    if (mouse_event.GetType() == blink::WebInputEvent::kMouseDown) {
      handled = GetMainFrame()->GetEventHandler().HandleMousePressEvent(
                    mouse_event) != blink::WebInputEventResult::kNotHandled;
    }
    if (mouse_event.GetType() == blink::WebInputEvent::kMouseUp) {
      handled = GetMainFrame()->GetEventHandler().HandleMouseReleaseEvent(
                    mouse_event) != blink::WebInputEventResult::kNotHandled;
    }
  }

  if (blink::WebInputEvent::IsPointerEventType(input_event.GetType())) {
    blink::WebPointerEvent transformed_event = TransformWebPointerEvent(
        frame_impl_->GetFrameView(),
        static_cast<const blink::WebPointerEvent&>(input_event));
    GetMainFrame()->GetEventHandler().HandlePointerEvent(
        transformed_event, Vector<blink::WebPointerEvent>());
  }
  if (blink::WebInputEvent::IsKeyboardEventType(input_event.GetType())) {
    GetMainFrame()->GetEventHandler().KeyEvent(
        static_cast<const blink::WebKeyboardEvent&>(input_event));
  }

  if (input_event.GetType() == blink::WebInputEvent::kMouseWheel) {
    blink::WebMouseWheelEvent transformed_event = TransformWebMouseWheelEvent(
        frame_impl_->GetFrameView(),
        static_cast<const blink::WebMouseWheelEvent&>(input_event));
    handled = GetMainFrame()->GetEventHandler().HandleWheelEvent(
                  transformed_event) != blink::WebInputEventResult::kNotHandled;
  }

  return handled;
}

void InputDispatcher::OnWebFrameCreated(blink::WebLocalFrame* web_frame) {
  frame_impl_ = static_cast<blink::WebLocalFrameImpl*>(web_frame);
}


}
