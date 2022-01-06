// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_APPLICATION_INPUT_DISPATCHER_H_
#define MUMBA_APPLICATION_INPUT_DISPATCHER_H_

#include "core/shared/common/mojom/automation.mojom.h"

#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "third_party/blink/renderer/platform/heap/handle.h"

namespace blink {
class LocalFrame;
class WebInputEvent;
class WebLocalFrameImpl;
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

class InputDispatcher : public automation::Input {
public:
  
  static void Create(automation::InputRequest request, PageInstance* page_instance);//, blink::WebLocalFrameImpl* frame_impl);

  InputDispatcher(automation::InputRequest request, 
                  PageInstance* page_instance);//,
                  //blink::WebLocalFrameImpl* frame_impl);
  InputDispatcher(PageInstance* page_instance);//,
                  //blink::WebLocalFrameImpl* frame_impl);
  ~InputDispatcher() override;

  void Init(IPC::SyncChannel* channel);
  void Bind(automation::InputAssociatedRequest request);

  void Register(int32_t application_id) override;
  void DispatchKeyEvent(automation::KeyEventType type, int32_t modifiers, int64_t timestamp, const base::Optional<std::string>& text, const base::Optional<std::string>& unmodified_text, const base::Optional<std::string>& key_identifier, const base::Optional<std::string>& code, const base::Optional<std::string>& key, int32_t windows_virtual_key_code, int32_t native_virtual_key_code, bool auto_repeat, bool is_keypad, bool is_system_key, int32_t location, DispatchKeyEventCallback callback) override;
  void DispatchMouseEvent(automation::MouseEventType type, int32_t x, int32_t y, int32_t modifiers, int64_t timestamp, automation::MouseButton button, int32_t click_count, int32_t delta_x, int32_t delta_y, DispatchMouseEventCallback callback) override;
  void DispatchTouchEvent(automation::TouchEventType type, std::vector<automation::TouchPointPtr> touch_points, int32_t modifiers, int64_t timestamp, DispatchTouchEventCallback callback) override;
  void EmulateTouchFromMouseEvent(automation::MouseEventType type, int32_t x, int32_t y, automation::MouseButton button, int64_t timestamp, int32_t delta_x, int32_t delta_y, int32_t modifiers, int32_t click_count, EmulateTouchFromMouseEventCallback callback) override;
  void SetIgnoreInputEvents(bool ignore) override;
  void SynthesizePinchGesture(int32_t x, int32_t y, int32_t scale_factor, int32_t relative_speed, automation::GestureSourceType gesture_source_type, SynthesizePinchGestureCallback callback) override;
  void SynthesizeScrollGesture(int32_t x, int32_t y, int32_t x_distance, int32_t y_distance, int32_t x_overscroll, int32_t y_overscroll, bool prevent_fling, int32_t speed, automation::GestureSourceType gesture_source_type, int32_t repeat_count, int32_t repeat_delay_ms, const base::Optional<std::string>& interaction_marker_name, SynthesizeScrollGestureCallback callback) override;
  void SynthesizeTapGesture(int32_t x, int32_t y, int32_t duration, int32_t tap_count, automation::GestureSourceType gesture_source_type, SynthesizeTapGestureCallback callback) override;

  PageInstance* page_instance() const {
    return page_instance_;
  }

  blink::LocalFrame* GetMainFrame();

  void OnWebFrameCreated(blink::WebLocalFrame* web_frame);
  
private:

  bool HandleInputEvent(const blink::WebInputEvent& input_event);

  int32_t application_id_;
  PageInstance* page_instance_;
  mojo::AssociatedBinding<automation::Input> binding_;
  blink::Member<blink::WebLocalFrameImpl> frame_impl_;

  DISALLOW_COPY_AND_ASSIGN(InputDispatcher); 
};

}

#endif