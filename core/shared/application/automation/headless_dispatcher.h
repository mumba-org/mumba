// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_APPLICATION_HEADLESS_DISPATCHER_H_
#define MUMBA_APPLICATION_HEADLESS_DISPATCHER_H_

#include "core/shared/common/mojom/automation.mojom.h"

#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"

namespace blink {
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

class HeadlessDispatcher : public automation::Headless {
public:
  static void Create(automation::HeadlessRequest request, PageInstance* page_instance);

  HeadlessDispatcher(automation::HeadlessRequest request, PageInstance* page_instance);
  HeadlessDispatcher(PageInstance* page_instance);
  ~HeadlessDispatcher() override;

  void Init(IPC::SyncChannel* channel);
  void Bind(automation::HeadlessAssociatedRequest request);

  void Register(int32_t application_id) override;
  void BeginFrame(int64_t frame_time, int32_t frame_time_ticks, int64_t deadline, int32_t deadline_ticks, int32_t interval, bool no_display_updates, automation::ScreenshotParamsPtr screenshot, BeginFrameCallback callback) override;
  void EnterDeterministicMode(int32_t initial_date) override;
  void Disable() override;
  void Enable() override;

  PageInstance* page_instance() const {
    return page_instance_;
  }

  void OnWebFrameCreated(blink::WebLocalFrame* web_frame);
  
private:
  int32_t application_id_;
  PageInstance* page_instance_;
  mojo::AssociatedBinding<automation::Headless> binding_;
  automation::HeadlessClientAssociatedPtr headless_client_ptr_;

  DISALLOW_COPY_AND_ASSIGN(HeadlessDispatcher); 
};

}

#endif