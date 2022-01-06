// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_APPLICATION_DEVICE_ORIENTATION_DISPATCHER_H_
#define MUMBA_APPLICATION_DEVICE_ORIENTATION_DISPATCHER_H_

#include "core/shared/common/mojom/automation.mojom.h"

#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "third_party/blink/renderer/platform/heap/heap.h"
#include "third_party/blink/renderer/platform/heap/heap_traits.h"

namespace blink {
class DeviceOrientationController;
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
class DeviceOrientationInspectorAgentImpl;

class DeviceOrientationDispatcher : public automation::DeviceOrientation {
public:

  static void Create(automation::DeviceOrientationRequest request, PageInstance* page_instance);

  DeviceOrientationDispatcher(automation::DeviceOrientationRequest request, PageInstance* page_instance);
  DeviceOrientationDispatcher(PageInstance* page_instance);
  ~DeviceOrientationDispatcher() override;

  void Init(IPC::SyncChannel* channel);
  void Bind(automation::DeviceOrientationAssociatedRequest request);

  void Register(int32_t application_id) override;
  void ClearDeviceOrientationOverride() override;
  void SetDeviceOrientationOverride(int32_t alpha, int32_t beta, int32_t gamma) override;

  PageInstance* page_instance() const {
    return page_instance_;
  }

  void OnWebFrameCreated(blink::WebLocalFrame* web_frame);
  
private:
  friend class DeviceOrientationInspectorAgentImpl;

  void DidCommitLoadForLocalFrame(blink::LocalFrame* frame);
  void Restore();
  blink::DeviceOrientationController* Controller();

  PageInstance* page_instance_;
  int32_t application_id_;
  mojo::AssociatedBinding<automation::DeviceOrientation> binding_;
  blink::Persistent<DeviceOrientationInspectorAgentImpl> device_orientation_inspector_agent_;
  double alpha_;  
  double beta_;
  double gamma_;
  bool enabled_;

  DISALLOW_COPY_AND_ASSIGN(DeviceOrientationDispatcher); 
};

}

#endif
