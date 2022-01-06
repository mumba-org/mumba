// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_APPLICATION_ACCESSIBILITY_DISPATCHER_H_
#define MUMBA_APPLICATION_ACCESSIBILITY_DISPATCHER_H_

#include "core/shared/common/mojom/automation.mojom.h"

#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"

namespace blink {
class LocalFrame;
class WebLocalFrame;
}

namespace IPC {
class SyncChannel;
}

namespace service_manager {
class InterfaceProvider;
}

namespace application {
class PageInstance;

class AccessibilityDispatcher : public automation::Accessibility {
public:

  static void Create(automation::AccessibilityRequest request, PageInstance* page_instance);

  AccessibilityDispatcher(automation::AccessibilityRequest request, PageInstance* page_instance);
  AccessibilityDispatcher(PageInstance* page_instance);
  ~AccessibilityDispatcher() override;

  void Init(IPC::SyncChannel* channel);
  void Bind(automation::AccessibilityAssociatedRequest request);

  void Register(int32_t application_id) override;
  void GetPartialAXTree(const base::Optional<std::string>& node_id, int32_t backend_node_id, const base::Optional<std::string>& object_id, bool fetch_relatives, GetPartialAXTreeCallback callback) override;
  
  PageInstance* page_instance() const {
    return page_instance_;
  }

  void OnWebFrameCreated(blink::WebLocalFrame* web_frame);

private:
  PageInstance* page_instance_;
  int32_t application_id_;
  mojo::AssociatedBinding<automation::Accessibility> binding_;

  
  DISALLOW_COPY_AND_ASSIGN(AccessibilityDispatcher); 
};

}

#endif