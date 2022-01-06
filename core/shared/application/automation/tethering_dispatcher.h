// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_APPLICATION_TETHERING_DISPATCHER_H_
#define MUMBA_APPLICATION_TETHERING_DISPATCHER_H_

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

class TetheringDispatcher : public automation::Tethering {
public:
  static void Create(automation::TetheringRequest request, PageInstance* page_instance);

  TetheringDispatcher(automation::TetheringRequest request, PageInstance* page_instance);
  TetheringDispatcher(PageInstance* page_instance);
  ~TetheringDispatcher() override;

  void Init(IPC::SyncChannel* channel);
  void BindMojo(automation::TetheringAssociatedRequest request);

  void Register(int32_t application_id) override;
  void Bind(int32_t port) override;
  void Unbind(int32_t port) override;

  PageInstance* page_instance() const {
    return page_instance_;
  }

  void OnWebFrameCreated(blink::WebLocalFrame* web_frame);
  
private:
  int32_t application_id_;
  PageInstance* page_instance_;
  mojo::AssociatedBinding<automation::Tethering> binding_;
  automation::TetheringClientAssociatedPtr tethering_client_ptr_;

  DISALLOW_COPY_AND_ASSIGN(TetheringDispatcher); 
};

}

#endif