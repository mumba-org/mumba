// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_APPLICATION_SYSTEM_INFO_DISPATCHER_H_
#define MUMBA_APPLICATION_SYSTEM_INFO_DISPATCHER_H_

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

class SystemInfoDispatcher : public automation::SystemInfo {
public:
  static void Create(automation::SystemInfoRequest request, PageInstance* page_instance);
  
  SystemInfoDispatcher(automation::SystemInfoRequest request, PageInstance* page_instance);
  SystemInfoDispatcher(PageInstance* page_instance);
  ~SystemInfoDispatcher() override;

  void Init(IPC::SyncChannel* channel);

  void Bind(automation::SystemInfoAssociatedRequest request);

  // SystemInfo
  void Register(int32_t application_id) override;
  void GetInfo(GetInfoCallback callback) override;

  PageInstance* page_instance() const {
    return page_instance_;
  }

  void OnWebFrameCreated(blink::WebLocalFrame* web_frame);
  
private:
  int32_t application_id_;
  PageInstance* page_instance_;
  mojo::AssociatedBinding<automation::SystemInfo> binding_;
  
  DISALLOW_COPY_AND_ASSIGN(SystemInfoDispatcher); 
};

}

#endif