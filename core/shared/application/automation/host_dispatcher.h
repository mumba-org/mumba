// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_APPLICATION_HOST_DISPATCHER_H_
#define MUMBA_APPLICATION_HOST_DISPATCHER_H_

#include "core/shared/common/mojom/automation.mojom.h"

#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"

namespace service_manager {
class InterfaceProvider;
}

namespace blink {
class WebLocalFrame;  
}

namespace IPC {
class SyncChannel;
}

namespace application {
class PageInstance;

class HostDispatcher : public automation::Host {
public:
  static void Create(automation::HostRequest request, PageInstance* page_instance);

  HostDispatcher(automation::HostRequest request, PageInstance* page_instance);
  HostDispatcher(PageInstance* page_instance);
  ~HostDispatcher() override;

  void Init(IPC::SyncChannel* channel);
  void Bind(automation::HostAssociatedRequest request);

  void Register(int32_t application_id) override;
  void Close() override;
  void GetVersion(GetVersionCallback callback) override;
  void GetHostCommandLine(GetHostCommandLineCallback callback) override;
  void GetHistograms(const base::Optional<std::string>& query, GetHistogramsCallback callback) override;
  void GetHistogram(const std::string& name, GetHistogramCallback callback) override;
  void GetWindowBounds(int32_t window_id, GetWindowBoundsCallback callback) override;
  void GetWindowForTarget(const std::string& target_id, GetWindowForTargetCallback callback) override;
  void SetWindowBounds(int32_t window_id, automation::BoundsPtr bounds) override;
  
  PageInstance* page_instance() const {
    return page_instance_;
  }

  void OnWebFrameCreated(blink::WebLocalFrame* web_frame);

private:
  int32_t application_id_;
  PageInstance* page_instance_;
  mojo::AssociatedBinding<automation::Host> binding_;

  DISALLOW_COPY_AND_ASSIGN(HostDispatcher); 
};

}

#endif