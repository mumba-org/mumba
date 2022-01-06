// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_APPLICATION_TARGET_DISPATCHER_H_
#define MUMBA_APPLICATION_TARGET_DISPATCHER_H_

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
class TargetDispatcher : public automation::Target {
public:
  static void Create(automation::TargetRequest request, PageInstance* page_instance);

  TargetDispatcher(automation::TargetRequest request, PageInstance* page_instance);
  TargetDispatcher(PageInstance* page_instance);
  ~TargetDispatcher() override;

  void Init(IPC::SyncChannel* channel);
  void Bind(automation::TargetAssociatedRequest request);

  void Register(int32_t application_id) override;
  void ActivateTarget(const std::string& target_id) override;
  void AttachToTarget(const std::string& targetId, AttachToTargetCallback callback) override;
  void CloseTarget(const std::string& target_id, CloseTargetCallback callback) override;
  void CreateBrowserContext(CreateBrowserContextCallback callback) override;
  void CreateTarget(const std::string& url, int32_t width, int32_t height, const base::Optional<std::string>& browser_context_id, bool enable_begin_frame_control, CreateTargetCallback callback) override;
  void DetachFromTarget(const base::Optional<std::string>& session_id, const base::Optional<std::string>& target_id) override;
  void DisposeBrowserContext(const std::string& browser_context_id, DisposeBrowserContextCallback callback) override;
  void GetTargetInfo(const std::string& targetId, GetTargetInfoCallback callback) override;
  void GetTargets(GetTargetsCallback callback) override;
  void SendMessageToTarget(const std::string& message, const base::Optional<std::string>& session_id, const base::Optional<std::string>& target_id) override;
  void SetAutoAttach(bool auto_attach, bool wait_for_debugger_on_start) override;
  void SetDiscoverTargets(bool discover) override;
  void SetRemoteLocations(std::vector<automation::RemoteLocationPtr> locations) override;

  PageInstance* page_instance() const {
    return page_instance_;
  }

  void OnWebFrameCreated(blink::WebLocalFrame* web_frame);
  
private:
  int32_t application_id_;
  PageInstance* page_instance_;
  mojo::AssociatedBinding<automation::Target> binding_;
  automation::TargetClientAssociatedPtr target_client_ptr_;

  DISALLOW_COPY_AND_ASSIGN(TargetDispatcher); 
};

}

#endif