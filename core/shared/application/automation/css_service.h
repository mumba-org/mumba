// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_APPLICATION_CSS_SERVICE_H_
#define MUMBA_APPLICATION_CSS_SERVICE_H_

#include "services/service_manager/public/cpp/binder_registry.h"
#include "services/service_manager/public/cpp/service.h"
#include "core/shared/common/mojom/automation.mojom.h"

namespace application {
class PageInstance;
class AutomationContext;
class CSSDispatcher;

class CSSService : public service_manager::Service {
 public:
  CSSService(AutomationContext* context, PageInstance* page_instance);
  ~CSSService() override;

  CSSDispatcher* dispatcher() const {
    return dispatcher_;
  }

 private:
  // service_manager::Service:
  void OnStart() override;
  void OnBindInterface(const service_manager::BindSourceInfo& source_info,
                       const std::string& interface_name,
                       mojo::ScopedMessagePipeHandle interface_pipe) override;

  void Create(automation::CSSRequest request);

  // Shuts down this instance, blocking it from serving any pending or future
  // requests. Safe to call multiple times; will be a no-op after the first
  // call.
  void ShutDown();
  bool IsShutDown();
  
  AutomationContext* context_;
  PageInstance* page_instance_;
  CSSDispatcher* dispatcher_;
  service_manager::BinderRegistry registry_;
  bool shutdown_ = false;

  DISALLOW_COPY_AND_ASSIGN(CSSService);
};

}  // namespace application

#endif  // MUMBA_APPLICATION_CSS_SERVICE_H_
