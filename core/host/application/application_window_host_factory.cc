// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/application_window_host_factory.h"

#include <memory>

#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "core/host/application/application_window_host.h"

namespace host {

// static
ApplicationWindowHostFactory* ApplicationWindowHostFactory::factory_ = nullptr;

// static
bool ApplicationWindowHostFactory::is_real_application_window_host_ = false;

// static
ApplicationWindowHost* ApplicationWindowHostFactory::Create(
    ApplicationWindowHostDelegate* delegate,
    Application* application,
    ApplicationProcessHost* process,
    int32_t routing_id,
    bool swapped_out,
    bool hidden) {
  // RenderViewHost creation can be either browser-driven (by the user opening a
  // new tab) or renderer-driven (by script calling window.open, etc).
  //
  // In the browser-driven case, the routing ID of the view is lazily assigned:
  // this is signified by passing MSG_ROUTING_NONE for |routing_id|.
  if (routing_id == MSG_ROUTING_NONE) {
    routing_id = process->GetNextRoutingID();
  }// else {
    // Otherwise, in the renderer-driven case, the routing ID of the view is
    // already set. This is due to the fact that a sync render->browser IPC is
    // involved. In order to quickly reply to the sync IPC, the routing IDs are
    // assigned as early as possible. The IO thread immediately sends a reply to
    // the sync IPC, while deferring the creation of the actual Host objects to
    // the UI thread.
  //}
  if (factory_) {
    return factory_->CreateApplicationWindowHost(delegate,
                                                 application,
                                                 process, 
                                                 routing_id, 
                                                 swapped_out);
  }
  return new ApplicationWindowHost(
    delegate,
    application,
    process,
    routing_id,
    hidden);
}

// static
void ApplicationWindowHostFactory::RegisterFactory(ApplicationWindowHostFactory* factory) {
  DCHECK(!factory_) << "Can't register two factories at once.";
  factory_ = factory;
}

// static
void ApplicationWindowHostFactory::UnregisterFactory() {
  DCHECK(factory_) << "No factory to unregister.";
  factory_ = nullptr;
}

}  // namespace host
