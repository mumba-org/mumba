// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_MODULE_CLIENT_H_
#define MUMBA_DOMAIN_MODULE_CLIENT_H_

#include "core/shared/common/content_export.h"
#include "runtime/MumbaShims/WebDefinitions.h"

namespace domain {
class ModuleState;

class CONTENT_EXPORT ModuleClient {
public:
  virtual ~ModuleClient() {}

  //virtual EventQueue* event_queue() = 0;
  // Lifetime
  virtual void OnInit(ModuleState* state) = 0;
  //virtual void OnRun() = 0;
  virtual void OnShutdown() = 0;
  virtual void* GetServiceWorkerContextClientState() = 0; 
  virtual ServiceWorkerContextClientCallbacks GetServiceWorkerContextClientCallbacks() = 0;
};

}

#endif