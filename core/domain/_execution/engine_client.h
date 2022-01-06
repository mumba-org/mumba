// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_MODULE_CLIENT_H_
#define MUMBA_DOMAIN_MODULE_CLIENT_H_

//#include "base/single_thread_task_runner.h"

namespace domain {
class EngineContext;
//class EventQueue;

class EngineClient {
public:
  virtual ~EngineClient() {}

  //virtual EventQueue* event_queue() = 0;
  // Lifetime
  virtual void OnInit(EngineContext* context) = 0;
  //virtual void OnRun() = 0;
  virtual void OnShutdown() = 0;
};

}

#endif