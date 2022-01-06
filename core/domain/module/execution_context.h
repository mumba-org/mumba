// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_EXECUTION_EXECUTION_CONTEXT_H_
#define MUMBA_DOMAIN_EXECUTION_EXECUTION_CONTEXT_H_

#include <memory>

#include "base/macros.h"

namespace domain {

// the platform for the "shell sdk" 
// the loaded dso should be using as
// a interface to custom core features 
class CoreInterface {
public:
  virtual ~CoreInterface() {}

  /*
   * socket api
   */
  virtual void CreateSocket(
      int type, 
      int id, 
      const uint8_t* local_addr, 
      int local_port, 
      uint16_t port_range_min, 
      uint16_t port_range_max, 
      const uint8_t* remote_addr, 
      int remote_port,
      base::Callback<void(int, int)> onCreate) = 0;

  virtual void CloseSocket(int id) = 0;
};

/*
 * A isolated area of execution, with its own memory
 * and possibly with some thread affinity logic
 */
class ExecutionContext {
public:
  virtual ~ExecutionContext() {}
  virtual bool initialized() const = 0;
  virtual CoreInterface* core_interface() = 0;
};

}

#endif