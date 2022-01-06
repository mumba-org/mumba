// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_RUNNABLE_H_
#define MUMBA_HOST_APPLICATION_RUNNABLE_H_

#include <string>

#include "base/macros.h"
#include "base/uuid.h"
#include "core/shared/common/mojom/application.mojom.h"
#include "core/common/proto/objects.pb.h"
#include "core/host/serializable.h"

namespace host {
class Domain;
class RunnableProcess;
class RunnableManager;

enum class RunnableType : int {
  APPLICATION = 0,
  JOB = 1,
  DAEMON = 2
};

enum class RunnableState : int {
  INIT = 0,
  // a start command was issued but it did not ack 
  STARTING = 1,
  STARTED = 2,
  // a stop command was issued but it did not ack 
  STOPPING = 3,
  STOPPED = 4,
  IDLE = 5
};

class Runnable : public Serializable {
public:
  virtual ~Runnable();
  int id() const;
  const base::UUID& uuid() const;
  const std::string& name() const;
  const std::string& url_string() const;
  GURL url() const;
  RunnableState state();
  void set_state(RunnableState state);
  
  virtual RunnableType type() const = 0;
  Domain* domain() const {
    return domain_;
  }
  virtual RunnableProcess* process() const = 0;
  RunnableManager* manager() const {
    return manager_;
  }

  virtual void TerminateNow() = 0;
  
  virtual common::mojom::Application* GetApplicationInterface();
  virtual bool Shutdown(int exit_code);

  scoped_refptr<net::IOBufferWithSize> Serialize() const override;

protected:
  Runnable(
    RunnableManager* manager, 
    Domain* domain, 
    int id, 
    const std::string& name, 
    const std::string& url, 
    const base::UUID& uuid);

  Runnable(RunnableManager* manager, Domain* domain, protocol::Application proto);
  
  protocol::Application* proto() {
    return &proto_;
  }

  base::UUID uuid_;
  protocol::Application proto_;
  RunnableState state_;
  RunnableManager* manager_;
  Domain* domain_;

  DISALLOW_COPY_AND_ASSIGN(Runnable);
};

}

#endif
