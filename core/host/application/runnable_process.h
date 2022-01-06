// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_RUNNABLE_PROCESS_H_
#define MUMBA_HOST_APPLICATION_RUNNABLE_PROCESS_H_

#include "base/macros.h"
#include "base/callback.h"
#include "base/process/process.h"
#include "ipc/ipc_sender.h"
#include "ipc/ipc_listener.h"
#include "ipc/ipc_channel_proxy.h"
#include "core/shared/common/mojom/application.mojom.h"

namespace host {
class Domain;
class Runnable;
class RunnableProcess {
public:
  virtual ~RunnableProcess() {}
  virtual Domain* domain() const = 0;
  virtual Runnable* runnable() const = 0;
  virtual int GetID() const = 0;
  virtual const base::Process& GetProcess() const = 0;
  virtual IPC::ChannelProxy* GetChannelProxy() = 0;
  virtual common::mojom::Application* GetApplicationInterface() = 0;
  virtual bool Shutdown(int exit_code) = 0;
};

}

#endif