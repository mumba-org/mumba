// Copyright 2021 Jabberwock Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef THIRD_PARTY_BLINK_RENDERER_CORE_WORKERS_WORKER_NATIVE_CLIENT_H_
#define THIRD_PARTY_BLINK_RENDERER_CORE_WORKERS_WORKER_NATIVE_CLIENT_H_

#include <memory>

#include "base/memory/scoped_refptr.h"
#include "third_party/blink/renderer/core/core_export.h"

namespace blink {
class DedicatedWorker;
class EventListener;
class WorkerGlobalScope;

// This is a interface to be implemented by clients that want to process
// events from the worker thread directly without passing through v8

// It should be on public, but theres a need to reference 'DedicatedWorker'
// so, it would be a layering violation to do so.. but this is for implementers

class CORE_EXPORT WorkerNativeClient {
 public:
  virtual ~WorkerNativeClient() = default;

  virtual EventListener* GetEventListener(WorkerGlobalScope*) = 0;
  virtual void OnWorkerInit(WorkerGlobalScope*) = 0;
  virtual void OnWorkerTerminate() = 0;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_CORE_WORKERS_WORKER_NATIVE_CLIENT_H_
