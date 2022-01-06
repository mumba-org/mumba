// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_SERVICE_WORKER_WORKER_NATIVE_CLIENT_FACTORY_H_
#define MUMBA_DOMAIN_SERVICE_WORKER_WORKER_NATIVE_CLIENT_FACTORY_H_

#include <memory>

#include "base/macros.h"
#include "core/shared/common/content_export.h"
#include "third_party/blink/renderer/core/workers/worker_native_client.h"

namespace common {

class CONTENT_EXPORT WorkerNativeClientFactory {
public:
  virtual ~WorkerNativeClientFactory() {}
  virtual std::unique_ptr<blink::WorkerNativeClient> CreateWorkerNativeClient() = 0;
};

}

#endif