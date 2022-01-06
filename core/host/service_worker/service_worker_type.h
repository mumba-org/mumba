// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_HOST_SERVICE_WORKER_SERVICE_WORKER_TYPE_H_
#define CORE_HOST_SERVICE_WORKER_SERVICE_WORKER_TYPE_H_

namespace host {
class ApplicationProcessHost;
class DomainProcessHost;

enum ServiceWorkerProcessType {
  kPROCESS_TYPE_APPLICATION = 0,
  kPROCESS_TYPE_SERVICE = 1,
};

struct ServiceWorkerProcessHandle {
  ServiceWorkerProcessType type = kPROCESS_TYPE_APPLICATION;
  ApplicationProcessHost* application = nullptr;
  DomainProcessHost* service = nullptr;
};

}

#endif
