// Copyright 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_DOMAIN_PROCESS_H_
#define MUMBA_DOMAIN_DOMAIN_PROCESS_H_

#include <memory>

#include "base/macros.h"
#include "base/template_util.h"
#include "base/memory/ref_counted.h"
#include "base/synchronization/waitable_event.h"
#include "base/threading/thread.h"
#include "base/uuid.h"
#include "core/shared/common/child_process.h"
#include "core/domain/domain_thread.h"
#include "core/domain/domain_context.h"

namespace domain {

class DomainProcess : public common::ChildProcess {
public:
  static std::unique_ptr<DomainProcess> Create();
  static DomainProcess* current() {
    return static_cast<DomainProcess*>(common::ChildProcess::current());
  }

  DomainProcess(const std::string& task_scheduler_name,
                   std::unique_ptr<base::TaskScheduler::InitParams> task_scheduler_init_params);
  ~DomainProcess() override;

private:

  DISALLOW_COPY_AND_ASSIGN(DomainProcess);
};

}

#endif