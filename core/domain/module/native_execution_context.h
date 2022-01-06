// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_MODULE_NATIVE_EXECUTION_CONTEXT_H_
#define MUMBA_DOMAIN_MODULE_NATIVE_EXECUTION_CONTEXT_H_

#include <memory>
#include <v8.h>

#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "base/files/file_path.h"
#include "base/single_thread_task_runner.h"
#include "core/domain/module/execution_context.h"

namespace domain {
class Executable;
class NativeExecutionContext : public ExecutionContext {
public:
  NativeExecutionContext(Executable* executable, scoped_refptr<base::SingleThreadTaskRunner> background_task_runner);
  ~NativeExecutionContext() override;

  Executable* executable() const {
    return executable_;
  }

  bool initialized() const override;
  CoreInterface* core_interface() override;

private:
  class Interface;

  void LoadCoreLibraries();
  bool LoadPlatformLibraries();
  bool LoadSDKLibraries();
  
  Executable* executable_;

  scoped_refptr<base::SingleThreadTaskRunner> background_task_runner_;

  std::unique_ptr<Interface> interface_;

  bool initialized_;

  DISALLOW_COPY_AND_ASSIGN(NativeExecutionContext);
};

}

#endif
