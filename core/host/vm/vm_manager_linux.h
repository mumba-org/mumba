// Copyright 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_VM_MANAGER_LINUX_H_
#define MUMBA_HOST_VM_MANAGER_LINUX_H_

#include <string>

#include "base/macros.h"
#include "core/host/data/resource.h"
#include "base/single_thread_task_runner.h"
#include "base/memory/weak_ptr.h"

namespace vm_tools {
namespace concierge {
// concierge service
class Service;
}
}

namespace host {
class Workspace;
class ShareDatabase;

class VMManagerLinux : public ResourceManager {
public:
  VMManagerLinux(scoped_refptr<Workspace> workspace, scoped_refptr<ShareDatabase> db);
  ~VMManagerLinux() override;

  bool Init();

  // ResourceManager
  bool HaveResource(const base::UUID& id) override;
  bool HaveResource(const std::string& name) override;
  Resource* GetResource(const base::UUID& id) override;
  Resource* GetResource(const std::string& name) override;
  const google::protobuf::Descriptor* resource_descriptor() override;
  std::string resource_classname() const override;

private:

  void InitImpl();

  scoped_refptr<Workspace> workspace_;
  scoped_refptr<ShareDatabase> db_;
  // has/owns its own thread
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
  // concierge service
  std::unique_ptr<vm_tools::concierge::Service> service_;

  base::WeakPtrFactory<VMManagerLinux> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(VMManagerLinux);
};

}

#endif