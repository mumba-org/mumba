// Copyright 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_VM_MANAGER_H_
#define MUMBA_HOST_VM_MANAGER_H_

#include <string>

#include "base/macros.h"
#include "core/host/data/resource.h"

namespace host {
class Workspace;
class ShareDatabase;
#if defined(OS_LINUX)
class VMManagerLinux;
#else
class VMManagerDummy;
#endif

class VMManager : public ResourceManager {
public:
  VMManager();
  ~VMManager() override;

  bool Init(scoped_refptr<Workspace> workspace, scoped_refptr<ShareDatabase> db);

  // ResourceManager
  bool HaveResource(const base::UUID& id) override;
  bool HaveResource(const std::string& name) override;
  Resource* GetResource(const base::UUID& id) override;
  Resource* GetResource(const std::string& name) override;
  const google::protobuf::Descriptor* resource_descriptor() override;
  std::string resource_classname() const override;

private:

#if defined(OS_LINUX)
  std::unique_ptr<VMManagerLinux> impl_;
#else
  std::unique_ptr<VMManagerDummy> impl_;
#endif
  
  DISALLOW_COPY_AND_ASSIGN(VMManager);
};

}

#endif