// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/vm/vm_manager_linux.h"

#include "core/host/workspace/workspace.h"
#include "chromeos/vm_tools/concierge/service.h"

namespace host {

VMManagerLinux::VMManagerLinux(scoped_refptr<Workspace> workspace, scoped_refptr<ShareDatabase> db): 
  workspace_(std::move(workspace)),
  db_(db),
  task_runner_(
    base::CreateSingleThreadTaskRunnerWithTraits(
     {base::MayBlock(), 
      base::WithBaseSyncPrimitives(), 
      base::TaskPriority::USER_BLOCKING},
      base::SingleThreadTaskRunnerThreadMode::DEDICATED
  )),
  weak_factory_(this) {
  
}

VMManagerLinux::~VMManagerLinux() {

}

bool VMManagerLinux::Init() {
  task_runner_->PostTask(
    FROM_HERE,
    base::BindOnce(&VMManagerLinux::InitImpl, base::Unretained(this)));
  return true;
}

bool VMManagerLinux::HaveResource(const base::UUID& id) {
  return false;
}

bool VMManagerLinux::HaveResource(const std::string& name) {
  return false;
}

Resource* VMManagerLinux::GetResource(const base::UUID& id) {
  return nullptr;
}

Resource* VMManagerLinux::GetResource(const std::string& name) {
  return nullptr;
}

void VMManagerLinux::InitImpl() {
  service_ = vm_tools::concierge::Service::Create();
}

const google::protobuf::Descriptor* VMManagerLinux::resource_descriptor() {
  return nullptr;
}

std::string VMManagerLinux::resource_classname() const {
  return std::string();
}


}