// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/vm/vm_manager.h"

#include "core/host/workspace/workspace.h"
#include "core/host/share/share_database.h"

#if defined(OS_LINUX)
#include "core/host/vm/vm_manager_linux.h"
#endif

namespace host {

class VMManagerDummy : public ResourceManager {
public:
  VMManagerDummy() {}
  ~VMManagerDummy() override {}

  bool Init() {
    return true;
  }

  bool HaveResource(const base::UUID& id) override {
    return false;
  }
  
  bool HaveResource(const std::string& name) override {
    return false;
  }
  
  Resource* GetResource(const base::UUID& id) override {
    return nullptr;
  }
  
  Resource* GetResource(const std::string& name) override {
    return nullptr;
  }
  
  const google::protobuf::Descriptor* resource_descriptor() override {
    return nullptr;
  }
  
  std::string resource_classname() const override {
    return std::string();
  }

private:
  
  DISALLOW_COPY_AND_ASSIGN(VMManagerDummy);
};

VMManager::VMManager() {
  
}

VMManager::~VMManager() {

}

bool VMManager::Init(scoped_refptr<Workspace> workspace, scoped_refptr<ShareDatabase> db) {
#if defined(OS_LINUX)
  impl_ = std::make_unique<VMManagerLinux>(std::move(workspace), db);
#else
  impl_ = std::make_unique<VMManagerDummy>();
#endif
  return impl_->Init();
}

bool VMManager::HaveResource(const base::UUID& id) {
  return impl_->HaveResource(id);
}

bool VMManager::HaveResource(const std::string& name) {
  return impl_->HaveResource(name);
}

Resource* VMManager::GetResource(const base::UUID& id) {
  return impl_->GetResource(id);
}

Resource* VMManager::GetResource(const std::string& name) {
  return impl_->GetResource(name);
}

const google::protobuf::Descriptor* VMManager::resource_descriptor() {
  return impl_->resource_descriptor();
}

std::string VMManager::resource_classname() const {
  return impl_->resource_classname();
}


}