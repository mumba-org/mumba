// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/module/native_execution_context.h"
#include "core/domain/module/executable.h"

namespace domain {

class NativeExecutionContext::Interface : public CoreInterface {
public:
  Interface() {}
  ~Interface() {}

  // DomainExecutor
  void CreateSocket(
      int type, 
      int id, 
      const uint8_t* local_addr, 
      int local_port, 
      uint16_t port_range_min, 
      uint16_t port_range_max, 
      const uint8_t* remote_addr, 
      int remote_port,
      base::Callback<void(int, int)> onCreate) override {

  }

  void CloseSocket(int id) override {

  }

private:
  DISALLOW_COPY_AND_ASSIGN(Interface);
};

NativeExecutionContext::NativeExecutionContext(
	Executable* executable, 
	scoped_refptr<base::SingleThreadTaskRunner> background_task_runner):
	 executable_(executable),
	 background_task_runner_(background_task_runner),
	 interface_(new Interface()),
	 initialized_(false) {

}

NativeExecutionContext::~NativeExecutionContext() {

}

bool NativeExecutionContext::initialized() const {
  return initialized_;
}

CoreInterface* NativeExecutionContext::core_interface() {
  return interface_.get();
}

void NativeExecutionContext::LoadCoreLibraries() {
  if (!LoadPlatformLibraries()) {
  	return;
  }
  if (!LoadSDKLibraries()) {
  	return;
  }
}

bool NativeExecutionContext::LoadPlatformLibraries() {
  // Load the posix layer
  return true;
}

bool NativeExecutionContext::LoadSDKLibraries() {
  // See wich kind of shell we are: application, web or service
  // according to this profile, load the matching sdk´s for
  // the **shell process**
  
  // eg. the 'module engine' api is pertinent here
  // but the UI api is not, belonging to the application process

  // the profile of the current shell process 
  // is contained in the application disk manifest
  return true;
}


}