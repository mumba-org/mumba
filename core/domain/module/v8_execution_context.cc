// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/module/v8_execution_context.h"

#include "gin/public/isolate_holder.h"

namespace domain {

class V8ExecutionContext::Interface : public CoreInterface {
public:
  Interface() {}
  ~Interface() {}

  // Interface
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

V8ExecutionContext::V8ExecutionContext(
	Executable* executable, 
	scoped_refptr<base::SingleThreadTaskRunner> background_task_runner):
	 executable_(executable),
	 background_task_runner_(background_task_runner),
	 interface_(new Interface()),
	 initialized_(false) {

}

V8ExecutionContext::~V8ExecutionContext() {

}

bool V8ExecutionContext::initialized() const {
  return initialized_;
}

CoreInterface* V8ExecutionContext::core_interface() {
  return interface_.get();
}

void V8ExecutionContext::LoadCoreLibraries() { 
  if (!LoadBuiltins()) {
  	return;
  }
  if (!LoadPlatformLibraries()) {
  	return;
  }
  if (!LoadSDKLibraries()) {
  	return;
  }
}

bool V8ExecutionContext::LoadBuiltins() {
  // Load our home-made builtins into the v8 isolate
  
  // for instance, we could give access to a logging facility
  return true;
}

bool V8ExecutionContext::LoadPlatformLibraries() { 
  // Load the posix layer
  return true;
}

bool V8ExecutionContext::LoadSDKLibraries() {
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