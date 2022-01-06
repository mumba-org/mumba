// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "SandboxImpl.h"

#include <memory>

#include "base/lazy_instance.h"
//#include "base/memory/scoped_ptr.h"
#include "base/threading/thread_local.h"

namespace {

  static base::LazyInstance<std::unique_ptr<Sandbox>>::Leaky::DestructorAtExit g_sandbox =
      LAZY_INSTANCE_INITIALIZER;
}

//static 
Sandbox* Sandbox::CreateInstance() {
  g_sandbox.Get().reset(new Sandbox());
  return g_sandbox.Get().get();
}

// static 
Sandbox* Sandbox::GetInstance() {
  return g_sandbox.Get().get();
}

Sandbox::Sandbox(): initialized_(false) {
}

Sandbox::~Sandbox() {
}
  
bool Sandbox::Init() {
  initialized_ = true;
  return initialized_;
}

bool Sandbox::Enter() {
  DCHECK(initialized_);
  return true;
}

void Sandbox::Leave() {

}