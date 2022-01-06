// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/win/jumplist_factory.h"

#include "base/no_destructor.h"
#include "core/host/favicon/favicon_service_factory.h"
#include "core/host/win/jumplist.h"

namespace host {

// static
JumpList* JumpListFactory::Get() {
  return JumpListFactory::GetInstance()->jumplist();
}

// static
JumpListFactory* JumpListFactory::GetInstance() {
  static base::NoDestructor<JumpListFactory> instance;
  return instance.get();
}

JumpListFactory::JumpListFactory(): jumplist_(new JumpList()) {
}

JumpListFactory::~JumpListFactory() = default;

}