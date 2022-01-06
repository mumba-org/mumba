// Copyright 2015 The Chromium Authors. All rights reserved.
// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/domain_blink_platform_impl.h"

#include "third_party/blink/public/platform/scheduler/child/webthread_base.h"

namespace domain {

DomainBlinkPlatformImpl::DomainBlinkPlatformImpl()
    : main_thread_(blink::scheduler::WebThreadBase::InitializeUtilityThread()) {
}

DomainBlinkPlatformImpl::~DomainBlinkPlatformImpl() {
}

blink::WebThread* DomainBlinkPlatformImpl::CurrentThread() {
  if (main_thread_->IsCurrentThread())
    return main_thread_.get();
  return BlinkPlatformImpl::CurrentThread();
}

}  // namespace domain
