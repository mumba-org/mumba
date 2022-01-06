// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/domain_main_platform_delegate.h"

namespace domain {

DomainMainPlatformDelegate::DomainMainPlatformDelegate(
    const common::MainParams& parameters) {}

DomainMainPlatformDelegate::~DomainMainPlatformDelegate() {}

void DomainMainPlatformDelegate::PlatformInitialize(const base::FilePath& root) {}

void DomainMainPlatformDelegate::PlatformUninitialize() {}

bool DomainMainPlatformDelegate::EnableSandbox() {
  // TODO(750938): Report NOTIMPLEMENTED() here until we re-enable sandboxing
  // of sub-processes.
  NOTIMPLEMENTED();
  return true;
}

}  // namespace domain
