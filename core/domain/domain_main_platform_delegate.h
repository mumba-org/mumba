// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_DOMAIN_MAIN_PLATFORM_DELEGATE_H_
#define MUMBA_DOMAIN_DOMAIN_MAIN_PLATFORM_DELEGATE_H_

#include "build/build_config.h"

#if defined(OS_WIN)
#include <windows.h>
#endif

#include "base/macros.h"
#include "base/files/file_path.h"
#include "core/shared/common/content_export.h"
#include "core/common/main_params.h"

namespace domain {

class CONTENT_EXPORT DomainMainPlatformDelegate {
 public:
  explicit DomainMainPlatformDelegate(
      const common::MainParams& parameters);
  ~DomainMainPlatformDelegate();

  // Called first thing and last thing in the process' lifecycle, i.e. before
  // the sandbox is enabled.
  void PlatformInitialize(const base::FilePath& root);
  void PlatformUninitialize();

  // Initiate Lockdown, returns true on success.
  bool EnableSandbox();

 private:
#if defined(OS_WIN)
  const common::MainParams& parameters_;
#endif

  base::FilePath root_dir_;

  DISALLOW_COPY_AND_ASSIGN(DomainMainPlatformDelegate);
};

}  // namespace domain

#endif  // CORE_DOMAIN_RENDERER_MAIN_PLATFORM_DELEGATE_H_
