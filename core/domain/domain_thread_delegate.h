// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_DOMAIN_THREAD_DELEGATE_H_
#define MUMBA_DOMAIN_DOMAIN_THREAD_DELEGATE_H_

#include "core/shared/common/content_export.h"

namespace domain {

// A Delegate for content embedders to perform extra initialization/cleanup on
// DomainThread::IO.
class DomainThreadDelegate {
 public:
  virtual ~DomainThreadDelegate() = default;

  // Called prior to completing initialization of DomainThread::IO.
  virtual void Init() = 0;

  // Called during teardown of DomainThread::IO.
  virtual void CleanUp() = 0;
};

}  // namespace domain

#endif  // MUMBA_DOMAIN_DOMAIN_THREAD_DELEGATE_H_
