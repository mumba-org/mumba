// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_NAMESPACE_NAMESPACE_DATABASE_BACKEND_H_
#define MUMBA_DOMAIN_NAMESPACE_NAMESPACE_DATABASE_BACKEND_H_

#include "base/callback.h"

namespace domain {

class DatabaseBackend {
public:
  virtual ~DatabaseBackend() {}
  virtual bool in_memory() const = 0;
  virtual void Initialize(const base::Callback<void(int, int)>& result) = 0;
  virtual void Shutdown() = 0;
  virtual void CheckDatabase(const base::Callback<void(int)>& result) = 0;
};

}

#endif