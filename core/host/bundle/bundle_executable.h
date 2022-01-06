// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_BUNDLE_EXECUTABLE_H_
#define MUMBA_HOST_BUNDLE_EXECUTABLE_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"
#include "base/strings/string_piece.h"

namespace host {

class BundleExecutable {
public:
  BundleExecutable();
  ~BundleExecutable();
  
private:
  DISALLOW_COPY_AND_ASSIGN(BundleExecutable);
};

}

#endif