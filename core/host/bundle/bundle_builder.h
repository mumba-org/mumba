// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_BUNDLE_BUILDER_H_
#define MUMBA_HOST_BUNDLE_BUILDER_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"
#include "base/strings/string_piece.h"

namespace host {

class BundleBuilder {
public:
  BundleBuilder();
  ~BundleBuilder();
  
private:
  DISALLOW_COPY_AND_ASSIGN(BundleBuilder);
};

}

#endif