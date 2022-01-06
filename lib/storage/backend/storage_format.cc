// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/backend/storage_format.h"

namespace storage {

IndexHeader::IndexHeader() {
  memset(this, 0, sizeof(*this));
  magic = kIndexMagic;
  version = kCurrentVersion;
}

}  // namespace storage
