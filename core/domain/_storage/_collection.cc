// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/storage/collection.h"

#include "base/macros.h"
#include "base/logging.h"

namespace domain {

Collection::Collection(std::string oid, std::string oname, std::shared_ptr<data::Schema> schema): 
 Object(std::move(oid), std::move(oname), schema) {

}

Collection::Collection(std::string oname, std::shared_ptr<data::Schema> schema): 
  Object(std::move(oname), schema) {

}

Collection::~Collection() {

}

size_t Collection::count() const {
  NOTREACHED();
  return 0;
}

std::shared_ptr<RecordBatch> Collection::Scan() {
  NOTREACHED();
  return {};
}

}