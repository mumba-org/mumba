// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_NAMESPACE_COLLECTIONS_PROCESS_COLLECTION_H_
#define MUMBA_DOMAIN_NAMESPACE_COLLECTIONS_PROCESS_COLLECTION_H_

#include <string>

#include "base/macros.h"
#include "core/shared/domain/storage/collection.h"

namespace domain {

class ProcessCollection : public Collection {
public:
  ProcessCollection();
  ~ProcessCollection() override;

  size_t count() const override;
  std::shared_ptr<RecordBatch> Scan() override;
};

}

#endif