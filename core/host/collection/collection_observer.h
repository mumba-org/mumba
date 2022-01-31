// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_STORE_COLLECTION_OBSERVER_H_
#define MUMBA_HOST_STORE_COLLECTION_OBSERVER_H_

#include <memory>

#include "base/macros.h"

namespace host {
class CollectionEntry;

class CollectionObserver {
public:
  virtual ~CollectionObserver(){}
  virtual void OnCollectionEntriesLoad(int r, int count) {}
  virtual void OnCollectionEntryAdded(CollectionEntry* entry) {}
  virtual void OnCollectionEntryRemoved(CollectionEntry* entry) {}
};

}

#endif