// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_STORE_APP_STORE_OBSERVER_H_
#define MUMBA_HOST_STORE_APP_STORE_OBSERVER_H_

#include <memory>

#include "base/macros.h"

namespace host {
class AppStoreEntry;

class AppStoreObserver {
public:
  virtual ~AppStoreObserver(){}
  virtual void OnAppStoreEntriesLoad(int r, int count) {}
  virtual void OnAppStoreEntryAdded(AppStoreEntry* entry) {}
  virtual void OnAppStoreEntryRemoved(AppStoreEntry* entry) {}
};

}

#endif