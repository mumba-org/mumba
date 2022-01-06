// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_BACKGROUND_SYNC_BACKGROUND_SYNC_CONTROLLER_FACTORY_H_
#define CHROME_BROWSER_BACKGROUND_SYNC_BACKGROUND_SYNC_CONTROLLER_FACTORY_H_

#include "base/macros.h"
#include "base/memory/singleton.h"
//#include "components/keyed_service/content/browser_context_keyed_service_factory.h"

namespace host {
class BackgroundSyncControllerImpl;
class Domain;

class BackgroundSyncControllerFactory {
 public:
  static BackgroundSyncControllerImpl* GetForDomain(Domain* domain);
  static BackgroundSyncControllerFactory* GetInstance();

 private:
  friend struct base::DefaultSingletonTraits<BackgroundSyncControllerFactory>;

  BackgroundSyncControllerFactory();
  ~BackgroundSyncControllerFactory();

  BackgroundSyncControllerImpl* GetBackgroundSyncController(Domain* domain);

  std::unique_ptr<BackgroundSyncControllerImpl> controller_;

  DISALLOW_COPY_AND_ASSIGN(BackgroundSyncControllerFactory);
};

}

#endif  // CHROME_BROWSER_BACKGROUND_SYNC_BACKGROUND_SYNC_CONTROLLER_FACTORY_H_
