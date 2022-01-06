// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_FAVICON_LARGE_ICON_SERVICE_FACTORY_H_
#define CHROME_BROWSER_FAVICON_LARGE_ICON_SERVICE_FACTORY_H_

#include "base/macros.h"
#include "base/memory/ref_counted.h"
//#include "components/keyed_service/content/browser_context_keyed_service_factory.h"

namespace base {
template <typename T> struct DefaultSingletonTraits;
}


namespace favicon {
class LargeIconService;
}

namespace host {
class Workspace;

// Singleton that owns all LargeIconService and associates them with
// BrowserContext instances.
class LargeIconServiceFactory {//: public BrowserContextKeyedServiceFactory {
 public:
  //static favicon::LargeIconService* GetForBrowserContext(content::BrowserContext* context);

  static LargeIconServiceFactory* GetInstance();
  static favicon::LargeIconService* GetForWorkspace(scoped_refptr<Workspace> workspace);
  

 private:
  friend struct base::DefaultSingletonTraits<LargeIconServiceFactory>;

  LargeIconServiceFactory();
  ~LargeIconServiceFactory();// override;

  // BrowserContextKeyedServiceFactory:
  //content::BrowserContext* GetBrowserContextToUse(
  //    content::BrowserContext* context) const override;
  //KeyedService* BuildServiceInstanceFor(
  //    content::BrowserContext* context) const override;
  //bool ServiceIsNULLWhileTesting() const override;

  DISALLOW_COPY_AND_ASSIGN(LargeIconServiceFactory);
};

}

#endif  // CHROME_BROWSER_FAVICON_LARGE_ICON_SERVICE_FACTORY_H_
