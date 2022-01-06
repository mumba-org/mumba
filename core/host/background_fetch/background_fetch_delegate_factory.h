// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_BACKGROUND_FETCH_BACKGROUND_FETCH_DELEGATE_FACTORY_H_
#define CHROME_BROWSER_BACKGROUND_FETCH_BACKGROUND_FETCH_DELEGATE_FACTORY_H_

#include "base/macros.h"
#include "base/memory/singleton.h"
//#include "components/keyed_service/content/browser_context_keyed_service_factory.h"

namespace host {

class BackgroundFetchDelegateImpl;
class Domain;

class BackgroundFetchDelegateFactory {
  //  : public BrowserContextKeyedServiceFactory {
 public:
  static BackgroundFetchDelegateImpl* GetForDomain(Domain* domain);
  static BackgroundFetchDelegateFactory* GetInstance();

 private:
  friend struct base::DefaultSingletonTraits<BackgroundFetchDelegateFactory>;

  BackgroundFetchDelegateFactory();
  ~BackgroundFetchDelegateFactory();

  // BrowserContextKeyedBaseFactory methods:
  // TODO(crbug.com/766082): Override GetBrowserContextToUse to handle Incognito
  // mode.
//   KeyedService* BuildServiceInstanceFor(
//       content::BrowserContext* context) const override;
  BackgroundFetchDelegateImpl* GetBackgroundFetchDelegate(Domain* domain);

  std::unique_ptr<BackgroundFetchDelegateImpl> delegate_;

  DISALLOW_COPY_AND_ASSIGN(BackgroundFetchDelegateFactory);
};

}

#endif  // CHROME_BROWSER_BACKGROUND_FETCH_BACKGROUND_FETCH_DELEGATE_FACTORY_H_
