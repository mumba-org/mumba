// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/background_fetch/background_fetch_delegate_factory.h"

#include "core/host/background_fetch/background_fetch_delegate_impl.h"
//#include "core/host/download/download_service_factory.h"
#include "core/host/background_fetch_delegate.h"

namespace host {

// static
BackgroundFetchDelegateImpl* BackgroundFetchDelegateFactory::GetForDomain(Domain* domain) {
  return GetInstance()->GetBackgroundFetchDelegate(domain);
  
}

// static
BackgroundFetchDelegateFactory* BackgroundFetchDelegateFactory::GetInstance() {
  return base::Singleton<BackgroundFetchDelegateFactory>::get();
}

BackgroundFetchDelegateFactory::BackgroundFetchDelegateFactory() {
    //:// BrowserContextKeyedServiceFactory(
    //      "BackgroundFetchService",
     //     BrowserContextDependencyManager::GetInstance()) {
  //DependsOn(DownloadServiceFactory::GetInstance());
}

BackgroundFetchDelegateFactory::~BackgroundFetchDelegateFactory() {}

//KeyedService* BackgroundFetchDelegateFactory::BuildServiceInstanceFor(
//    content::BrowserContext* context) const {
//  return new BackgroundFetchDelegateImpl(Profile::FromBrowserContext(context));
//}

BackgroundFetchDelegateImpl* BackgroundFetchDelegateFactory::GetBackgroundFetchDelegate(Domain* domain) {
  if (!delegate_) {
    delegate_ = std::make_unique<BackgroundFetchDelegateImpl>(domain);
  }
  return delegate_.get();
}

}