// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/favicon/large_icon_service_factory.h"

#include "base/memory/singleton.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/favicon/favicon_service_factory.h"
//#include "chrome/browser/profiles/incognito_helpers.h"
#include "core/host/workspace/workspace.h"
#include "core/host/favicon/image_decoder_impl.h"
#include "components/favicon/core/favicon_service.h"
#include "components/favicon/core/large_icon_service.h"
#include "components/image_fetcher/core/image_decoder.h"
#include "components/image_fetcher/core/image_fetcher_impl.h"
//#include "components/keyed_service/content/browser_context_dependency_manager.h"
//#include "core/host/browser_context.h"

namespace host {

// static
//favicon::LargeIconService* LargeIconServiceFactory::GetForBrowserContext(
    //content::BrowserContext* context) {
  //return static_cast<favicon::LargeIconService*>(
      //GetInstance()->GetServiceForBrowserContext(context, true));
  //return nullptr;
//}

// static
LargeIconServiceFactory* LargeIconServiceFactory::GetInstance() {
  return base::Singleton<LargeIconServiceFactory>::get();
}

LargeIconServiceFactory::LargeIconServiceFactory() {
    //: BrowserContextKeyedServiceFactory(
   //     "LargeIconService",
   //     BrowserContextDependencyManager::GetInstance()) {
  //DependsOn(FaviconServiceFactory::GetInstance());
}

LargeIconServiceFactory::~LargeIconServiceFactory() {}

//content::BrowserContext* LargeIconServiceFactory::GetBrowserContextToUse(
//      content::BrowserContext* context) const {
  //return chrome::GetBrowserContextRedirectedInIncognito(context);
//}

// static 
favicon::LargeIconService* LargeIconServiceFactory::GetForWorkspace(scoped_refptr<Workspace> workspace) {
  favicon::FaviconService* favicon_service =
      FaviconServiceFactory::GetForWorkspace(workspace,//profile,
                                             ServiceAccessType::EXPLICIT_ACCESS);
  return new favicon::LargeIconService(
      favicon_service,
      std::make_unique<image_fetcher::ImageFetcherImpl>(
          std::make_unique<ImageDecoderImpl>(), nullptr));
}

// KeyedService* LargeIconServiceFactory::BuildServiceInstanceFor(
//     content::BrowserContext* context) const {
//   //Profile* profile = Profile::FromBrowserContext(context);
//   Workspace* workspace = Workspace::GetCurrent();
//   favicon::FaviconService* favicon_service =
//       FaviconServiceFactory::GetForProfile(workspace,//profile,
//                                            ServiceAccessType::EXPLICIT_ACCESS);
//   return new favicon::LargeIconService(
//       favicon_service,
//       std::make_unique<image_fetcher::ImageFetcherImpl>(
//           std::make_unique<ImageDecoderImpl>(), nullptr));//,
//           //profile->GetRequestContext()));
// }

//bool LargeIconServiceFactory::ServiceIsNULLWhileTesting() const {
//  return true;
//}

}