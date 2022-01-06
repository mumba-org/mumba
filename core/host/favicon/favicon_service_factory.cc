// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/favicon/favicon_service_factory.h"

#include <memory>

#include "base/memory/ptr_util.h"
#include "base/memory/singleton.h"
#include "core/host/favicon/favicon_client.h"
//#include "chrome/browser/history/history_service_factory.h"
#include "core/host/workspace/workspace.h"
#include "components/favicon/core/favicon_service_impl.h"
//#include "components/history/core/browser/history_service.h"
#include "components/keyed_service/content/browser_context_dependency_manager.h"
//#include "components/prefs/pref_service.h"

namespace host {

// namespace {

// std::unique_ptr<KeyedService> BuildFaviconService(
//     content::BrowserContext* context) {
//   //Profile* profile = Profile::FromBrowserContext(context);
//   Workspace* workspace = Workspace::GetCurrent();
//   return std::make_unique<favicon::FaviconServiceImpl>(
//       base::WrapUnique(new FaviconClient(workspace)));//,
//       //HistoryServiceFactory::GetForProfile(workspacs,
//       //                                     ServiceAccessType::EXPLICIT_ACCESS));
// }

// }  // namespace

// static
favicon::FaviconService* FaviconServiceFactory::GetForWorkspace(
    scoped_refptr<Workspace> workspace,
    ServiceAccessType sat) {
  //if (!profile->IsOffTheRecord()) {
  //  return static_cast<favicon::FaviconService*>(
  //      GetInstance()->GetServiceForBrowserContext(profile, true));
  //} //else if (sat == ServiceAccessType::EXPLICIT_ACCESS) {
    // Profile must be OffTheRecord in this case.
    //return static_cast<favicon::FaviconService*>(
    //    GetInstance()->GetServiceForBrowserContext(nullptr, false));
           // profile->GetOriginalProfile(), true));
  //}

  // Profile is OffTheRecord without access.
  //NOTREACHED() << "This profile is OffTheRecord";
  //return NULL;
  FaviconServiceFactory* factory = GetInstance();
  DCHECK(factory);
  if (!factory->favicon_service_) {
    factory->favicon_service_ = std::make_unique<favicon::FaviconServiceImpl>(
      base::WrapUnique(new FaviconClient(workspace)));
  }
  return factory->favicon_service_.get();
}

// static
FaviconServiceFactory* FaviconServiceFactory::GetInstance() {
  return base::Singleton<FaviconServiceFactory>::get();
}

// static
//BrowserContextKeyedServiceFactory::TestingFactoryFunction
//FaviconServiceFactory::GetDefaultFactory() {
//  return &BuildFaviconService;
//}

FaviconServiceFactory::FaviconServiceFactory() {
    //:// BrowserContextKeyedServiceFactory(
       // "FaviconService",
        //BrowserContextDependencyManager::GetInstance()) {
  //DependsOn(HistoryServiceFactory::GetInstance());
}

FaviconServiceFactory::~FaviconServiceFactory() {
}

//KeyedService* FaviconServiceFactory::BuildServiceInstanceFor(
    //content::BrowserContext* context) const {
  //return BuildFaviconService(context).release();
//}

//bool FaviconServiceFactory::ServiceIsNULLWhileTesting() const {
//  return true;
//}

}