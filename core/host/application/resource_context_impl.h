// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_RESOURCE_CONTEXT_IMPL_H_
#define CONTENT_BROWSER_RESOURCE_CONTEXT_IMPL_H_

#include "core/shared/common/content_export.h"
#include "core/host/application/resource_context.h"

namespace host {
//class StreamContext;
class Domain;
class URLDataManager;
class URLDataManagerBackend;

class ResourceContextImpl : public ResourceContext {
public:
  ResourceContextImpl(
    Domain* domain,
    net::HostResolver* host_resolver,
    net::URLRequestContext* request_context); 
  
  ~ResourceContextImpl() override;

  Domain* GetDomain() override;
  net::HostResolver* GetHostResolver() override;
  net::URLRequestContext* GetRequestContext() override;

  URLDataManager* GetDataManager() const override;
  void SetDataManager(std::unique_ptr<URLDataManager> data_manager) override;
  URLDataManagerBackend* GetDataManagerBackend() const override;
  void SetDataManagerBackend(std::unique_ptr<URLDataManagerBackend> data_manager) override;
  ChromeBlobStorageContext* GetBlobStorageContext() override;
  StreamContext* GetStreamContext() override;
  void SetDomain(Domain* domain) {
    domain_ = domain;
  }

private:

  Domain* domain_;
  net::HostResolver* host_resolver_;
  net::URLRequestContext* request_context_;
  std::unique_ptr<URLDataManager> data_manager_;
  std::unique_ptr<URLDataManagerBackend> data_manager_backend_;

  DISALLOW_COPY_AND_ASSIGN(ResourceContextImpl);
};

// Getters for objects that are part of BrowserContext which are also used on
// the IO thread. These are only accessed by content so they're not on the
// public API.

ChromeBlobStorageContext* GetChromeBlobStorageContextForResourceContext(
    const ResourceContext* resource_context);

CONTENT_EXPORT StreamContext* GetStreamContextForResourceContext(
    const ResourceContext* resource_context);

//URLDataManagerBackend* GetURLDataManagerForResourceContext(
//    ResourceContext* context);

// Initialize the above data on the ResourceContext from a given BrowserContext.
CONTENT_EXPORT void InitializeResourceContext(Domain* domain);

}  // namespace host

#endif  // CONTENT_BROWSER_RESOURCE_CONTEXT_IMPL_H_
