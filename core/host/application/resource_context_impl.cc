// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/resource_context_impl.h"

#include <stdint.h>

#include "base/bind.h"
#include "base/logging.h"
#include "core/host/application/resource_dispatcher_host.h"
#include "core/host/application/resource_request_info_impl.h"
#include "core/host/streams/stream_context.h"
#include "core/host/application/url_data_manager.h"
#include "core/host/application/url_data_manager_backend.h"
#include "core/host/application/application_contents.h"
#include "core/host/application/domain.h"
#include "core/host/host_thread.h"

using base::UserDataAdapter;

namespace host {

// Key names on ResourceContext.
//const char kStreamContextKeyName[] = "content_stream_context";
//const char kURLDataManagerBackendKeyName[] = "url_data_manager_backend";

ResourceContext::ResourceContext() {}

ResourceContext::~ResourceContext() {
  if (ResourceDispatcherHost::Get())
    ResourceDispatcherHost::Get()->CancelRequestsForContext(this);
}

ResourceContextImpl::ResourceContextImpl(
    Domain* domain,
    net::HostResolver* host_resolver,
    net::URLRequestContext* request_context):
  domain_(domain),
  host_resolver_(host_resolver),
  request_context_(request_context) {
 
}

ResourceContextImpl::~ResourceContextImpl() {
  
}

Domain* ResourceContextImpl::GetDomain() {
  return domain_;
}

net::HostResolver* ResourceContextImpl::GetHostResolver() {
  return host_resolver_;
}

net::URLRequestContext* ResourceContextImpl::GetRequestContext() {
  return request_context_;
}

URLDataManager* ResourceContextImpl::GetDataManager() const {
  return data_manager_.get();
}

void ResourceContextImpl::SetDataManager(std::unique_ptr<URLDataManager> data_manager) {
  data_manager_ = std::move(data_manager);
}

URLDataManagerBackend* ResourceContextImpl::GetDataManagerBackend() const {
  return data_manager_backend_.get();
}

void ResourceContextImpl::SetDataManagerBackend(std::unique_ptr<URLDataManagerBackend> data_manager) {
  data_manager_backend_ = std::move(data_manager);
}

ChromeBlobStorageContext* ResourceContextImpl::GetBlobStorageContext() {
  return domain_->GetBlobStorageContext();
}

StreamContext* ResourceContextImpl::GetStreamContext() {
  return domain_->GetStreamContext();
}

StreamContext* GetStreamContextForResourceContext(
   const ResourceContext* resource_context) {
 DCHECK_CURRENTLY_ON(HostThread::IO);
//  return UserDataAdapter<StreamContext>::Get(
//      resource_context, kStreamContextKeyName);
return const_cast<ResourceContextImpl*>(static_cast<const ResourceContextImpl*>(resource_context))->GetStreamContext();
}


//URLDataManagerBackend* GetURLDataManagerForResourceContext(
//    ResourceContext* context) {
//  DCHECK_CURRENTLY_ON(HostThread::IO);
//  scoped_refptr<Workspace> workspace = context->GetWorkspace();
//  if (!workspace->GetUserData(kURLDataManagerBackendKeyName)) {
//    workspace->SetUserData(kURLDataManagerBackendKeyName,
//                         std::make_unique<URLDataManagerBackend>(workspace));
//  }
//  return static_cast<URLDataManagerBackend*>(
//      workspace->GetUserData(kURLDataManagerBackendKeyName));
//}

ChromeBlobStorageContext* GetChromeBlobStorageContextForResourceContext(
    const ResourceContext* resource_context) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  // return UserDataAdapter<ChromeBlobStorageContext>::Get(
  //     resource_context, kBlobStorageContextKeyName);
  return const_cast<ResourceContextImpl*>(static_cast<const ResourceContextImpl*>(resource_context))->GetBlobStorageContext();
}

void InitializeResourceContext(Domain* domain) {
  ResourceContext* resource_context = domain->GetResourceContext();

  //resource_context->SetUserData(
  //    kBlobStorageContextKeyName,
  //    std::make_unique<UserDataAdapter<ChromeBlobStorageContext>>(
  //        ChromeBlobStorageContext::GetFor(browser_context)));

  //resource_context->SetUserData(
  //    kStreamContextKeyName, std::make_unique<UserDataAdapter<StreamContext>>(
  //                               StreamContext::GetFor(browser_context)));

  resource_context->DetachFromSequence();
}

}  // namespace host
