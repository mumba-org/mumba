// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_NAVIGATION_ENTRY_H_
#define MUMBA_HOST_APPLICATION_NAVIGATION_ENTRY_H_

#include <memory>

#include "core/host/route/route_entry.h"
#include "net/url_request/url_request.h"
#include "core/host/service_worker/service_worker_context_wrapper.h"
#include "core/host/service_worker/service_worker_navigation_handle.h"
#include "core/host/host_thread.h"

namespace host {

class NavigationEntry : public ServiceWorkerNavigationHandle::Observer {
public:  
  NavigationEntry(): valid_service_worker_handle_(false) {}
  ~NavigationEntry() override {
    if (service_worker_handle_) {
      service_worker_handle_->RemoveObserver(this);
    }
    HostThread::GetTaskRunnerForThread(HostThread::IO)->DeleteSoon(FROM_HERE, request_.release());
    // if (request_) {
    //   request_->set_network_delegate(nullptr);
    //   request_->DetachFromSequence();
    // }
  }

  int id() const {
    return id_;
  }

  void set_id(int id) {
    id_ = id;
  }

  net::URLRequest* request() const {
    return request_.get();
  }

  void set_request(std::unique_ptr<net::URLRequest> request) {
    request_ = std::move(request);
  }

  RouteEntry* route() const {
    return route_;
  }

  void set_route(RouteEntry* route) {
    route_ = route;
  }
  
  int route_id() const {
    return route_id_;
  }

  void set_route_id(int route_id) {
    route_id_ = route_id;
  }

  int32_t provider_id() const {
    //DCHECK(valid_service_worker_handle_);
    return valid_service_worker_handle_ ? 
      service_worker_provider_host_id_ : 
      service_worker_handle_->service_worker_provider_host_id();
  }

  void InitServiceWorkerHandle(ServiceWorkerContextWrapper* service_worker_context) {
    service_worker_handle_.reset(new ServiceWorkerNavigationHandle(service_worker_context));
    service_worker_handle_->AddObserver(this);
  }

  ServiceWorkerNavigationHandle* service_worker_handle() const {
    return service_worker_handle_.get();
  }

  void OnCreateServiceWorkerProviderHost(int service_worker_provider_host_id) override {
    service_worker_provider_host_id_ = service_worker_provider_host_id;
    valid_service_worker_handle_ = true;
  }

private:
  
  RouteEntry* route_ = nullptr;
  std::unique_ptr<net::URLRequest> request_;
  std::unique_ptr<ServiceWorkerNavigationHandle> service_worker_handle_;
  int id_ = 0;
  int route_id_ = 0;
  int32_t service_worker_provider_host_id_ = 0;
  bool valid_service_worker_handle_;
  
  DISALLOW_COPY_AND_ASSIGN(NavigationEntry);
};

}  // namespace host

#endif
