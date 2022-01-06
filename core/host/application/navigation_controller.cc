// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/navigation_controller.h"

#include "core/host/route/route_controller.h"
#include "core/host/route/route_entry.h"
#include "core/host/io_thread.h"
#include "core/host/host_controller.h"
#include "net/url_request/url_request_context.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"

namespace host {

NavigationController::NavigationController(RouteController* url_controller):
 url_controller_(url_controller),
 current_(nullptr),
 weak_factory_(this) {

}

NavigationController::~NavigationController() {

}

void NavigationController::Navigate(const GURL& url, base::OnceCallback<void(int, NavigationEntry*)> callback) {
  if (current() && current()->request()->url() == url) {
    std::move(callback).Run(net::OK, current());
    return;
  }
  std::unique_ptr<net::URLRequest> request = CreateRequest(url, "GET");
  Navigate(std::move(request), std::move(callback));
}

void NavigationController::Navigate(std::unique_ptr<net::URLRequest> request, base::OnceCallback<void(int, NavigationEntry*)> callback) {
  if (current() && current()->request()->url() == request->url()) {
    std::move(callback).Run(net::OK, current());
    return;
  }

  url_controller_->GoTo(
    request->url(), 
    base::BindOnce(&NavigationController::OnRouteEntryResolved,
                   weak_factory_.GetWeakPtr(),
                   base::Passed(std::move(request)),
                   base::Passed(std::move(callback))));
}

std::unique_ptr<net::URLRequest> NavigationController::CreateRequest(const GURL& url,
                                                                     const std::string& method) {
  IOThread* io_thread = HostController::Instance()->io_thread();
  std::unique_ptr<net::URLRequest> request =
  io_thread->system_url_request_context()->CreateRequest(
                                           url, 
                                            net::DEFAULT_PRIORITY,
                                           this,
                                           TRAFFIC_ANNOTATION_FOR_TESTS);
  request->set_method(method);
  return request;
}

void NavigationController::OnResponseStarted(net::URLRequest* request, int net_error) {

}

void NavigationController::OnReadCompleted(net::URLRequest* request, int bytes_read) {

}

void NavigationController::OnRouteEntryResolved(std::unique_ptr<net::URLRequest> request, base::OnceCallback<void(int, NavigationEntry*)> callback, int result, RouteEntry* entry) {
  if (result != net::OK) {
    // dont let the request destructor run on ui thread
    HostThread::DeleteSoon(HostThread::IO, FROM_HERE, request.release());
    std::move(callback).Run(result, nullptr);
    return;
  }
  std::unique_ptr<NavigationEntry> nav_entry = std::make_unique<NavigationEntry>();
  int id = sequence_.GetNext() + 1;
  nav_entry->set_id(id);
  nav_entry->set_route(entry);
  nav_entry->set_request(std::move(request));

  NavigationEntry* entry_ptr = nav_entry.get();
  current_ = entry_ptr;
  entries_.emplace(std::make_pair(id, std::move(nav_entry)));
  std::move(callback).Run(result, entry_ptr);
}

}