// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_NAVIGATION_CONTROLLER_H_
#define MUMBA_HOST_APPLICATION_NAVIGATION_CONTROLLER_H_

#include <memory>

#include "core/host/application/navigation_entry.h"
#include "base/atomic_sequence_num.h"

namespace host {
class RouteController;

class CONTENT_EXPORT NavigationController : public net::URLRequest::Delegate {
public: 
  NavigationController(RouteController* url_controller);
  ~NavigationController();

  void Navigate(const GURL& url, base::OnceCallback<void(int, NavigationEntry*)> callback);
  void Navigate(std::unique_ptr<net::URLRequest> request, base::OnceCallback<void(int, NavigationEntry*)> callback);

  NavigationEntry* current() const {
    return current_;
  }

  void OnResponseStarted(net::URLRequest* request, int net_error) override;
  void OnReadCompleted(net::URLRequest* request, int bytes_read) override;

private:
 
  std::unique_ptr<net::URLRequest> CreateRequest(const GURL& url,
                                                 const std::string& method);
  
  void OnRouteEntryResolved(std::unique_ptr<net::URLRequest> request, base::OnceCallback<void(int, NavigationEntry*)> callback, int result, RouteEntry* entry);

 RouteController* url_controller_;
 NavigationEntry* current_;
 std::unordered_map<int, std::unique_ptr<NavigationEntry>> entries_;
 base::AtomicSequenceNumber sequence_;
 base::WeakPtrFactory<NavigationController> weak_factory_;
 
 DISALLOW_COPY_AND_ASSIGN(NavigationController);
};

}  // namespace host

#endif
