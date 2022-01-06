// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_CORE_HOST_APPLICATION_ROUTE_CONTROLLER_H_
#define MUMBA_CORE_HOST_APPLICATION_ROUTE_CONTROLLER_H_

#include <string>

#include "base/macros.h"
#include "url/gurl.h"
#include "base/memory/weak_ptr.h"

namespace host {
class RouteEntry;
class RouteGraph;
class RouteResolver;
class RouteRegistry;

/* 
 * TODO: use RouteGraph as internal representation
 * return current() from it and we can have
 * Previous() Next() allowing for proper navigation
 * over the graph
 */
class RouteController {
public:  
  RouteController(RouteResolver* resolver);
  ~RouteController();

  RouteRegistry* registry() const;

  bool is_active() const {
    return active_;
  }

  void set_active(bool active) {
    active_ = active;
  }

  RouteEntry* GetCurrent() const;
  RouteEntry* Get(size_t offset) const;
  void GoTo(const std::string& scheme, const std::string& page_name, base::OnceCallback<void(int, RouteEntry*)> callback);
  void GoTo(const GURL& url, base::OnceCallback<void(int, RouteEntry*)> callback);
  
private:

  void OnEntryResolved(base::OnceCallback<void(int, RouteEntry*)> callback, int result, RouteEntry* entry);

  RouteResolver* resolver_;
  RouteEntry* current_entry_;

  bool active_;

  base::WeakPtrFactory<RouteController> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(RouteController);
};

}

#endif