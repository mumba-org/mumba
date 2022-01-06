// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_CORE_HOST_ROUTE_OBSERVER_H_
#define MUMBA_CORE_HOST_ROUTE_OBSERVER_H_

namespace host {
class RouteEntry;

class RouteObserver {
public:
 virtual ~RouteObserver() {}
 virtual void OnRouteEntriesLoad(int r, int count) {}
 virtual void OnRouteAdded(RouteEntry* entry) {}
 virtual void OnRouteRemoved(RouteEntry* entry) {}
 virtual void OnRouteChanged(RouteEntry* entry) {}
};

}

#endif