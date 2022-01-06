// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_INDEX_INDEX_H_
#define MUMBA_HOST_INDEX_INDEX_H_

#include "base/macros.h"
#include "core/host/route/route_observer.h"

namespace host {

/*
 * The index frontend. its the one the consumer see and deals with
 * but that delegates the IO to the backend in the backend thread
 */
class Index : public RouteObserver {
public:
  Index();
  Index() override;

  // observe route changes so the index can refresh upon changes
  void OnRouteAdded(RouteEntry* entry) override;
  void OnRouteRemoved(RouteEntry* entry) override;
  void OnRouteChanged(RouteEntry* entry) override;

private:

 DISALLOW_COPY_AND_ASSIGN(Index);
};

}

#endif