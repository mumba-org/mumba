// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_CORE_HOST_ROUTE_REGISTRY_ROUTE_GRAPH_H_
#define MUMBA_CORE_HOST_ROUTE_REGISTRY_ROUTE_GRAPH_H_

#include <string>

#include "base/macros.h"
#include "base/callback.h"

namespace host {
class Graph;
class RouteEntry;
class RouteRegistry;

class RouteGraph {
public:
  RouteGraph(RouteRegistry* registry);//, Graph* graph);
  ~RouteGraph();

  size_t count();

  RouteEntry* GetCurrent() const;
  RouteEntry* Get(size_t offset) const;

  bool GoTo(const std::string& scheme, const std::string& path);
  bool GoNext();
  bool GoPrevious();
  
private:
  RouteRegistry* registry_; 
 // Graph* graph_;
  RouteEntry* current_;
  size_t count_;

  DISALLOW_COPY_AND_ASSIGN(RouteGraph);
};

}

#endif