// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_GRAPH_GRAPH_CURSOR_H_
#define MUMBA_HOST_GRAPH_GRAPH_CURSOR_H_

#include "base/macros.h"
#include "core/host/graph/graph_entry.h"
#include "core/host/graph/graph_node.h"
#include "core/host/graph/graph_edge.h"
#include "core/host/graph/graph_property.h"
#include "storage/db/db.h"

namespace host {
class GraphTransaction;

class GraphCursor {
public:
  virtual ~GraphCursor() {} 
  
  virtual GraphEntryBase* Get() const = 0;
  virtual bool HasNext() const = 0;
  virtual void Next() = 0;
  virtual void Close() = 0;
  virtual size_t Count() = 0;
  
  template <class T> T* GetAs() {
    GraphEntryBase* entry = Get();
    return entry->cast_as<T>();
  }

  GraphNode* GetNode() {
    return GetAs<GraphNode>(); 
  }

  GraphEdge* GetEdge() {
    return GetAs<GraphEdge>();
  }

  GraphProperty* GetProperty() {
    return GetAs<GraphProperty>(); 
  }

};

}

#endif