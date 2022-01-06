// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_GRAPH_GRAPH_MANAGER_OBSERVER_H_
#define MUMBA_HOST_GRAPH_GRAPH_MANAGER_OBSERVER_H_

#include "base/macros.h"
#include "base/uuid.h"
#include "base/callback.h"
#include "base/strings/string_piece.h"
#include "storage/torrent.h"
#include "storage/db/db.h"
#include "core/host/graph/graph_model.h"
#include "core/host/share/share_database.h"

namespace host {
class Graph;
class GraphManagerObserver {
public:
  virtual ~GraphManagerObserver(){}
  virtual void OnGraphsLoad(int r, int count) {}
  virtual void OnGraphCreated(int r, Graph* graph) {}
  virtual void OnGraphOpen(int r, Graph* graph) {}
  virtual void OnGraphRemoved(int r, Graph* graph) {}
};

}

#endif