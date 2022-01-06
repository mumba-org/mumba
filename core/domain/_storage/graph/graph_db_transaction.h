// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_NAMESPACE_GRAPH_GRAPH_TRANSACTION_H_
#define MUMBA_DOMAIN_NAMESPACE_GRAPH_GRAPH_TRANSACTION_H_

#include "core/shared/domain/storage/graph/graph_db_nodes.h"
//#include "core/shared/domain/storage/graph/graph_iterator.h"
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
#include "core/shared/domain/storage/graph/lemongraph.h"
#pragma clang diagnostic push

namespace domain {

// always use on stack.. cheap copy constructible
class GraphDbTransaction {
public:
  GraphDbTransaction(graph_txn_t handle);
  ~GraphDbTransaction();

  GraphDbTransaction(const GraphDbTransaction &other) {
    handle_ = other.handle_; 
  }

  bool Commit();
  void Abort();
  bool Updated();

  graph_txn_t handle() const {
    return handle_;
  }

  uint64_t Delete(const GraphDbEntry& entry);

  uint64_t GetNextID() const;

  GraphDbPropertyIterator GetProperties();
  GraphDbEdgeIterator GetEdges();
  GraphDbNodeIterator GetNodes();

  bool GetEntry(uint64_t id, GraphDbEntry* entry);
  bool GetNode(uint64_t id, GraphDbNode* node);
  bool GetEdge(uint64_t id, GraphDbEdge* edge);
  bool GetProperty(uint64_t id, GraphDbProperty* prop);

private:
  graph_txn_t handle_;
};

}

#endif