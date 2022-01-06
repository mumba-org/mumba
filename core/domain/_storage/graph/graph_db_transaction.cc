// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/storage/graph/graph_db_transaction.h"

namespace domain {

GraphDbTransaction::GraphDbTransaction(graph_txn_t handle): handle_(handle) {

}

GraphDbTransaction::~GraphDbTransaction() {

}

uint64_t GraphDbTransaction::GetNextID() const {
  return graph_log_nextID(handle_);
}

bool GraphDbTransaction::Commit() {
  return graph_txn_commit(handle_) == 0;
}

void GraphDbTransaction::Abort() {
  graph_txn_abort(handle_);
}

bool GraphDbTransaction::Updated() {
  return graph_txn_updated(handle_) == 0;
}

uint64_t GraphDbTransaction::Delete(const GraphDbEntry& entry) {
  return graph_delete(handle_, entry.handle());
}

GraphDbPropertyIterator GraphDbTransaction::GetProperties(){
  return GraphDbPropertyIterator(this, nullptr); 
}

GraphDbEdgeIterator GraphDbTransaction::GetEdges(){
  return GraphDbEdgeIterator(this, nullptr);
}

GraphDbNodeIterator GraphDbTransaction::GetNodes() {
  return GraphDbNodeIterator(this, nullptr);
}

bool GraphDbTransaction::GetEntry(uint64_t id, GraphDbEntry* entry) {
  entry_t n = graph_entry(handle_, id);
  if (!n)
    return false;

  entry->set_handle(n);
  entry->set_transaction(this);
  return true;
}

bool GraphDbTransaction::GetNode(uint64_t id, GraphDbNode* node) {
  node_t n = graph_node(handle_, id);
  if (!n)
    return false;

  node->set_node_handle(n);
  node->set_transaction(this);
  return true;
}

bool GraphDbTransaction::GetEdge(uint64_t id, GraphDbEdge* edge) {
  edge_t n = graph_edge(handle_, id);
  if (!n)
    return false;

  edge->set_edge_handle(n);
  edge->set_transaction(this);
  return true;
}

bool GraphDbTransaction::GetProperty(uint64_t id, GraphDbProperty* prop) {
  prop_t n = graph_prop(handle_, id);
  if (!n)
    return false;

  prop->set_prop_handle(n);
  prop->set_transaction(this);
  return true;
}

}