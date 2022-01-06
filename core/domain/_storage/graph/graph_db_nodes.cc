// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/storage/graph/graph_db_nodes.h"

#include "core/shared/domain/storage/graph/graph_db_transaction.h"

namespace domain {

GraphDbEntry::GraphDbEntry(GraphDbTransaction* transaction, entry_t handle): 
  transaction_(transaction),
  handle_(handle) {

}

GraphDbEntry::GraphDbEntry(): handle_(nullptr) {

}

GraphDbEntry::~GraphDbEntry(){

}
  
uint64_t GraphDbEntry::id() const{
  return handle_->id;
}

GraphDbType GraphDbEntry::type() const {
  return static_cast<GraphDbType>(handle_->rectype);
}

bool GraphDbEntry::is_new() const {
  return handle_->is_new;
}

uint64_t GraphDbEntry::next() const {
  return handle_->next;
}

GraphDbNode::GraphDbNode(GraphDbTransaction* transaction, node_t handle): GraphDbEntry(transaction, reinterpret_cast<entry_t>(handle)) {}
GraphDbNode::GraphDbNode(): GraphDbEntry() {}
GraphDbNode::~GraphDbNode() {}

GraphDbPropertyIterator GraphDbNode::properties() const {
  return GraphDbPropertyIterator(transaction(), nullptr);
}

GraphDbEdgeIterator GraphDbNode::edges() const {
  return GraphDbEdgeIterator(transaction(), nullptr);
}

base::StringPiece GraphDbNode::get_type() const {
  size_t len;
  char* data = graph_string(transaction()->handle(), node_handle()->type, &len);
  if (!data)
    return base::StringPiece();

  return base::StringPiece(data, len);
}

base::StringPiece GraphDbNode::get_value() const {
  size_t len;
  char* data = graph_string(transaction()->handle(), node_handle()->val, &len);
  if (!data)
    return base::StringPiece();

  return base::StringPiece(data, len);
}

GraphDbEdge::GraphDbEdge(GraphDbTransaction* transaction, edge_t handle): GraphDbEntry(transaction, reinterpret_cast<entry_t>(handle)) {}
GraphDbEdge::GraphDbEdge(): GraphDbEntry() {}
GraphDbEdge::~GraphDbEdge() {}

base::StringPiece GraphDbEdge::get_type() const {
  size_t len;
  char* data = graph_string(transaction()->handle(), edge_handle()->type, &len);
  if (!data)
    return base::StringPiece();

  return base::StringPiece(data, len);
}

base::StringPiece GraphDbEdge::get_value() const {
  size_t len;
  char* data = graph_string(transaction()->handle(), edge_handle()->val, &len);
  if (!data)
    return base::StringPiece();

  return base::StringPiece(data, len);
}

uint64_t GraphDbEdge::source_id() const {
  return edge_handle()->src;
}

uint64_t GraphDbEdge::target_id() const {
  return edge_handle()->tgt;
}

bool GraphDbEdge::get_source(GraphDbNode& node) const {
  node_t gnode = graph_node(transaction()->handle(), source_id());
  if (!gnode)
    return false;

  node.set_node_handle(gnode);
  node.set_transaction(transaction());
  return true;
}

bool GraphDbEdge::get_target(GraphDbNode& node) const {
  node_t gnode = graph_node(transaction()->handle(), target_id());
  if (!gnode)
    return false;

  node.set_node_handle(gnode);
  node.set_transaction(transaction());
  return true;
}

GraphDbProperty::GraphDbProperty(GraphDbTransaction* transaction, prop_t handle): GraphDbEntry(transaction, reinterpret_cast<entry_t>(handle)){}
GraphDbProperty::GraphDbProperty(): GraphDbEntry(){}
GraphDbProperty::~GraphDbProperty(){}

uint64_t GraphDbProperty::pid() const {
  return prop_handle()->pid;
}

base::StringPiece GraphDbProperty::get_key() const {
  size_t len;
  char* data = graph_string(transaction()->handle(), prop_handle()->key, &len);
  if (!data)
    return base::StringPiece();

  return base::StringPiece(data, len);
}

base::StringPiece GraphDbProperty::get_value() const {
  size_t len;
  char* data = graph_string(transaction()->handle(), prop_handle()->val, &len);
  if (!data)
    return base::StringPiece();

  return base::StringPiece(data, len);
}

}