// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_NAMESPACE_GRAPH_GRAPH_ENTRY_H_
#define MUMBA_DOMAIN_NAMESPACE_GRAPH_GRAPH_ENTRY_H_

#include "base/strings/string_piece.h"
#include "core/shared/domain/storage/graph/graph_db_iterator.h"
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
#include "core/shared/domain/storage/graph/lemongraph.h"
#pragma clang diagnostic push

namespace domain {
class GraphDbNode;
class DbTransaction;

enum class GraphDbType : uint8_t {
  Deletion = GRAPH_DELETION,
  Node = GRAPH_NODE,
  Edge = GRAPH_EDGE,
  Property = GRAPH_PROP
};

// always use on stack.. cheap copy constructible
class GraphDbEntry {
public:
  static GraphDbEntry Cast(GraphDbTransaction* transaction, entry_t handle) {
    return GraphDbEntry(transaction, handle);
  }

  GraphDbEntry(GraphDbTransaction* transaction, entry_t handle);
  GraphDbEntry();
  virtual ~GraphDbEntry();

  GraphDbEntry(const GraphDbEntry &other) {
    handle_ = other.handle_;
    transaction_ = other.transaction_;
  }

  template <class T> T CastAs() {
    return T::Cast(transaction(), *this);
  }
  
  uint64_t id() const;
  GraphDbType type() const;
  bool is_new() const;
  uint64_t next() const;

  bool is_null() const {
    return handle_ == nullptr;
  }

  entry_t handle() const {
    return handle_;
  }

  void set_handle(entry_t handle) {
    handle_ = handle;
  }

  GraphDbTransaction* transaction() const {
    return transaction_;
  }

  void set_transaction(GraphDbTransaction* transaction) {
    transaction_ = transaction;
  }

private:
  GraphDbTransaction* transaction_;
  entry_t handle_;
};

// always use on stack.. cheap copy constructible
class GraphDbEdge : public GraphDbEntry {
public:
  
  static GraphDbType Type() {
    return GraphDbType::Edge;
  }

  static GraphDbEdge Cast(GraphDbTransaction* transaction, entry_t handle) {
    DCHECK(handle->rectype == static_cast<uint8_t>(Type()));
    return GraphDbEdge(transaction, reinterpret_cast<edge_t>(handle));
  }

  static GraphDbEdge Cast(GraphDbTransaction* transaction, GraphDbEntry entry) {
    DCHECK(entry.type() == Type());
    return GraphDbEdge(transaction, reinterpret_cast<edge_t>(entry.handle()));
  }

  GraphDbEdge(GraphDbTransaction* transaction, edge_t handle);
  GraphDbEdge();
  ~GraphDbEdge() override;

  edge_t edge_handle() const {
    return reinterpret_cast<edge_t>(handle());
  }

  void set_edge_handle(edge_t handle) {
    set_handle(reinterpret_cast<entry_t>(handle));
  }

  base::StringPiece get_type() const;
  base::StringPiece get_value() const;

  uint64_t source_id() const;
  
  uint64_t target_id() const;

  bool get_source(GraphDbNode& node) const;
  bool get_target(GraphDbNode& node) const;

};

// always use on stack.. cheap copy constructible
class GraphDbProperty : public GraphDbEntry {
public:
  
  static GraphDbType Type() {
    return GraphDbType::Property;
  }

  static GraphDbProperty Cast(GraphDbTransaction* transaction, entry_t handle) {
    DCHECK(handle->rectype == static_cast<uint8_t>(Type()));
    return GraphDbProperty(transaction, reinterpret_cast<prop_t>(handle));
  }

  static GraphDbProperty Cast(GraphDbTransaction* transaction, GraphDbEntry entry) {
    DCHECK(entry.type() == Type());
    return GraphDbProperty(transaction, reinterpret_cast<prop_t>(entry.handle()));
  }

  GraphDbProperty(GraphDbTransaction* transaction, prop_t handle);
  GraphDbProperty();
  ~GraphDbProperty() override;

  prop_t prop_handle() const {
    return reinterpret_cast<prop_t>(handle());
  }

  void set_prop_handle(prop_t handle) {
    set_handle(reinterpret_cast<entry_t>(handle));
  }

  uint64_t pid() const;

  base::StringPiece get_key() const;
  base::StringPiece get_value() const;

};

using GraphDbEntryIterator = GraphDbIterator<GraphDbEntry>;
using GraphDbEdgeIterator = GraphDbIterator<GraphDbEdge>;
using GraphDbPropertyIterator = GraphDbIterator<GraphDbProperty>;

// always use on stack.. cheap copy constructible
class GraphDbNode : public GraphDbEntry {
public:

  static GraphDbType Type() {
    return GraphDbType::Node;
  }
  
  static GraphDbNode Cast(GraphDbTransaction* transaction, entry_t handle) {
    DCHECK(handle->rectype == static_cast<uint8_t>(Type()));
    return GraphDbNode(transaction, reinterpret_cast<node_t>(handle));
  }

  static GraphDbNode Cast(GraphDbTransaction* transaction, GraphDbEntry entry) {
    DCHECK(entry.type() == Type());
    return GraphDbNode(transaction, reinterpret_cast<node_t>(entry.handle()));
  }

  GraphDbNode(GraphDbTransaction* transaction, node_t handle);
  GraphDbNode();
  ~GraphDbNode() override;

  node_t node_handle() const {
    return reinterpret_cast<node_t>(handle());
  }

  void set_node_handle(node_t handle) {
    set_handle(reinterpret_cast<entry_t>(handle)); 
  }

  base::StringPiece get_type() const;
  base::StringPiece get_value() const;

  GraphDbPropertyIterator properties() const;
  GraphDbEdgeIterator edges() const;

};

using GraphDbNodeIterator = GraphDbIterator<GraphDbNode>;

}

#endif