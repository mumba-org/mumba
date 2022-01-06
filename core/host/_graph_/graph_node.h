// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_GRAPH_GRAPH_NODE_H_
#define MUMBA_HOST_GRAPH_GRAPH_NODE_H_

#include "base/macros.h"
#include "core/host/graph/graph_entry.h"
#include "core/host/graph/graph_transaction.h"

namespace host {
class Graph;
class GraphNode : public GraphEntryBase {
public:
  ~GraphNode() override;

  GraphTransaction* transaction() const override {
    return transaction_;
  }

  graph_t id() const override {
    return node_proto_.id();
  }

  void set_id(graph_t new_id) override {
    graph_t old_id = id();
    node_proto_.set_id(new_id);
    set_dirty(old_id != id());
  }

  protocol::GraphKind kind() const override {
    return node_proto_.kind();
  }

  // void set_kind(protocol::GraphKind kind) override {
  //   node_proto_.set_kind(kind);
  // }

  graph_t next_id() const override {
    return node_proto_.next();
  }

  void set_next_id(graph_t new_next) override {
    graph_t old_next = next_id();
    node_proto_.set_next(new_next);
    set_dirty(old_next != next_id());
  }

  graph_t type_id() const {
    return node_proto_.type();
  }

  void set_type_id(graph_t new_type) {
    graph_t old_type = type_id();
    node_proto_.set_type(new_type);
    set_dirty(old_type != type_id());
  }

  graph_t value_id() const {
    return node_proto_.value();
  }

  void set_value_id(graph_t new_value) {
    graph_t old_value = value_id();
    node_proto_.set_value(new_value);
    set_dirty(old_value != value_id());
  }

  const std::string& type() {
    if (type_string_.empty() && managed() && type_id() > 0) {
      transaction_->GetBlob(type_id(), &type_string_);
    }
    return type_string_;
  }

  void set_type(const std::string& new_type) {
    std::string old_type = type_string_;
    type_string_ = new_type;
    set_dirty(type_string_ != old_type);
    // reset the type id if the source have changed
    if (dirty()) {
      graph_t new_type_id = 0;
      if (transaction_->ResolveBlob(&new_type_id, type_string_, false)) {
        node_proto_.set_type(new_type_id);
      }
    }
  }

  const std::string& value() {
    if (value_string_.empty() && managed() && value_id() > 0) {
      transaction_->GetBlob(value_id(), &value_string_);
    }
    return value_string_;
  }

  void set_value(const std::string& new_value) {
    std::string old_value = value_string_;
    value_string_ = new_value;
    set_dirty(value_string_ != old_value);
    // reset the value id if the source have changed
    if (dirty()) {
      graph_t new_value_id = 0;
      if (transaction_->ResolveBlob(&new_value_id, value_string_, false)) {
        node_proto_.set_value(new_value_id);
      }
    }
  }

  bool Encode(std::string* out) const override;
  bool EncodeIndex(std::string* out) const override;
  bool Decode(const std::string& data) override;
  bool DecodeIndex(const std::string& data) override;

private:
  friend class Graph;
  friend class GraphTransactionBase;

  GraphNode(GraphTransaction* transaction);
  GraphNode(GraphTransaction* transaction, protocol::GraphNode node_proto);
  
  GraphTransaction* transaction_;
  protocol::GraphNode node_proto_;
  std::string type_string_;
  std::string value_string_;
  
  DISALLOW_COPY_AND_ASSIGN(GraphNode);
};

}

#endif