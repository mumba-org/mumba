// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_GRAPH_GRAPH_EDGE_H_
#define MUMBA_HOST_GRAPH_GRAPH_EDGE_H_

#include "base/macros.h"
#include "core/host/graph/graph_entry.h"
#include "core/host/graph/graph_transaction.h"

namespace host {

class GraphEdge : public GraphEntryBase {
public:
  ~GraphEdge() override;

  GraphTransaction* transaction() const override {
    return transaction_;
  }

  graph_t id() const override {
    return edge_proto_.id();
  }

  void set_id(graph_t new_id) override {
    graph_t old_id = id();
    edge_proto_.set_id(new_id);
    set_dirty(old_id != id());
  }

  protocol::GraphKind kind() const override {
    return edge_proto_.kind();
  }

  // void set_kind(protocol::GraphKind kind) override {
  //   edge_proto_.set_kind(kind);
  // }

  graph_t next_id() const override {
    return edge_proto_.next();
  }

  void set_next_id(graph_t new_next) override {
    graph_t old_next = next_id();
    edge_proto_.set_next(new_next);
    set_dirty(old_next != next_id());
  }

  graph_t type_id() const {
    return edge_proto_.type();
  }

  void set_type_id(graph_t new_type) {
    graph_t old_type = type_id();
    edge_proto_.set_type(new_type);
    set_dirty(old_type != type_id());
  }

  graph_t value_id() const {
    return edge_proto_.value();
  }

  void set_value_id(graph_t new_value) {
    graph_t old_value = value_id();
    edge_proto_.set_value(new_value);
    set_dirty(old_value != value_id());
  }

  GraphEntryBase* source() const {
    return source_;
  }

  void set_source(GraphEntryBase* source) {
    source_ = source;
    set_source_id(source->id());
  }

  graph_t source_id() const {
    return edge_proto_.source();
  }

  void set_source_id(graph_t new_source) {
    graph_t old_source = source_id();
    edge_proto_.set_source(new_source);
    set_dirty(old_source != source_id());
  }

  GraphEntryBase* target() const {
    return target_;
  }

  void set_target(GraphEntryBase* target) {
    target_ = target;
    set_target_id(target->id());
  }

  graph_t target_id() const {
    return edge_proto_.target();
  }

  void set_target_id(graph_t new_target) {
    graph_t old_target = target_id();
    edge_proto_.set_target(new_target);
    set_dirty(target_id() != old_target);
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
        edge_proto_.set_type(new_type_id);
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
        edge_proto_.set_value(new_value_id);
      }
    }
  }

  bool Encode(std::string* out) const override;
  bool EncodeIndex(std::string* out) const override;
  bool Decode(const std::string& data) override;
  bool DecodeIndex(const std::string& data) override;
  bool EncodeTargetIndex(std::string* out) const;
  bool DecodeTargetIndex(const std::string& data);
  bool EncodeSourceIndex(std::string* out) const;
  bool DecodeSourceIndex(const std::string& data);
  
private:
  friend class Graph;
  friend class GraphTransactionBase;

  GraphEdge(GraphTransaction* transaction);
  GraphEdge(GraphTransaction* transaction, protocol::GraphEdge proto);
  

  GraphTransaction* transaction_;
  GraphEntryBase* source_;
  GraphEntryBase* target_;
  protocol::GraphEdge edge_proto_;
  std::string type_string_;
  std::string value_string_;

  DISALLOW_COPY_AND_ASSIGN(GraphEdge);
};

}

#endif