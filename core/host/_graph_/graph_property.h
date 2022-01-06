// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_GRAPH_GRAPH_PROPERTY_H_
#define MUMBA_HOST_GRAPH_GRAPH_PROPERTY_H_

#include "base/macros.h"
#include "core/host/graph/graph_entry.h"
#include "core/host/graph/graph_transaction.h"

namespace host {

class GraphProperty : public GraphEntryBase {
public:
  ~GraphProperty() override;

  GraphTransaction* transaction() const override {
    return transaction_;
  }

  graph_t id() const override {
    return property_proto_.id();
  }

  void set_id(graph_t new_id) override {
    graph_t old_id = id();
    property_proto_.set_id(new_id);
    set_dirty(old_id != id());
  }

  protocol::GraphKind kind() const override {
    return property_proto_.kind();
  }

  // void set_kind(protocol::GraphKind kind) override {
  //   property_proto_.set_kind(kind);
  // }

  graph_t next_id() const override {
    return property_proto_.next();
  }

  void set_next_id(graph_t new_next) override {
    graph_t old_next = next_id();
    property_proto_.set_next(new_next);
    set_dirty(old_next != next_id());
  }

  graph_t key_id() const {
    return property_proto_.key();
  }

  void set_key_id(graph_t new_key) {
    graph_t old_key = key_id();
    property_proto_.set_key(new_key);
    set_dirty(old_key != key_id());
  }

  graph_t value_id() const {
    return property_proto_.value();
  }

  void set_value_id(graph_t new_value) {
    graph_t old_value = value_id();
    property_proto_.set_value(new_value);
    set_dirty(old_value != value_id());
  }

  GraphEntryBase* parent() const {
    return parent_;
  }

  void set_parent(GraphEntryBase* parent) {
    parent_ = parent;
    set_parent_id(parent->id());
  }

  graph_t parent_id() const {
    return property_proto_.pid();
  }

  void set_parent_id(graph_t new_pid) {
    graph_t old_parent = parent_id();
    property_proto_.set_pid(new_pid);
    set_dirty(old_parent != parent_id());
  }

  const std::string& key() {
    if (key_string_.empty() && managed() && key_id() > 0) {
      transaction_->GetBlob(key_id(), &key_string_);
    }
    return key_string_;
  }

  void set_key(const std::string& new_key) {
    std::string old_key = key_string_;
    key_string_ = new_key;
    set_dirty(key_string_ != old_key);
    // reset the key id if the source have changed
    if (dirty()) {
      graph_t new_key_id = 0;
      if (transaction_->ResolveBlob(&new_key_id, key_string_, false)) {
        property_proto_.set_key(new_key_id);
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
        property_proto_.set_value(new_value_id);
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

  GraphProperty(GraphTransaction* transaction);
  GraphProperty(GraphTransaction* transaction, protocol::GraphProperty property_proto);
  
  GraphTransaction* transaction_;
  GraphEntryBase* parent_;
  protocol::GraphProperty property_proto_;
  std::string key_string_;
  std::string value_string_;

  DISALLOW_COPY_AND_ASSIGN(GraphProperty);
};

}

#endif