// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_GRAPH_GRAPH_ENTRY_H_
#define MUMBA_HOST_GRAPH_GRAPH_ENTRY_H_

#include "base/macros.h"
#include "base/logging.h"
#include "core/common/proto/objects.pb.h"
#include "core/host/graph/graph_common.h"

namespace host {
class Graph;
class GraphNode;
class GraphEdge;
class GraphProperty;
class GraphTransaction;
class GraphTransactionBase;

class GraphEntryBase {
public:
  virtual ~GraphEntryBase();

  bool is_new() const {
    return is_new_;
  }

  void set_is_new(bool value) {
    is_new_ = value;
  }

  bool dirty() const {
    return dirty_;
  }

  void set_dirty(bool value) {
    dirty_ = value;
  }

  bool managed() const {
    return managed_;
  }

  void set_managed(bool value) {
    managed_ = value;
  }

  bool is_node() const {
    return kind() == protocol::GRAPH_NODE;
  }

  bool is_edge() const {
    return kind() == protocol::GRAPH_EDGE;
  }

  bool is_property() const {
    return kind() == protocol::GRAPH_PROPERTY;
  }

  template <class T> T* cast_as() {
    return static_cast<T*>(this);
  }


  GraphNode* as_node();
  GraphEdge* as_edge();
  GraphProperty* as_property();

  virtual GraphTransaction* transaction() const = 0;
  virtual graph_t id() const = 0;
  virtual void set_id(graph_t id) = 0;
  virtual protocol::GraphKind kind() const = 0;
  //virtual void set_kind(protocol::GraphKind kind) = 0;
  virtual graph_t next_id() const = 0;
  virtual void set_next_id(graph_t next) = 0;
  virtual bool Encode(std::string* out) const = 0;
  virtual bool EncodeIndex(std::string* out) const = 0;
  virtual bool Decode(const std::string& data) = 0;
  virtual bool DecodeIndex(const std::string& data) = 0;

protected:
  // avoid any way of direct instantiation as to not incur in 
  // cast troubles given the heap object being a Entry with a record 
  // to a subclass ta will think its ok to cast it, while the object
  // on the heap is actually a 'pure' GraphEntry
  GraphEntryBase();

private:
  friend class Graph;
  bool is_new_;
  bool dirty_;
  bool managed_;

  DISALLOW_COPY_AND_ASSIGN(GraphEntryBase);
};

class GraphEntry : public GraphEntryBase {
public:
  GraphEntry();
  GraphEntry(protocol::GraphEntry proto);
  ~GraphEntry() override;

  graph_t id() const override {
    return entry_proto_.id();
  }

  void set_id(graph_t id) override {
    entry_proto_.set_id(id);
  }

  protocol::GraphKind kind() const override {
    return entry_proto_.kind();
  }

  void set_kind(protocol::GraphKind kind) {
    entry_proto_.set_kind(kind);
  }

  graph_t next_id() const override {
    return entry_proto_.next();
  }

  void set_next_id(graph_t next) override {
    entry_proto_.set_next(next);
  }

  bool Encode(std::string* out) const override {
    DLOG(INFO) << "GraphEntry::Encode";
    return entry_proto_.SerializeToString(out);
  }

  bool EncodeIndex(std::string* out) const override;
  
  bool Decode(const std::string& data) override {
    DLOG(INFO) << "GraphEntry::Decode";
    return entry_proto_.ParseFromString(data);
  }

  bool DecodeIndex(const std::string& data) override;
  
private: 
  friend class Graph;
  friend class GraphTransactionBase;

  protocol::GraphEntry entry_proto_;

  DISALLOW_COPY_AND_ASSIGN(GraphEntry);
};

}

#endif