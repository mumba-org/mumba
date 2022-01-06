// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/graph/graph_node.h"

#include "storage/db/sqlite3.h"
#include "storage/db/sqliteInt.h"

namespace host {

GraphNode::GraphNode(GraphTransaction* transaction): transaction_(transaction) {
  node_proto_.set_id(kInvalidGraphId);
  node_proto_.set_next(kInvalidGraphId);
  node_proto_.set_type(kInvalidGraphId);
  node_proto_.set_value(kInvalidGraphId);
  node_proto_.set_kind(protocol::GRAPH_NODE);
}

GraphNode::GraphNode(GraphTransaction* transaction, protocol::GraphNode node_proto): GraphEntryBase(), 
  transaction_(transaction),
  node_proto_(std::move(node_proto)) {

}

GraphNode::~GraphNode() {

}

bool GraphNode::Encode(std::string* out) const {
  //DLOG(INFO) << "GraphNode::Encode";
  //return node_proto_.SerializeToString(out);
  
  // GraphKind kind = 1;
  // uint64 next = 2;
  // uint64 type = 3;
  // uint64 value = 4;
  // uint64 id = 5;

  int size = csqliteVarintLen(id()) * 5;
  uint8_t data[size];
  uint8_t* ptr = &data[0];
  ptr += csqlitePutVarint(ptr, kind());
  ptr += csqlitePutVarint(ptr, next_id());
  ptr += csqlitePutVarint(ptr, type_id());
  ptr += csqlitePutVarint(ptr, value_id());
  ptr += csqlitePutVarint(ptr, id());
  out->assign(reinterpret_cast<const char *>(&data[0]), size);
  return true;
}

bool GraphNode::EncodeIndex(std::string* out) const {
  const int fields = 3;
  int int_sizes = csqliteVarintLen(id()) * fields;
  int size = int_sizes;//csqliteVarintLen(int_sizes) + int_sizes;
  uint8_t data[size];
  uint8_t* ptr = &data[0];
  //ptr += csqlitePutVarint(ptr, int_sizes);
  ptr += csqlitePutVarint(ptr, type_id());
  ptr += csqlitePutVarint(ptr, value_id());
  ptr += csqlitePutVarint(ptr, id());
  out->assign(reinterpret_cast<const char *>(&data[0]), size);
  return true;
}

bool GraphNode::Decode(const std::string& data) {
  //DLOG(INFO) << "GraphNode::Decode";
  //return node_proto_.ParseFromString(data);

  // GraphKind kind = 1;
  // uint64 next = 2;
  // uint64 type = 3;
  // uint64 value = 4;
  // uint64 id = 5;

  graph_t kind, next, type, value, id;

  if (data.empty()) {
    return false;
  }

  uint8_t const* buf = reinterpret_cast<uint8_t const*>(data.data());
  
  buf += csqliteGetVarint(buf, (u64*)&kind);
  buf += csqliteGetVarint(buf, (u64*)&next);
  buf += csqliteGetVarint(buf, (u64*)&type);
  buf += csqliteGetVarint(buf, (u64*)&value);
  buf += csqliteGetVarint(buf, (u64*)&id);

  DCHECK(kind == protocol::GRAPH_NODE);

  set_id(id);
  set_next_id(next);
  set_type_id(type);
  set_value_id(value);
  
  return true;
} 

bool GraphNode::DecodeIndex(const std::string& data) {
  //int int_sizes = 0;
  //const int expected_size = csqliteVarintLen(id()) * 3;
  graph_t type, value, id;

  if (data.empty()) {
    return false;
  }

  uint8_t const* buf = reinterpret_cast<uint8_t const*>(data.data());
  //buf += csqliteGetVarint(buf, (u64*)&int_sizes);

  //if (int_sizes != expected_size) {
  //  DLOG(ERROR) << "GraphEdge::DecodeIndex: sizes dont match: recovered: " << int_sizes << " expected: " << expected_size;
  //  return false;
  //}

  buf += csqliteGetVarint(buf, (u64*)&type);
  buf += csqliteGetVarint(buf, (u64*)&value);
  buf += csqliteGetVarint(buf, (u64*)&id);

  set_id(id);
  set_type_id(type);
  set_value_id(value);

  return true;
}

}