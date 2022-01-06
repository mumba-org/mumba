// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/graph/graph_edge.h"

#include "storage/db/sqlite3.h"
#include "storage/db/sqliteInt.h"

namespace host {

GraphEdge::GraphEdge(GraphTransaction* transaction): 
  transaction_(transaction),
  source_(nullptr), 
  target_(nullptr) {
  edge_proto_.set_id(kInvalidGraphId);
  edge_proto_.set_next(kInvalidGraphId);
  edge_proto_.set_type(kInvalidGraphId);
  edge_proto_.set_value(kInvalidGraphId);
  edge_proto_.set_source(kInvalidGraphId);
  edge_proto_.set_target(kInvalidGraphId);
  edge_proto_.set_kind(protocol::GRAPH_EDGE);
}

GraphEdge::GraphEdge(GraphTransaction* transaction, protocol::GraphEdge proto): 
  transaction_(transaction),
  source_(nullptr), 
  target_(nullptr), 
  edge_proto_(std::move(proto)) {
  
}

GraphEdge::~GraphEdge() {

}

bool GraphEdge::Encode(std::string* out) const {
  //DLOG(INFO) << "GraphEdge::Encode";
  //return edge_proto_.SerializeToString(out);
  
  // GraphKind kind = 1;
  // uint64 next = 2;
  // uint64 type = 3;
  // uint64 value = 4;
  // uint64 source = 5;
  // uint64 target = 6;
  // uint64 id = 7;

  int size = csqliteVarintLen(id()) * 7;
  uint8_t data[size];
  uint8_t* ptr = &data[0];
  ptr += csqlitePutVarint(ptr, kind());
  ptr += csqlitePutVarint(ptr, next_id());
  ptr += csqlitePutVarint(ptr, type_id());
  ptr += csqlitePutVarint(ptr, value_id());
  ptr += csqlitePutVarint(ptr, source_id());
  ptr += csqlitePutVarint(ptr, target_id());
  ptr += csqlitePutVarint(ptr, id());
  out->assign(reinterpret_cast<const char *>(&data[0]), size);
  return true;
}

bool GraphEdge::EncodeIndex(std::string* out) const {
  const int fields = 5;
  int int_sizes = csqliteVarintLen(id()) * fields;
  int size = int_sizes;//csqliteVarintLen(int_sizes) + int_sizes;
  uint8_t data[size];
  uint8_t* ptr = &data[0];

  //ptr += csqlitePutVarint(ptr, int_sizes);
  ptr += csqlitePutVarint(ptr, type_id());
  ptr += csqlitePutVarint(ptr, value_id());
  ptr += csqlitePutVarint(ptr, source_id());
  ptr += csqlitePutVarint(ptr, target_id());
  ptr += csqlitePutVarint(ptr, id());
  
  out->assign(reinterpret_cast<const char *>(&data[0]), size);
  return true;
}

bool GraphEdge::DecodeIndex(const std::string& data) {
  //int int_sizes = 0;
  //const int expected_size = csqliteVarintLen(id()) * 5;
  graph_t type, value, source, target, id;

  if (data.empty()) {
    return false;
  }

  uint8_t const* buf = reinterpret_cast<uint8_t const*>(data.data());
  // buf += csqliteGetVarint(buf, (u64*)&int_sizes);

  // if (int_sizes != expected_size) {
  //   DLOG(ERROR) << "GraphEdge::DecodeIndex: sizes dont match: recovered: " << int_sizes << " expected: " << expected_size;
  //   return false;
  // }

  buf += csqliteGetVarint(buf, (u64*)&type);
  buf += csqliteGetVarint(buf, (u64*)&value);
  buf += csqliteGetVarint(buf, (u64*)&source);
  buf += csqliteGetVarint(buf, (u64*)&target);
  buf += csqliteGetVarint(buf, (u64*)&id);

  set_id(id);
  set_type_id(type);
  set_value_id(value);
  set_source_id(source);
  set_target_id(target);

  return true;
}

bool GraphEdge::EncodeTargetIndex(std::string* out) const {
  int int_sizes = csqliteVarintLen(id()) * 3;
  int size = int_sizes;//csqliteVarintLen(int_sizes) + int_sizes;
  uint8_t data[size];
  uint8_t* ptr = &data[0];
  //ptr += csqlitePutVarint(ptr, int_sizes);
  ptr += csqlitePutVarint(ptr, target_id());
  ptr += csqlitePutVarint(ptr, type_id());
  ptr += csqlitePutVarint(ptr, id());
  out->assign(reinterpret_cast<const char *>(&data[0]), size);
  return true;
}

bool GraphEdge::Decode(const std::string& data) {
  //DLOG(INFO) << "GraphEdge::Decode";
  //return edge_proto_.ParseFromString(data);

  // GraphKind kind = 1;
  // uint64 next = 2;
  // uint64 type = 3;
  // uint64 value = 4;
  // uint64 source = 5;
  // uint64 target = 6;
  // uint64 id = 7;

  graph_t kind, next, type, value, source, target, id;

  if (data.empty()) {
    return false;
  }

  uint8_t const* buf = reinterpret_cast<uint8_t const*>(data.data());
  
  buf += csqliteGetVarint(buf, (u64*)&kind);
  buf += csqliteGetVarint(buf, (u64*)&next);
  buf += csqliteGetVarint(buf, (u64*)&type);
  buf += csqliteGetVarint(buf, (u64*)&value);
  buf += csqliteGetVarint(buf, (u64*)&source);
  buf += csqliteGetVarint(buf, (u64*)&target);
  buf += csqliteGetVarint(buf, (u64*)&id);

  DCHECK(kind == protocol::GRAPH_EDGE);

  set_id(id);
  set_next_id(next);
  set_type_id(type);
  set_value_id(value);
  set_source_id(source);
  set_target_id(target);

  return true;
}

bool GraphEdge::DecodeTargetIndex(const std::string& data) {
  //int int_sizes = 0;
  //const int expected_size = csqliteVarintLen(id()) * 3;
  graph_t type, target, id;

  if (data.empty()) {
    return false;
  }

  uint8_t const* buf = reinterpret_cast<uint8_t const*>(data.data());
  //buf += csqliteGetVarint(buf, (u64*)&int_sizes);

  //if (int_sizes != expected_size) {
  //  DLOG(ERROR) << "GraphEdge::DecodeIndex: sizes dont match: recovered: " << int_sizes << " expected: " << expected_size;
  //  return false;
  //}

  buf += csqliteGetVarint(buf, (u64*)&target);
  buf += csqliteGetVarint(buf, (u64*)&type);
  buf += csqliteGetVarint(buf, (u64*)&id);

  set_id(id);
  set_type_id(type);
  set_target_id(target);

  return true;
}

bool GraphEdge::EncodeSourceIndex(std::string* out) const {
  int int_sizes = csqliteVarintLen(id()) * 3;
  int size = int_sizes;//csqliteVarintLen(int_sizes) + int_sizes;
  uint8_t data[size];
  uint8_t* ptr = &data[0];
  //ptr += csqlitePutVarint(ptr, int_sizes);
  ptr += csqlitePutVarint(ptr, source_id());
  ptr += csqlitePutVarint(ptr, type_id());
  ptr += csqlitePutVarint(ptr, id());
  out->assign(reinterpret_cast<const char *>(&data[0]), size);
  return true;
}

bool GraphEdge::DecodeSourceIndex(const std::string& data) {
  //int int_sizes = 0;
  //const int expected_size = csqliteVarintLen(id()) * 3;
  graph_t type, source, id;

  if (data.empty()) {
    return false;
  }

  uint8_t const* buf = reinterpret_cast<uint8_t const*>(data.data());
  //buf += csqliteGetVarint(buf, (u64*)&int_sizes);

  //if (int_sizes != expected_size) {
  //  DLOG(ERROR) << "GraphEdge::DecodeIndex: sizes dont match: recovered: " << int_sizes << " expected: " << expected_size;
  //  return false;
  //}

  buf += csqliteGetVarint(buf, (u64*)&source);
  buf += csqliteGetVarint(buf, (u64*)&type);
  buf += csqliteGetVarint(buf, (u64*)&id);

  set_id(id);
  set_type_id(type);
  set_source_id(source);

  return true;
}

}