// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/graph/graph_property.h"

#include "storage/db/sqlite3.h"
#include "storage/db/sqliteInt.h"

namespace host {

GraphProperty::GraphProperty(GraphTransaction* transaction): 
  transaction_(transaction),
  parent_(nullptr) {
  property_proto_.set_id(kInvalidGraphId);
  property_proto_.set_next(kInvalidGraphId);
  property_proto_.set_key(kInvalidGraphId);
  property_proto_.set_value(kInvalidGraphId);
  property_proto_.set_pid(kInvalidGraphId);
  property_proto_.set_kind(protocol::GRAPH_PROPERTY);
}

GraphProperty::GraphProperty(GraphTransaction* transaction, protocol::GraphProperty property_proto): 
  transaction_(transaction),
  parent_(nullptr), 
  property_proto_(property_proto) {
    
}

GraphProperty::~GraphProperty() {

}


bool GraphProperty::Encode(std::string* out) const {
  //return property_proto_.SerializeToString(out);
  //GraphKind kind = 1;
  //uint64 next = 2;
  //uint64 pid = 3;
  //uint64 key = 4;
  //uint64 value = 5;
  //uint64 id = 6;
  int size = csqliteVarintLen(id()) * 6;
  uint8_t data[size];
  uint8_t* ptr = &data[0];
  ptr += csqlitePutVarint(ptr, kind());
  ptr += csqlitePutVarint(ptr, next_id());
  ptr += csqlitePutVarint(ptr, parent_id());
  ptr += csqlitePutVarint(ptr, key_id());
  ptr += csqlitePutVarint(ptr, value_id());
  ptr += csqlitePutVarint(ptr, id());
  out->assign(reinterpret_cast<const char *>(&data[0]), size);
  return true;
}

bool GraphProperty::EncodeIndex(std::string* out) const {
  int int_sizes = csqliteVarintLen(id()) * 3;
  int size = int_sizes;//csqliteVarintLen(int_sizes) + int_sizes;
  uint8_t data[size];
  uint8_t* ptr = &data[0];
  //ptr += csqlitePutVarint(ptr, int_sizes);
  ptr += csqlitePutVarint(ptr, parent_id());
  ptr += csqlitePutVarint(ptr, key_id());
  ptr += csqlitePutVarint(ptr, id());
  out->assign(reinterpret_cast<const char *>(&data[0]), size);
  return true;
}

bool GraphProperty::Decode(const std::string& data) {
  //return property_proto_.ParseFromString(data);
  
  //GraphKind kind = 1;
  //uint64 next = 2;
  //uint64 pid = 3;
  //uint64 key = 4;
  //uint64 value = 5;
  //uint64 id = 6;
  
  graph_t kind, next, pid, key, value, id;

  if (data.empty()) {
    return false;
  }

  uint8_t const* buf = reinterpret_cast<uint8_t const*>(data.data());
  
  buf += csqliteGetVarint(buf, (u64*)&kind);
  buf += csqliteGetVarint(buf, (u64*)&next);
  buf += csqliteGetVarint(buf, (u64*)&pid);
  buf += csqliteGetVarint(buf, (u64*)&key);
  buf += csqliteGetVarint(buf, (u64*)&value);
  buf += csqliteGetVarint(buf, (u64*)&id);

  DCHECK(kind == protocol::GRAPH_PROPERTY);

  set_id(id);
  set_next_id(next);
  set_key_id(key);
  set_value_id(value);
  set_parent_id(pid);

  return true;
}

bool GraphProperty::DecodeIndex(const std::string& data) {
  graph_t pid, key, id;

  if (data.empty()) {
    return false;
  }

  uint8_t const* buf = reinterpret_cast<uint8_t const*>(data.data());
  //buf += csqliteGetVarint(buf, (u64*)&int_sizes);

  //if (int_sizes != expected_size) {
  //  DLOG(ERROR) << "GraphEdge::DecodeIndex: sizes dont match: recovered: " << int_sizes << " expected: " << expected_size;
  //  return false;
  //}

  buf += csqliteGetVarint(buf, (u64*)&pid);
  buf += csqliteGetVarint(buf, (u64*)&key);
  buf += csqliteGetVarint(buf, (u64*)&id);

  set_parent_id(pid);
  set_key_id(key);
  set_id(id);

  return true;
}

}