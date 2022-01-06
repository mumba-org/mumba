// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/graph/graph_common.h"

namespace host {

std::vector<std::string> kGraphKeyspaceNames = {
  "blob",
  "blob_index",
  "entry",
  "node_index",
  "edge_index",
  "property_index",
  "source_node_index",
  "target_node_index",
  "kv",
  "transaction_log"
};

std::unordered_map<GraphKeyspace, std::string> kGraphKeyspaces = {
  // strID_t strID => bytes (append-only)
  {GraphKeyspace::BLOB, kGraphKeyspaceNames[0]},
  // uint32_t crc => strID_t strIDs[]
  {GraphKeyspace::BLOB_INDEX, kGraphKeyspaceNames[1]},
  // varint_t logID => entry_t (appends & updates)
  {GraphKeyspace::ENTRY, kGraphKeyspaceNames[2]},
  // varint_t [type, val, logID] => ''
  {GraphKeyspace::NODE_INDEX, kGraphKeyspaceNames[3]},
  // varint_t [type, val, src, tgt, logID]
  {GraphKeyspace::EDGE_INDEX, kGraphKeyspaceNames[4]},
  // varint_t pid, key, logID => ''
  {GraphKeyspace::PROPERTY_INDEX, kGraphKeyspaceNames[5]},
  // varint_t node, type, edge => ''
  {GraphKeyspace::SOURCE_NODE_INDEX, kGraphKeyspaceNames[6]},
  // varint_t node, type, edge => ''
  {GraphKeyspace::TARGET_NODE_INDEX, kGraphKeyspaceNames[7]},
  // varint_t domain, key => varint_t val
  {GraphKeyspace::KV, kGraphKeyspaceNames[8]},
  // varint_t [txnID, start, count] => varint_t [node_count, edge_count] (append only)
  {GraphKeyspace::TRANSACTION_LOG, kGraphKeyspaceNames[9]}
};


}