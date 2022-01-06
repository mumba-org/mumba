// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_GRAPH_GRAPH_CODEC_H_
#define MUMBA_HOST_GRAPH_GRAPH_CODEC_H_

#include "base/macros.h"
#include "core/common/proto/objects.pb.h"
#include "core/host/graph/graph_common.h"

namespace host {
class GraphEntry;
class GraphNode;
class GraphEdge;
class GraphProperty;

class GraphCodec {
public:
  static std::string EncodeInt(int32_t i);
  static std::string EncodeInt(uint64_t i);
  static std::string EncodeBlobHash(const std::string& blob);
  
  static std::string EncodeEntry(const GraphEntry& entry);
  static std::string EncodeNode(const GraphNode& node);
  static std::string EncodeProperty(const GraphProperty& property);
  static std::string EncodeEdge(const GraphEdge& edge);

  static graph_t DecodeId(const std::string& data);
  static uint64_t DecodeInt(const std::string& data);
  static protocol::GraphKind PeekType(const std::string& data);
  //static bool DecodeInt(const std::string& data, int32_t* out);
};

}

#endif