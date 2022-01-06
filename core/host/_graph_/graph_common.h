// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_GRAPH_GRAPH_COMMON_H_
#define MUMBA_HOST_GRAPH_GRAPH_COMMON_H_

#include <unordered_map>
#include <vector>
#include <string>
#include <limits>

namespace host {

using graph_t = uint64_t;

constexpr graph_t kInvalidGraphId = 0;//std::numeric_limits<uint64_t>::max();

enum class GraphKeyspace : int {
    BLOB = 0,
    BLOB_INDEX = 1,
    ENTRY = 2,
    NODE_INDEX = 3,
    EDGE_INDEX = 4,
    PROPERTY_INDEX = 5,
    SOURCE_NODE_INDEX = 6,
    TARGET_NODE_INDEX = 7,
    KV = 8,
    TRANSACTION_LOG = 9,
    kKEYSPACE_MAX
};

extern std::unordered_map<GraphKeyspace, std::string> kGraphKeyspaces;
extern std::vector<std::string> kGraphKeyspaceNames;

}

#endif