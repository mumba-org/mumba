// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_GRAPH_GRAPH_SERIALIZABLE_H_
#define MUMBA_HOST_GRAPH_GRAPH_SERIALIZABLE_H_

#include "base/macros.h"

namespace host {
class GraphNode;
class GraphTransaction;

class GraphSerializable {
public:
 virtual ~GraphSerializable() {}
 virtual GraphNode* AsNode(GraphTransaction* tr) = 0;
};

}

#endif