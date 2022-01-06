// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/graph/graph_entry.h"

#include "core/host/graph/graph_edge.h"
#include "core/host/graph/graph_node.h"
#include "core/host/graph/graph_property.h"

namespace host {

GraphEntryBase::GraphEntryBase(): is_new_(true), dirty_(false), managed_(false) {
    
}

GraphEntryBase::~GraphEntryBase() {

}

GraphNode* GraphEntryBase::as_node() {
  return static_cast<GraphNode*>(this);
}

GraphEdge* GraphEntryBase::as_edge() {
  return static_cast<GraphEdge*>(this);
}

GraphProperty* GraphEntryBase::as_property() {
  return static_cast<GraphProperty*>(this);
}

GraphEntry::GraphEntry() {
  entry_proto_.set_id(kInvalidGraphId);
  entry_proto_.set_next(kInvalidGraphId);
}

GraphEntry::GraphEntry(protocol::GraphEntry proto): GraphEntryBase(), entry_proto_(proto) {
  
}

GraphEntry::~GraphEntry() {

}

bool GraphEntry::EncodeIndex(std::string* out) const {
  // we should never try to index a 'pure' entry
  // if this is being called theres something wrong
  DCHECK(false);
  return Encode(out);
}

bool GraphEntry::DecodeIndex(const std::string& data) {
  // we should never try to index a 'pure' entry
  // if this is being called theres something wrong
  DCHECK(false);
  return Decode(data);
}

}