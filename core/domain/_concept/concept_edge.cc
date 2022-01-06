// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/concept/concept_edge.h"

#include "core/domain/concept/concept_node.h"

namespace domain {

ConceptEdge::ConceptEdge() {

}

ConceptEdge::~ConceptEdge() {

}

ConceptNode* ConceptEdge::source() const {
  return nullptr;
}

ConceptNode* ConceptEdge::target() const {
  return nullptr;
}

void ConceptEdge::set_source(ConceptNode* node) {

}

void ConceptEdge::set_target(ConceptNode* node) {

}

}