// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_CONCEPT_CONCEPT_GRAPH_H_
#define MUMBA_DOMAIN_CONCEPT_CONCEPT_GRAPH_H_

#include "base/macros.h"
#include "base/callback.h"
#include "base/synchronization/waitable_event.h"
#include "core/shared/domain/storage/graph/graph_db.h"
#include "core/domain/concept/concept_node.h"

namespace domain {
//class ConceptNode;

class ConceptGraph {
public:
  ConceptGraph(GraphDb* db);
  ~ConceptGraph();

  bool Init();

  GraphDb* db() const {
    return db_;
  }

  void AddNode(ConceptNode* node, const base::Callback<void(bool)>& cb);
  void DeleteNode(ConceptNode* node, const base::Callback<void(bool)>& cb);
  void DeleteNode(uint64_t gid, const base::Callback<void(bool)>& cb);
  // sync
  bool FillAllNodes(ConceptNode::Delegate* delegate, std::vector<std::unique_ptr<ConceptNode>>* nodes);

private:

  void FillAllNodesImpl(ConceptNode::Delegate* delegate, std::vector<std::unique_ptr<ConceptNode>>* nodes, bool* result);
  bool AddNodeImpl(ConceptNode* node);
  bool DeleteNodeImpl(ConceptNode* node);
  bool DeleteNodeByIdImpl(uint64_t gid);
  
  GraphDb* db_;

  base::WaitableEvent db_sync_;

  DISALLOW_COPY_AND_ASSIGN(ConceptGraph);
};


}


#endif