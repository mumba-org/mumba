// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/concept/concept_graph.h"

#include "base/threading/thread_restrictions.h"
#include "base/task_scheduler/post_task.h"
#include "base/single_thread_task_runner.h"
#include "base/task_runner_util.h"
#include "core/domain/concept/concept_node.h"

namespace domain { 

ConceptGraph::ConceptGraph(GraphDb* db): 
  db_(db),
  db_sync_(
    base::WaitableEvent::ResetPolicy::AUTOMATIC, 
    base::WaitableEvent::InitialState::NOT_SIGNALED) {

}

ConceptGraph::~ConceptGraph() {

}

bool ConceptGraph::Init() {
  return true;
}

void ConceptGraph::AddNode(ConceptNode* node, const base::Callback<void(bool)>& cb) {
  //base::PostTaskWithTraitsAndReplyWithResult(
  base::PostTaskAndReplyWithResult(
    db_->task_runner(),
    FROM_HERE,
 //   { base::MayBlock() },
     base::BindOnce(
       &ConceptGraph::AddNodeImpl,
       base::Unretained(this),
       base::Unretained(node)),
     base::BindOnce(cb));
}

void ConceptGraph::DeleteNode(ConceptNode* node, const base::Callback<void(bool)>& cb) {
  //base::PostTaskWithTraitsAndReplyWithResult(
  base::PostTaskAndReplyWithResult(
    db_->task_runner(),
    FROM_HERE,
    //{ base::MayBlock() },
     base::Bind(&ConceptGraph::DeleteNodeImpl,
       base::Unretained(this),
       base::Unretained(node)),
     cb);
}

void ConceptGraph::DeleteNode(uint64_t gid, const base::Callback<void(bool)>& cb) {
  //base::PostTaskWithTraitsAndReplyWithResult(
  base::PostTaskAndReplyWithResult(
    db_->task_runner(),
    FROM_HERE,
    //{ base::MayBlock() },
     base::Bind(&ConceptGraph::DeleteNodeByIdImpl,
       base::Unretained(this),
       gid),
     cb);
}

bool ConceptGraph::FillAllNodes(ConceptNode::Delegate* delegate, std::vector<std::unique_ptr<ConceptNode>>* nodes) {
  base::ScopedAllowBaseSyncPrimitivesForTesting allow_wait;

  bool result = false;

  if (db_->task_runner()->PostTask(
    FROM_HERE,
    base::Bind(&ConceptGraph::FillAllNodesImpl,
      base::Unretained(this),
      base::Unretained(delegate),
      base::Unretained(nodes),
      base::Unretained(&result))
  )) {
    db_sync_.Wait();
  }

  return result;
}

void ConceptGraph::FillAllNodesImpl(ConceptNode::Delegate* delegate, std::vector<std::unique_ptr<ConceptNode>>* nodes, bool* result) {
  size_t name_sz = 0;
  char* name_data = nullptr;

  size_t type_sz = 0;
  char* type_data = nullptr;    

  base::ScopedAllowBaseSyncPrimitivesForTesting allow_wait;

  auto tr = db_->Begin(false);
  
  graph_iter_t iter = graph_nodes(tr.handle(), 0);
  
  entry_t entry = graph_iter_next(iter);

  while (entry) {
    node_t node = reinterpret_cast<node_t>(entry);
    
    name_sz = 0;
    name_data = graph_string(tr.handle(), node->val, &name_sz);

    type_sz = 0;
    type_data = graph_string(tr.handle(), node->type, &type_sz);
    
    std::unique_ptr<ConceptNode> concept(new ConceptNode(delegate, std::string(name_data, name_sz), std::string(type_data, type_sz))); 
    
    concept->gid_ = node->id;
    concept->handle_ = node;
    concept->managed_ = true;

    nodes->push_back(std::move(concept));

    entry = graph_iter_next(iter);
  }
     
  graph_iter_close(iter);
  
  *result = tr.Commit();

  db_sync_.Signal();
}

bool ConceptGraph::AddNodeImpl(ConceptNode* node) {
  //char type[] = "concept";

  if (node->is_managed()) {
    LOG(ERROR) << "The concept node is managed already. Theres no need to add it";
    return false;
  }

  auto tr = db_->Begin(true);
  //uint64_t id = tr.GetNextID();

  //printf("adding node with id %zu ...\n", id);
  node_t gnode = graph_node_resolve(tr.handle(),  const_cast<char *>(node->type_name().data()), node->type_name().size(), const_cast<char *>(node->name().data()), node->name().size());
  if (!gnode) {
    printf("graph_node_resolve returned nothing\n");
    return false;
  }
  bool ok = tr.Commit();

  if (ok) {
    node->gid_ = gnode->id;
    node->handle_ = gnode;
    node->managed_ = true;
  }
  return ok;
}

bool ConceptGraph::DeleteNodeImpl(ConceptNode* node) {
  if (!node->is_managed()) {
    LOG(ERROR) << "The concept node is not managed. Theres no need to delete it";
    return false;
  }
  //auto tr = db_->Begin();
  //return tr.Commit();
  return false;
}

bool ConceptGraph::DeleteNodeByIdImpl(uint64_t gid) {
  return false;
}

}