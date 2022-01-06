// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/graph/graph_system_transaction.h"

#include "core/host/graph/graph.h"
#include "core/host/graph/graph_system_cursor.h"

namespace host {

GraphSystemTransaction::GraphSystemTransaction(Graph* graph): 
  GraphTransactionBase(graph) {//,
  //next_id_(0),
  //next_blob_id_(0) {
    
}

GraphSystemTransaction::~GraphSystemTransaction() {
  // just to silence the warning for now
  graph_ = nullptr;
}

bool GraphSystemTransaction::readonly() const {
  return true;
}

std::unique_ptr<GraphCursor> GraphSystemTransaction::CreateCursor() {
  // storage::Cursor* db_cursor = transaction_->CreateCursor(graph_->GetKeyspace(GraphKeyspace::ENTRY)); 
  // auto cursor = std::make_unique<GraphDbCursor>(this, db_cursor);
  // GraphDbCursor* cursor_ptr = cursor.get();
  // cursors_.push_back(std::move(cursor));
  // return cursor_ptr;
  return nullptr;
}

std::unique_ptr<GraphCursor> GraphSystemTransaction::CreateCursor(GraphKeyspace keyspace) {
  return nullptr;
}

bool GraphSystemTransaction::Commit() {
  // cursors_.clear();
  // transaction_->Commit();
  return true;
}

void GraphSystemTransaction::Rollback() {
  //transaction_->Rollback();
}

}