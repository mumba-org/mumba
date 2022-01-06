// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/graph/graph_db_transaction.h"

#include "core/host/graph/graph.h"
#include "core/host/graph/graph_db_cursor.h"

namespace host {

GraphDbTransaction::GraphDbTransaction(Graph* graph, storage::Transaction* transaction): 
  GraphTransactionBase(graph),
  transaction_(transaction),
  commited_(false) {
  //next_id_(0),
  //next_blob_id_(0) {
    
}

GraphDbTransaction::~GraphDbTransaction() {
  if (!commited_) {
    transaction_->Commit();  
  }
}

bool GraphDbTransaction::readonly() const {
  return !transaction_->is_write();
}

std::unique_ptr<GraphCursor> GraphDbTransaction::CreateCursor() {
  storage::Cursor* db_cursor = transaction_->CreateCursor(graph_->GetKeyspace(GraphKeyspace::ENTRY)); 
  return std::make_unique<GraphDbCursor>(this, db_cursor, GraphKeyspace::ENTRY);
}

std::unique_ptr<GraphCursor> GraphDbTransaction::CreateCursor(GraphKeyspace keyspace) {
  storage::Cursor* db_cursor = transaction_->CreateCursor(graph_->GetKeyspace(keyspace)); 
  return std::make_unique<GraphDbCursor>(this, db_cursor, keyspace);
}

bool GraphDbTransaction::Commit() {
  transaction_->Commit();
  commited_ = true;
  return true;
}

void GraphDbTransaction::Rollback() {
  transaction_->Rollback();
  commited_ = true;
}

}