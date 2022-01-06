// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_GRAPH_GRAPH_DB_TRANSACTION_H_
#define MUMBA_HOST_GRAPH_GRAPH_DB_TRANSACTION_H_

#include "base/macros.h"
#include "storage/db/db.h"
#include "core/host/graph/graph_common.h"
#include "core/host/graph/graph_transaction.h"

namespace host {
class GraphDbCursor;
class GraphDbStorage;
class GraphDbTransaction : public GraphTransactionBase {
public:
  GraphDbTransaction(Graph* graph, storage::Transaction* transaction);
  ~GraphDbTransaction() override;

  std::unique_ptr<GraphCursor> CreateCursor() override;
  std::unique_ptr<GraphCursor> CreateCursor(GraphKeyspace keyspace) override;
  bool readonly() const override;
  bool Commit() override;
  void Rollback() override;
  //void CloseCursor(GraphCursor* cursor) override;

private:
  friend class GraphDbStorage;

  storage::Transaction* transaction_;
  bool commited_;
  //std::vector<std::unique_ptr<GraphDbCursor>> cursors_;
  //graph_t next_id_;
  //graph_t next_blob_id_;

  DISALLOW_COPY_AND_ASSIGN(GraphDbTransaction);
};

}

#endif
