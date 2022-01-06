// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_GRAPH_GRAPH_SYSTEM_TRANSACTION_H_
#define MUMBA_HOST_GRAPH_GRAPH_SYSTEM_TRANSACTION_H_

#include "base/macros.h"
#include "storage/db/db.h"
#include "core/host/graph/graph_common.h"
#include "core/host/graph/graph_transaction.h"

namespace host {
class GraphSystemCursor;

class GraphSystemTransaction : public GraphTransactionBase {
public:
  GraphSystemTransaction(Graph* graph);
  ~GraphSystemTransaction() override;

  bool readonly() const override;
  std::unique_ptr<GraphCursor> CreateCursor() override;
  std::unique_ptr<GraphCursor> CreateCursor(GraphKeyspace keyspace) override;
  bool Commit() override;
  void Rollback() override;
  
private:
  
  //graph_t next_id_;
  //graph_t next_blob_id_;

  DISALLOW_COPY_AND_ASSIGN(GraphSystemTransaction);
};

}

#endif
