// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_GRAPH_GRAPH_SYSTEM_STORAGE_H_
#define MUMBA_HOST_GRAPH_GRAPH_SYSTEM_STORAGE_H_

#include "base/macros.h"
#include "storage/db/db.h"
#include "core/host/graph/graph_common.h"
#include "core/host/graph/graph_storage.h"

namespace host {
class Graph;

class GraphSystemStorage : public GraphStorage {
public:
  GraphSystemStorage(Graph* graph);
  ~GraphSystemStorage() override;

  std::unique_ptr<GraphTransaction> Begin(bool write) override;
  std::unique_ptr<GraphCursor> CreateCursor(GraphTransaction* transaction) override;
  void Close() override;
  size_t CountEntries() override;
  GraphEntry* GetEntry(GraphTransaction* transaction, graph_t id) override;
  GraphProperty* GetProperty(GraphTransaction* transaction, graph_t id) override;
  GraphNode* GetNode(GraphTransaction* transaction, graph_t id) override;
  GraphEdge* GetEdge(GraphTransaction* transaction, graph_t id) override;
  GraphNode* GetNode(GraphTransaction* transaction, base::StringPiece type, base::StringPiece value) override;
  GraphEdge* GetEdge(GraphTransaction* transaction, base::StringPiece type, base::StringPiece value) override;
  GraphProperty* GetProperty(GraphTransaction* transaction, base::StringPiece key) override;
  GraphProperty* GetProperty(GraphTransaction* transaction, GraphNode* node, base::StringPiece key) override;
  GraphProperty* GetProperty(GraphTransaction* transaction, GraphEdge* edge, base::StringPiece key) override;
  GraphProperty* GetProperty(GraphTransaction* transaction, GraphProperty* property, base::StringPiece key) override;
  bool ResolveBlob(GraphTransaction* transaction, graph_t* ret_id, const std::string& value, bool readonly) const override;
  bool GetBlob(GraphTransaction* transaction, graph_t blob_id, std::string* out) const override;
  std::unique_ptr<GraphCursor> GetNodes(GraphTransaction* transaction) override;
  std::unique_ptr<GraphCursor> GetEdges(GraphTransaction* transaction) override;
  bool InsertNode(GraphTransaction* transaction, GraphNode* node) override;
  bool InsertEdge(GraphTransaction* transaction, GraphEdge* edge) override;
  bool InsertProperty(GraphTransaction* transaction, GraphProperty* property) override;
  graph_t DeleteEntry(GraphTransaction* transaction, GraphEntry* entry) override;
  graph_t DeleteNode(GraphTransaction* transaction, GraphNode* node) override;
  graph_t DeleteEdge(GraphTransaction* transaction, GraphEdge* edge) override;
  graph_t DeleteProperty(GraphTransaction* transaction, GraphProperty* property) override;
  graph_t GetMaxId(GraphTransaction* transaction, GraphEntry* entry) override;
  graph_t GetNextId(GraphTransaction* transaction, GraphKeyspace keyspace) const override;
  
private:
  
  Graph* graph_;
  std::unique_ptr<storage::Database> db_;

  DISALLOW_COPY_AND_ASSIGN(GraphSystemStorage);
};

}

#endif
