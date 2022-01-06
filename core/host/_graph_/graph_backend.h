// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_GRAPH_GRAPH_BACKEND_H_
#define MUMBA_HOST_GRAPH_GRAPH_BACKEND_H_

#include "base/macros.h"
#include "base/containers/flat_map.h"
#include "core/host/graph/graph_common.h"
#include "core/host/graph/graph_storage.h"
#include "storage/torrent.h"

namespace host {
class ShareDatabase;  
class Graph;
//
// (Graph) <--> (Backend)[Storage A, Storage B]
//

class GraphBackend {
public:
  
  GraphBackend(Graph* graph);
  ~GraphBackend();

  bool Init(const scoped_refptr<ShareDatabase>& db, bool in_memory);
  //bool Init();
  
  std::unique_ptr<GraphTransaction> Begin(bool write);
  std::unique_ptr<GraphCursor> CreateCursor(GraphTransaction* transaction);
  void Close(GraphTransaction* transaction);
  size_t CountEntries(GraphTransaction* transaction);
  size_t CountNodes(GraphTransaction* transaction);
  size_t CountEdges(GraphTransaction* transaction);
  graph_t GetNextId(GraphTransaction* transaction, GraphKeyspace keyspace);
  GraphEntry* GetEntry(GraphTransaction* transaction, graph_t id);
  GraphProperty* GetProperty(GraphTransaction* transaction, graph_t id);
  GraphNode* GetNode(GraphTransaction* transaction, graph_t id);
  GraphEdge* GetEdge(GraphTransaction* transaction, graph_t id);
  GraphNode* GetNode(GraphTransaction* transaction, base::StringPiece type, base::StringPiece value);
  GraphEdge* GetEdge(GraphTransaction* transaction, base::StringPiece type, base::StringPiece value);
  GraphProperty* GetProperty(GraphTransaction* transaction, base::StringPiece key);
  GraphProperty* GetProperty(GraphTransaction* transaction, GraphNode* node, base::StringPiece key);
  GraphProperty* GetProperty(GraphTransaction* transaction, GraphEdge* edge, base::StringPiece key);
  GraphProperty* GetProperty(GraphTransaction* transaction, GraphProperty* property, base::StringPiece key);
  bool GetBlob(GraphTransaction* transaction, graph_t blob_id, std::string* out) const;
  bool ResolveBlob(GraphTransaction* transaction, graph_t* ret_id, const std::string& value, bool readonly) const;
  std::unique_ptr<GraphCursor> GetNodes(GraphTransaction* transaction);
  std::unique_ptr<GraphCursor> GetEdges(GraphTransaction* transaction);
  bool InsertNode(GraphTransaction* transaction, GraphNode* node);
  bool InsertEdge(GraphTransaction* transaction, GraphEdge* edge);
  bool InsertProperty(GraphTransaction* transaction, GraphProperty* property);
  graph_t DeleteEntry(GraphTransaction* transaction, GraphEntry* entry);
  graph_t DeleteNode(GraphTransaction* transaction, GraphNode* node);
  graph_t DeleteEdge(GraphTransaction* transaction, GraphEdge* edge);
  graph_t DeleteProperty(GraphTransaction* transaction, GraphProperty* property);

private:
  
  bool InitInternal(const scoped_refptr<ShareDatabase>& db, bool in_memory);
  std::unique_ptr<GraphStorage> CreateStorage(const scoped_refptr<ShareDatabase>& db, bool in_memory);
  
  Graph* graph_;
  GraphStorage* storage_;
  base::flat_map<std::string, std::unique_ptr<GraphStorage>> storages_;
  scoped_refptr<ShareDatabase> in_memory_db_;
  bool initialized_;
  bool closed_;

  DISALLOW_COPY_AND_ASSIGN(GraphBackend);
};

}

#endif