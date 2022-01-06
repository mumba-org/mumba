// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_GRAPH_GRAPH_STORAGE_H_
#define MUMBA_HOST_GRAPH_GRAPH_STORAGE_H_

#include "base/macros.h"

#include "core/host/graph/graph_entry.h"

namespace host {
class GraphTransaction;
class GraphCursor;
class GraphNode;
class GraphEdge;
class GraphProperty;

class GraphStorage {
public: 
  virtual ~GraphStorage() {}
  virtual std::unique_ptr<GraphTransaction> Begin(bool write) = 0;
  virtual std::unique_ptr<GraphCursor> CreateCursor(GraphTransaction* transaction) = 0;
  virtual size_t CountEntries() = 0;
  virtual size_t CountNodes(GraphTransaction* transaction) = 0;
  virtual size_t CountEdges(GraphTransaction* transaction) = 0;
  virtual GraphEntry* GetEntry(GraphTransaction* transaction, graph_t id) = 0;
  virtual GraphProperty* GetProperty(GraphTransaction* transaction, graph_t id) = 0;
  virtual GraphNode* GetNode(GraphTransaction* transaction, graph_t id) = 0;
  virtual GraphEdge* GetEdge(GraphTransaction* transaction, graph_t id) = 0;
  virtual GraphNode* GetNode(GraphTransaction* transaction, base::StringPiece type, base::StringPiece value) = 0;
  virtual GraphEdge* GetEdge(GraphTransaction* transaction, base::StringPiece type, base::StringPiece value) = 0;
  virtual GraphProperty* GetProperty(GraphTransaction* transaction, base::StringPiece key) = 0;
  virtual GraphProperty* GetProperty(GraphTransaction* transaction, GraphNode* node, base::StringPiece key) = 0;
  virtual GraphProperty* GetProperty(GraphTransaction* transaction, GraphEdge* edge, base::StringPiece key) = 0;
  virtual GraphProperty* GetProperty(GraphTransaction* transaction, GraphProperty* property, base::StringPiece key) = 0;
  virtual bool GetBlob(GraphTransaction* transaction, graph_t blob_id, std::string* out) const = 0;
  virtual bool ResolveBlob(GraphTransaction* transaction, graph_t* ret_id, const std::string& value, bool readonly) const = 0;
  virtual std::unique_ptr<GraphCursor> GetNodes(GraphTransaction* transaction) = 0;
  virtual std::unique_ptr<GraphCursor> GetEdges(GraphTransaction* transaction) = 0;
  virtual graph_t GetMaxId(GraphTransaction* transaction, GraphEntry* entry) = 0;
  virtual graph_t GetNextId(GraphTransaction* transaction, GraphKeyspace keyspace) const = 0;
  virtual bool InsertNode(GraphTransaction* transaction, GraphNode* node) = 0;
  virtual bool InsertEdge(GraphTransaction* transaction, GraphEdge* edge) = 0;
  virtual bool InsertProperty(GraphTransaction* transaction, GraphProperty* property) = 0;
  virtual graph_t DeleteEntry(GraphTransaction* transaction, GraphEntry* entry) = 0;
  virtual graph_t DeleteNode(GraphTransaction* transaction, GraphNode* node) = 0;
  virtual graph_t DeleteEdge(GraphTransaction* transaction, GraphEdge* edge) = 0;
  virtual graph_t DeleteProperty(GraphTransaction* transaction, GraphProperty* property) = 0;
  virtual void Close() = 0;
};

}

#endif