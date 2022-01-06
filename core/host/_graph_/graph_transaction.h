// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_GRAPH_GRAPH_TRANSACTION_H_
#define MUMBA_HOST_GRAPH_GRAPH_TRANSACTION_H_

#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "storage/db/db.h"
#include "core/host/graph/graph_common.h"
#include "core/host/graph/graph.h"

namespace host {
class GraphCursor;
class GraphEntry;
class GraphEdge;
class GraphNode;
class GraphProperty;

class GraphTransaction {
public:
  virtual ~GraphTransaction() {}

  virtual bool readonly() const = 0;
  virtual Graph* graph() const = 0;
  
  virtual GraphNode* NewNode() = 0;
  virtual GraphNode* NewNode(graph_t id) = 0;
  virtual GraphNode* NewNode(protocol::GraphNode proto) = 0;
  virtual GraphEdge* NewEdge() = 0;
  virtual GraphEdge* NewEdge(graph_t id) = 0;
  virtual GraphEdge* NewEdge(protocol::GraphEdge proto) = 0;
  virtual GraphProperty* NewProperty() = 0;
  virtual GraphProperty* NewProperty(graph_t id) = 0;
  virtual GraphProperty* NewProperty(protocol::GraphProperty proto) = 0;

  virtual std::unique_ptr<GraphCursor> CreateCursor();
  virtual std::unique_ptr<GraphCursor> CreateCursor(GraphKeyspace keyspace);
  virtual bool Commit() { return false; };
  virtual void Rollback() {};
  
  // ops
  virtual size_t CountEntries() = 0;
  virtual GraphEntry* GetEntry(graph_t id) = 0;
  virtual GraphProperty* GetProperty(graph_t id) = 0;
  virtual GraphNode* GetNode(graph_t id) = 0;
  virtual GraphEdge* GetEdge(graph_t id) = 0;
  virtual graph_t GetLastId() = 0;
  virtual graph_t GetLastIdOf(GraphEntry* entry) = 0;
  virtual graph_t GetLastIdOf(GraphNode* node) = 0;
  virtual graph_t GetLastIdOf(GraphEdge* edge) = 0;
  virtual graph_t GetLastIdOf(GraphProperty* property) = 0;
  virtual GraphProperty* GetProperty(base::StringPiece key) = 0;
  virtual GraphProperty* GetProperty(GraphNode* node, base::StringPiece key) = 0;
  virtual GraphProperty* GetProperty(GraphEdge* edge, base::StringPiece key) = 0;
  virtual GraphProperty* GetProperty(GraphProperty* property, base::StringPiece key) = 0;
  virtual GraphProperty* SetProperty(base::StringPiece key, base::StringPiece value) = 0;
  virtual GraphProperty* SetProperty(GraphNode* node, base::StringPiece key, base::StringPiece value) = 0;
  virtual GraphProperty* SetProperty(GraphEdge* edge, base::StringPiece key, base::StringPiece value) = 0;
  virtual GraphProperty* SetProperty(GraphProperty* property, base::StringPiece key, base::StringPiece value) = 0;
  virtual void UnsetProperty(base::StringPiece key) = 0;
  virtual void UnsetProperty(GraphNode* node, base::StringPiece key) = 0;
  virtual void UnsetProperty(GraphEdge* edge, base::StringPiece key) = 0;
  virtual void UnsetProperty(GraphProperty* property, base::StringPiece key) = 0;
  virtual bool InsertNode(GraphNode* node) = 0;
  virtual bool InsertEdge(GraphEdge* edge) = 0;
  virtual bool InsertProperty(GraphProperty* property) = 0;
  virtual GraphNode* LookupNode(base::StringPiece type, base::StringPiece value) = 0;
  virtual GraphEdge* LookupEdge(base::StringPiece type, base::StringPiece value) = 0;
  virtual GraphNode* ResolveNode(base::StringPiece type, base::StringPiece value) = 0;
  virtual GraphEdge* ResolveEdge(GraphNode* src, GraphNode* target, base::StringPiece type, base::StringPiece value) = 0;
  virtual bool GetBlob(graph_t blob_id, std::string* out) = 0;
  virtual bool ResolveBlob(graph_t* ret_id, const std::string& value, bool readonly) = 0;
  virtual size_t CountNodes() = 0;
  virtual size_t CountEdges() = 0;
  virtual std::unique_ptr<GraphCursor> GetNodes() = 0;
  virtual std::unique_ptr<GraphCursor> GetEdges() = 0;
  virtual std::unique_ptr<GraphCursor> GetNodesOfType(base::StringPiece type) = 0;
  virtual std::unique_ptr<GraphCursor> GetEdgesOfType(base::StringPiece type) = 0;
  virtual std::unique_ptr<GraphCursor> GetNodeEdges(GraphNode* node) = 0;
  virtual std::unique_ptr<GraphCursor> GetNodeEdgesIn(GraphNode* node) = 0;
  virtual std::unique_ptr<GraphCursor> GetNodeEdgesOut(GraphNode* node) = 0;
  virtual std::unique_ptr<GraphCursor> GetNodeEdgesDirection(GraphNode* node, GraphDirection direction) = 0;
  virtual std::unique_ptr<GraphCursor> GetNodeEdgesType(GraphNode* node, base::StringPiece type) = 0;
  virtual std::unique_ptr<GraphCursor> GetNodeEdgesTypeIn(GraphNode* node, base::StringPiece type) = 0;
  virtual std::unique_ptr<GraphCursor> GetNodeEdgesTypeOut(GraphNode* node, base::StringPiece type) = 0;
  virtual std::unique_ptr<GraphCursor> GetNodeEdgesDirectionType(GraphNode* node, GraphDirection direction, base::StringPiece type) = 0;
  virtual std::unique_ptr<GraphCursor> GetProperties() = 0;
  virtual std::unique_ptr<GraphCursor> GetNodeProperties(GraphNode* node) = 0;
  virtual std::unique_ptr<GraphCursor> GetEdgeProperties(GraphEdge* edge) = 0;
  virtual std::unique_ptr<GraphCursor> GetPropertyProperties(GraphProperty* property) = 0;
  virtual graph_t DeleteEntry(GraphEntry* entry) = 0;
  virtual graph_t DeleteNode(GraphNode* node) = 0;
  virtual graph_t DeleteEdge(GraphEdge* edge) = 0;
  virtual graph_t DeleteProperty(GraphProperty* property) = 0;
};

class GraphTransactionBase : public GraphTransaction {
public:
  GraphTransactionBase(Graph* graph);

  Graph* graph() const override {
    return graph_;
  }

  graph_t next_id() const {
    return next_id_;
  }

  void set_next_id(graph_t next_id) {
    next_id_ = next_id;
  }

  GraphNode* NewNode() override;
  GraphNode* NewNode(graph_t id) override;
  GraphNode* NewNode(protocol::GraphNode proto) override;
  GraphEdge* NewEdge() override;
  GraphEdge* NewEdge(graph_t id) override;
  GraphEdge* NewEdge(protocol::GraphEdge proto) override;
  GraphProperty* NewProperty() override;
  GraphProperty* NewProperty(graph_t id) override;
  GraphProperty* NewProperty(protocol::GraphProperty proto) override;

  size_t CountEntries() override;
  GraphEntry* GetEntry(graph_t id) override;
  GraphProperty* GetProperty(graph_t id) override;
  GraphNode* GetNode(graph_t id) override;
  GraphEdge* GetEdge(graph_t id) override;
  graph_t GetLastId() override;
  graph_t GetLastIdOf(GraphEntry* entry) override;
  graph_t GetLastIdOf(GraphNode* node) override;
  graph_t GetLastIdOf(GraphEdge* edge) override;
  graph_t GetLastIdOf(GraphProperty* property) override;
  GraphProperty* GetProperty(base::StringPiece key) override;
  GraphProperty* GetProperty(GraphNode* node, base::StringPiece key) override;
  GraphProperty* GetProperty(GraphEdge* edge, base::StringPiece key) override;
  GraphProperty* GetProperty(GraphProperty* property, base::StringPiece key) override;
  GraphProperty* SetProperty(base::StringPiece key, base::StringPiece value) override;
  GraphProperty* SetProperty(GraphNode* node, base::StringPiece key, base::StringPiece value) override;
  GraphProperty* SetProperty(GraphEdge* edge, base::StringPiece key, base::StringPiece value) override;
  GraphProperty* SetProperty(GraphProperty* property, base::StringPiece key, base::StringPiece value) override;
  void UnsetProperty(base::StringPiece key) override;
  void UnsetProperty(GraphNode* node, base::StringPiece key) override;
  void UnsetProperty(GraphEdge* edge, base::StringPiece key) override;
  void UnsetProperty(GraphProperty* property, base::StringPiece key) override;
  bool InsertNode(GraphNode* node) override;
  bool InsertEdge(GraphEdge* edge) override;
  bool InsertProperty(GraphProperty* property) override;
  GraphNode* LookupNode(base::StringPiece type, base::StringPiece value) override;
  GraphEdge* LookupEdge(base::StringPiece type, base::StringPiece value) override;
  GraphNode* ResolveNode(base::StringPiece type, base::StringPiece value) override;
  GraphEdge* ResolveEdge(GraphNode* src, GraphNode* target, base::StringPiece type, base::StringPiece value) override;
  bool GetBlob(graph_t blob_id, std::string* out) override;
  bool ResolveBlob(graph_t* ret_id, const std::string& value, bool readonly) override;
  size_t CountNodes() override;
  size_t CountEdges() override;
  std::unique_ptr<GraphCursor> GetNodes() override;
  std::unique_ptr<GraphCursor> GetEdges() override;
  std::unique_ptr<GraphCursor> GetNodesOfType(base::StringPiece type) override;
  std::unique_ptr<GraphCursor> GetEdgesOfType(base::StringPiece type) override;
  std::unique_ptr<GraphCursor> GetNodeEdges(GraphNode* node) override;
  std::unique_ptr<GraphCursor> GetNodeEdgesIn(GraphNode* node) override;
  std::unique_ptr<GraphCursor> GetNodeEdgesOut(GraphNode* node) override;
  std::unique_ptr<GraphCursor> GetNodeEdgesDirection(GraphNode* node, GraphDirection direction) override;
  std::unique_ptr<GraphCursor> GetNodeEdgesType(GraphNode* node, base::StringPiece type) override;
  std::unique_ptr<GraphCursor> GetNodeEdgesTypeIn(GraphNode* node, base::StringPiece type) override;
  std::unique_ptr<GraphCursor> GetNodeEdgesTypeOut(GraphNode* node, base::StringPiece type) override;
  std::unique_ptr<GraphCursor> GetNodeEdgesDirectionType(GraphNode* node, GraphDirection direction, base::StringPiece type) override;
  std::unique_ptr<GraphCursor> GetProperties() override;
  std::unique_ptr<GraphCursor> GetNodeProperties(GraphNode* node) override;
  std::unique_ptr<GraphCursor> GetEdgeProperties(GraphEdge* edge) override;
  std::unique_ptr<GraphCursor> GetPropertyProperties(GraphProperty* property) override;
  graph_t DeleteEntry(GraphEntry* entry) override;
  graph_t DeleteNode(GraphNode* node) override;
  graph_t DeleteEdge(GraphEdge* edge) override;
  graph_t DeleteProperty(GraphProperty* property) override;

protected:
  Graph* graph_;
  std::vector<std::unique_ptr<GraphEntryBase>> entries_;
  graph_t next_id_;
  
  DISALLOW_COPY_AND_ASSIGN(GraphTransactionBase);
};

}

#endif
