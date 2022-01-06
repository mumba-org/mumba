// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/graph/graph_transaction.h"

#include "core/host/graph/graph.h"
#include "core/host/graph/graph_node.h"
#include "core/host/graph/graph_edge.h"
#include "core/host/graph/graph_property.h"
#include "core/host/graph/graph_cursor.h"

namespace host {

std::unique_ptr<GraphCursor> GraphTransaction::CreateCursor() {
  return {};
}

std::unique_ptr<GraphCursor> GraphTransaction::CreateCursor(GraphKeyspace keyspace) {
  return {};
}

GraphTransactionBase::GraphTransactionBase(Graph* graph): graph_(graph), next_id_(0) {

}

GraphNode* GraphTransactionBase::NewNode() {
  std::unique_ptr<GraphNode> node(new GraphNode(this));
  GraphNode* ref = node.get();
  //graph_t id = graph_->GetNextId(this, GraphKeyspace::ENTRY);
  //node->set_id(id);
  entries_.push_back(std::move(node));
  return ref;
}

GraphNode* GraphTransactionBase::NewNode(graph_t id) {
  std::unique_ptr<GraphNode> node(new GraphNode(this));
  GraphNode* ref = node.get();
  node->set_id(id);
  entries_.push_back(std::move(node));
  return ref;
}

GraphNode* GraphTransactionBase::NewNode(protocol::GraphNode proto) {
  std::unique_ptr<GraphNode> node(new GraphNode(this, std::move(proto)));
  GraphNode* ref = node.get();
  entries_.push_back(std::move(node));
  return ref;
}

GraphEdge* GraphTransactionBase::NewEdge() {
  std::unique_ptr<GraphEdge> edge(new GraphEdge(this));
  GraphEdge* ref = edge.get();
  //graph_t id = graph_->GetNextId(this, GraphKeyspace::ENTRY);
  //edge->set_id(id);
  entries_.push_back(std::move(edge));
  return ref;
}

GraphEdge* GraphTransactionBase::NewEdge(graph_t id) {
  std::unique_ptr<GraphEdge> edge(new GraphEdge(this));
  GraphEdge* ref = edge.get();
  edge->set_id(id);
  entries_.push_back(std::move(edge));
  return ref;
}

GraphEdge* GraphTransactionBase::NewEdge(protocol::GraphEdge proto) {
  std::unique_ptr<GraphEdge> edge(new GraphEdge(this, std::move(proto)));
  GraphEdge* ref = edge.get();
  entries_.push_back(std::move(edge));
  return ref;
}

GraphProperty* GraphTransactionBase::NewProperty() {
  std::unique_ptr<GraphProperty> prop(new GraphProperty(this));
  GraphProperty* ref = prop.get();
  //graph_t id = graph_->GetNextId(this, GraphKeyspace::ENTRY);
  //prop->set_id(id);  
  entries_.push_back(std::move(prop));
  return ref;
}
GraphProperty* GraphTransactionBase::NewProperty(graph_t id) {
  std::unique_ptr<GraphProperty> prop(new GraphProperty(this));
  GraphProperty* ref = prop.get();
  prop->set_id(id);  
  entries_.push_back(std::move(prop));
  return ref;
}

GraphProperty* GraphTransactionBase::NewProperty(protocol::GraphProperty proto) {
  std::unique_ptr<GraphProperty> prop(new GraphProperty(this, std::move(proto)));
  GraphProperty* ref = prop.get();
  entries_.push_back(std::move(prop));
  return ref;
}

size_t GraphTransactionBase::CountEntries() {
  return graph_->CountEntries(this);
}

GraphEntry* GraphTransactionBase::GetEntry(graph_t id) {
  return graph_->GetEntry(this, id);
}

GraphProperty* GraphTransactionBase::GetProperty(graph_t id) {
  GraphProperty* p = graph_->GetProperty(this, id);
  if (p) {
    p->set_managed(true);
  }
  return p;
}

GraphNode* GraphTransactionBase::GetNode(graph_t id) {
  GraphNode* n = graph_->GetNode(this, id);
  if (n) {
    n->set_managed(true);
  }
  return n;
}

GraphEdge* GraphTransactionBase::GetEdge(graph_t id) {
  GraphEdge* e = graph_->GetEdge(this, id);
  if (e) {
    e->set_managed(true);
  }
  return e;
}

graph_t GraphTransactionBase::GetLastId() {
  return graph_->GetLastId(this);
}

graph_t GraphTransactionBase::GetLastIdOf(GraphEntry* entry) {
  return graph_->GetLastIdOf(this, entry);
}

graph_t GraphTransactionBase::GetLastIdOf(GraphNode* node) {
  return graph_->GetLastIdOf(this, node);
}

graph_t GraphTransactionBase::GetLastIdOf(GraphEdge* edge) {
  return graph_->GetLastIdOf(this, edge);
}

graph_t GraphTransactionBase::GetLastIdOf(GraphProperty* property) {
  return graph_->GetLastIdOf(this, property);
}

GraphProperty* GraphTransactionBase::GetProperty(base::StringPiece key) {
  GraphProperty* p = graph_->GetProperty(this, key);
  if (p) {
    p->set_managed(true);
  }
  return p;
}

GraphProperty* GraphTransactionBase::GetProperty(GraphNode* node, base::StringPiece key) {
  GraphProperty* p = graph_->GetProperty(this, node, key);
  if (p) {
    p->set_managed(true);
  }
  return p;
}

GraphProperty* GraphTransactionBase::GetProperty(GraphEdge* edge, base::StringPiece key) {
  GraphProperty* p = graph_->GetProperty(this, edge, key);
  if (p) {
    p->set_managed(true);
  }
  return p;
}

GraphProperty* GraphTransactionBase::GetProperty(GraphProperty* property, base::StringPiece key) {
  GraphProperty* p = graph_->GetProperty(this, property, key);
  if (p) {
    p->set_managed(true);
  }
  return p;
}

GraphProperty* GraphTransactionBase::SetProperty(base::StringPiece key, base::StringPiece value) {
  GraphProperty* p = graph_->SetProperty(this, key, value);
  if (p) {
    p->set_managed(true);
  }
  return p;
}

GraphProperty* GraphTransactionBase::SetProperty(GraphNode* node, base::StringPiece key, base::StringPiece value) {
  GraphProperty* p = graph_->SetProperty(this, node, key, value);
  if (p) {
    p->set_managed(true);
  }
  return p;
}

GraphProperty* GraphTransactionBase::SetProperty(GraphEdge* edge, base::StringPiece key, base::StringPiece value) {
  GraphProperty* p = graph_->SetProperty(this, edge, key, value);
  if (p) {
    p->set_managed(true);
  }
  return p;
}

GraphProperty* GraphTransactionBase::SetProperty(GraphProperty* property, base::StringPiece key, base::StringPiece value) {
  return graph_->SetProperty(this, property, key, value);
}

void GraphTransactionBase::UnsetProperty(base::StringPiece key) {
  graph_->UnsetProperty(this, key);
}

void GraphTransactionBase::UnsetProperty(GraphNode* node, base::StringPiece key) {
  graph_->UnsetProperty(this, node, key);
}

void GraphTransactionBase::UnsetProperty(GraphEdge* edge, base::StringPiece key) {
  graph_->UnsetProperty(this, edge, key);
}

void GraphTransactionBase::UnsetProperty(GraphProperty* property, base::StringPiece key) {
  graph_->UnsetProperty(this, property, key);
}

bool GraphTransactionBase::InsertNode(GraphNode* node) {
  bool r = graph_->InsertNode(this, node);
  if (r) {
    node->set_dirty(false);
    node->set_managed(true);
  }
  return r;
}

bool GraphTransactionBase::InsertEdge(GraphEdge* edge) {
  bool r = graph_->InsertEdge(this, edge);
  if (r) {
    edge->set_dirty(false);
    edge->set_managed(true);
  }
  return r;
}

bool GraphTransactionBase::InsertProperty(GraphProperty* property) {
  bool r = graph_->InsertProperty(this, property);
  if (r) {
    property->set_dirty(false);
    property->set_managed(true);
  }
  return r;
}

GraphNode* GraphTransactionBase::LookupNode(base::StringPiece type, base::StringPiece value) {
  GraphNode* n = graph_->LookupNode(this, type, value);
  if (n) {
    n->set_managed(true);
  }
  return n;
}

GraphEdge* GraphTransactionBase::LookupEdge(base::StringPiece type, base::StringPiece value) {
  GraphEdge* e = graph_->LookupEdge(this, type, value);
  if (e) {
    e->set_managed(true);
  }
  return e;
}

GraphNode* GraphTransactionBase::ResolveNode(base::StringPiece type, base::StringPiece value) {
  GraphNode* n = graph_->ResolveNode(this, type, value);
  if (n) {
    n->set_managed(true);
  }
  return n;
}

GraphEdge* GraphTransactionBase::ResolveEdge(GraphNode* src, GraphNode* target, base::StringPiece type, base::StringPiece value) {
  GraphEdge* e = graph_->ResolveEdge(this, src, target, type, value);
  if (e) {
    e->set_managed(true);
  }
  return e;
}

bool GraphTransactionBase::GetBlob(graph_t blob_id, std::string* out) {
  return graph_->GetBlob(this, blob_id, out);
}

bool GraphTransactionBase::ResolveBlob(graph_t* ret_id, const std::string& value, bool readonly) {
  return graph_->ResolveBlob(this, ret_id, value, readonly);
}

size_t GraphTransactionBase::CountNodes() {
  return graph_->CountNodes(this);
}

size_t GraphTransactionBase::CountEdges() {
  return graph_->CountEdges(this);
}

std::unique_ptr<GraphCursor> GraphTransactionBase::GetNodes() {
  return graph_->GetNodes(this);
}

std::unique_ptr<GraphCursor> GraphTransactionBase::GetEdges() {
  return graph_->GetEdges(this);
}

std::unique_ptr<GraphCursor> GraphTransactionBase::GetNodesOfType(base::StringPiece type) {
  return graph_->GetNodesOfType(this, type);
}

std::unique_ptr<GraphCursor> GraphTransactionBase::GetEdgesOfType(base::StringPiece type) {
  return graph_->GetEdgesOfType(this, type);
}

std::unique_ptr<GraphCursor> GraphTransactionBase::GetNodeEdges(GraphNode* node) {
  return graph_->GetNodeEdges(this, node);
}

std::unique_ptr<GraphCursor> GraphTransactionBase::GetNodeEdgesIn(GraphNode* node) {
  return graph_->GetNodeEdgesIn(this, node);
}

std::unique_ptr<GraphCursor> GraphTransactionBase::GetNodeEdgesOut(GraphNode* node) {
  return graph_->GetNodeEdgesOut(this, node);
}

std::unique_ptr<GraphCursor> GraphTransactionBase::GetNodeEdgesDirection(GraphNode* node, GraphDirection direction) {
  return graph_->GetNodeEdgesDirection(this, node, direction);
}

std::unique_ptr<GraphCursor> GraphTransactionBase::GetNodeEdgesType(GraphNode* node, base::StringPiece type) {
  return graph_->GetNodeEdgesType(this, node, type);
}

std::unique_ptr<GraphCursor> GraphTransactionBase::GetNodeEdgesTypeIn(GraphNode* node, base::StringPiece type) {
  return graph_->GetNodeEdgesTypeIn(this, node, type);
}

std::unique_ptr<GraphCursor> GraphTransactionBase::GetNodeEdgesTypeOut(GraphNode* node, base::StringPiece type) {
  return graph_->GetNodeEdgesTypeOut(this, node, type);
}

std::unique_ptr<GraphCursor> GraphTransactionBase::GetNodeEdgesDirectionType(GraphNode* node, GraphDirection direction, base::StringPiece type) {
  return graph_->GetNodeEdgesDirectionType(this, node, direction, type);
}

std::unique_ptr<GraphCursor> GraphTransactionBase::GetProperties() {
  return graph_->GetProperties(this);
}

std::unique_ptr<GraphCursor> GraphTransactionBase::GetNodeProperties(GraphNode* node) {
  return graph_->GetNodeProperties(this, node);
}

std::unique_ptr<GraphCursor> GraphTransactionBase::GetEdgeProperties(GraphEdge* edge) {
  return graph_->GetEdgeProperties(this, edge);
}

std::unique_ptr<GraphCursor> GraphTransactionBase::GetPropertyProperties(GraphProperty* property) {
  return graph_->GetPropertyProperties(this, property);
}

graph_t GraphTransactionBase::DeleteEntry(GraphEntry* entry) {
  return graph_->DeleteEntry(this, entry);
}

graph_t GraphTransactionBase::DeleteNode(GraphNode* node) {
  return graph_->DeleteNode(this, node);
}

graph_t GraphTransactionBase::DeleteEdge(GraphEdge* edge) {
  return graph_->DeleteEdge(this, edge);
}

graph_t GraphTransactionBase::DeleteProperty(GraphProperty* property) {
  return graph_->DeleteProperty(this, property);
}

}
