// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/graph/graph_system_storage.h"

#include "core/host/graph/graph.h"
#include "core/host/graph/graph_transaction.h"
#include "core/host/graph/graph_cursor.h"

namespace host {

GraphSystemStorage::GraphSystemStorage(Graph* graph): graph_(graph) {
  db_ = storage::Database::CreateMemory(kGraphKeyspaceNames);
}

GraphSystemStorage::~GraphSystemStorage() {
  // silence the warning
  graph_ = nullptr;
}

std::unique_ptr<GraphTransaction> GraphSystemStorage::Begin(bool write) {
  return {};
}

std::unique_ptr<GraphCursor> GraphSystemStorage::CreateCursor(GraphTransaction* transaction) {
  return transaction->CreateCursor();
}

void GraphSystemStorage::Close() {
  db_->Close();
}

size_t GraphSystemStorage::CountEntries() {
  return 0;
}

GraphEntry* GraphSystemStorage::GetEntry(GraphTransaction* transaction, graph_t id) {
  return {};
}

GraphProperty* GraphSystemStorage::GetProperty(GraphTransaction* transaction, graph_t id) {
  return {};
}

GraphNode* GraphSystemStorage::GetNode(GraphTransaction* transaction, graph_t id) {
  return {};
}

GraphEdge* GraphSystemStorage::GetEdge(GraphTransaction* transaction, graph_t id) {
  return {};
}

GraphNode* GraphSystemStorage::GetNode(GraphTransaction* transaction, base::StringPiece type, base::StringPiece value) {
  return {};
}

GraphEdge* GraphSystemStorage::GetEdge(GraphTransaction* transaction, base::StringPiece type, base::StringPiece value) {
  return {};
}

GraphProperty* GraphSystemStorage::GetProperty(GraphTransaction* transaction, base::StringPiece key) {
  return {};
}

GraphProperty* GraphSystemStorage::GetProperty(GraphTransaction* transaction, GraphNode* node, base::StringPiece key) {
  return {};
}

GraphProperty* GraphSystemStorage::GetProperty(GraphTransaction* transaction, GraphEdge* edge, base::StringPiece key) {
  return {};
}

GraphProperty* GraphSystemStorage::GetProperty(GraphTransaction* transaction, GraphProperty* property, base::StringPiece key) {
  return {};  
}

bool GraphSystemStorage::ResolveBlob(GraphTransaction* transaction, graph_t* ret_id, const std::string& value, bool readonly) const {
  return false;
}

bool GraphSystemStorage::GetBlob(GraphTransaction* transaction, graph_t blob_id, std::string* out) const {
  return false;
}

std::unique_ptr<GraphCursor> GraphSystemStorage::GetNodes(GraphTransaction* transaction) {
  return nullptr;
}

std::unique_ptr<GraphCursor> GraphSystemStorage::GetEdges(GraphTransaction* transaction) {
  return nullptr;
}  

bool GraphSystemStorage::InsertNode(GraphTransaction* transaction, GraphNode* node) {
  return false;
}

bool GraphSystemStorage::InsertEdge(GraphTransaction* transaction, GraphEdge* edge) {
  return false;
}

bool GraphSystemStorage::InsertProperty(GraphTransaction* transaction, GraphProperty* property) {
  return false;
}

graph_t GraphSystemStorage::DeleteEntry(GraphTransaction* transaction, GraphEntry* entry) {
  return 0;
}

graph_t GraphSystemStorage::DeleteNode(GraphTransaction* transaction, GraphNode* node) {
  return 0;
}

graph_t GraphSystemStorage::DeleteEdge(GraphTransaction* transaction, GraphEdge* edge) {
  return 0;
}

graph_t GraphSystemStorage::DeleteProperty(GraphTransaction* transaction, GraphProperty* property) {
  return 0;
}

graph_t GraphSystemStorage::GetMaxId(GraphTransaction* transaction, GraphEntry* entry) {
  return 0;
}

graph_t GraphSystemStorage::GetNextId(GraphTransaction* transaction, GraphKeyspace keyspace) const {
  return 0;
}  

}
