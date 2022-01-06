// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/graph/graph_backend.h"


#include "core/host/graph/graph.h"
#include "core/host/graph/graph.h"
#include "core/host/graph/graph_system_storage.h"
#include "core/host/graph/graph_db_storage.h"
#include "core/host/graph/graph_node.h"
#include "core/host/graph/graph_edge.h"
#include "core/host/graph/graph_entry.h"
#include "core/host/graph/graph_property.h"
#include "core/host/graph/graph_transaction.h"
#include "core/host/graph/graph_cursor.h"
#include "core/host/share/share.h"
#include "core/host/share/share_database.h"

namespace host {

GraphBackend::GraphBackend(Graph* graph): graph_(graph), storage_(nullptr), initialized_(false), closed_(false) {

}

GraphBackend::~GraphBackend() {
  
}

// bool GraphBackend::Init() {
//   DCHECK(graph_->in_memory());
//   scoped_refptr<ShareDatabase> null_ref;
//   return InitInternal(null_ref, true);
// }

bool GraphBackend::Init(const scoped_refptr<ShareDatabase>& db, bool in_memory) {
  return InitInternal(db, false);
}

bool GraphBackend::InitInternal(const scoped_refptr<ShareDatabase>& db, bool in_memory) {
  std::unique_ptr<GraphStorage> storage = CreateStorage(db, in_memory);
  storage_ = storage.get(); 
  storages_.emplace(std::make_pair(graph_->name(), std::move(storage)));

  initialized_ = true;
  
  return initialized_;
}

std::unique_ptr<GraphTransaction> GraphBackend::Begin(bool write) {
  DCHECK(initialized_);
  return storage_->Begin(write);
}

std::unique_ptr<GraphCursor> GraphBackend::CreateCursor(GraphTransaction* transaction) {
  return storage_->CreateCursor(transaction);
}

void GraphBackend::Close(GraphTransaction* transaction) {
  storage_->Close();
  closed_ = true;
}

graph_t GraphBackend::GetNextId(GraphTransaction* transaction, GraphKeyspace keyspace) {
  return storage_->GetNextId(transaction, keyspace);
}

size_t GraphBackend::CountEntries(GraphTransaction* transaction) {
  return storage_->CountEntries();
}

size_t GraphBackend::CountNodes(GraphTransaction* transaction) {
  return storage_->CountNodes(transaction);
}

size_t GraphBackend::CountEdges(GraphTransaction* transaction) {
  return storage_->CountEdges(transaction);
}

GraphEntry* GraphBackend::GetEntry(GraphTransaction* transaction, graph_t id) {
  return storage_->GetEntry(transaction, id);  
}

GraphProperty* GraphBackend::GetProperty(GraphTransaction* transaction, graph_t id) {
  return storage_->GetProperty(transaction, id);
}

GraphNode* GraphBackend::GetNode(GraphTransaction* transaction, graph_t id) {
  return storage_->GetNode(transaction, id);
}

GraphEdge* GraphBackend::GetEdge(GraphTransaction* transaction, graph_t id) {
  return storage_->GetEdge(transaction, id);
}

GraphNode* GraphBackend::GetNode(GraphTransaction* transaction, base::StringPiece type, base::StringPiece value) {
  return storage_->GetNode(transaction, type, value);
}

GraphEdge* GraphBackend::GetEdge(GraphTransaction* transaction, base::StringPiece type, base::StringPiece value) {
  return storage_->GetEdge(transaction, type, value);
}

GraphProperty* GraphBackend::GetProperty(GraphTransaction* transaction, base::StringPiece key) {
  return storage_->GetProperty(transaction, key);
}

GraphProperty* GraphBackend::GetProperty(GraphTransaction* transaction, GraphNode* node, base::StringPiece key) {
  return storage_->GetProperty(transaction, node, key);
}

GraphProperty* GraphBackend::GetProperty(GraphTransaction* transaction, GraphEdge* edge, base::StringPiece key) {
  return storage_->GetProperty(transaction, edge, key);
}

GraphProperty* GraphBackend::GetProperty(GraphTransaction* transaction, GraphProperty* property, base::StringPiece key) {
  return storage_->GetProperty(transaction, property, key);
}

bool GraphBackend::GetBlob(GraphTransaction* transaction, graph_t blob_id, std::string* out) const {
  return storage_->GetBlob(transaction, blob_id, out);
}

bool GraphBackend::ResolveBlob(GraphTransaction* transaction, graph_t* ret_id, const std::string& value, bool readonly) const {
  return storage_->ResolveBlob(transaction, ret_id, value, readonly);
}

std::unique_ptr<GraphCursor> GraphBackend::GetNodes(GraphTransaction* transaction) {
  return storage_->GetNodes(transaction);
}

std::unique_ptr<GraphCursor> GraphBackend::GetEdges(GraphTransaction* transaction) {
  return storage_->GetEdges(transaction);
}

bool GraphBackend::InsertNode(GraphTransaction* transaction, GraphNode* node) {
  return storage_->InsertNode(transaction, node);
}

bool GraphBackend::InsertEdge(GraphTransaction* transaction, GraphEdge* edge) {
  return storage_->InsertEdge(transaction, edge);
}

bool GraphBackend::InsertProperty(GraphTransaction* transaction, GraphProperty* property) {
  return storage_->InsertProperty(transaction, property);
}

graph_t GraphBackend::DeleteEntry(GraphTransaction* transaction, GraphEntry* entry) {
  return storage_->DeleteEntry(transaction, entry);
}

graph_t GraphBackend::DeleteNode(GraphTransaction* transaction, GraphNode* node) {
  return storage_->DeleteNode(transaction, node);
}

graph_t GraphBackend::DeleteEdge(GraphTransaction* transaction, GraphEdge* edge) {
  return storage_->DeleteEdge(transaction, edge);
}

graph_t GraphBackend::DeleteProperty(GraphTransaction* transaction, GraphProperty* property) {
  return storage_->DeleteProperty(transaction, property);
}

std::unique_ptr<GraphStorage> GraphBackend::CreateStorage(const scoped_refptr<ShareDatabase>& db, bool in_memory) {
  if (in_memory) {
    in_memory_db_ = ShareDatabase::CreateMemory(db->delegate(), kGraphKeyspaceNames);
    return std::make_unique<GraphDbStorage>(graph_, in_memory_db_.get());
  } 
  return std::make_unique<GraphDbStorage>(graph_, db);
}

}