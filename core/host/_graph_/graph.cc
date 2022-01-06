// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/graph/graph.h"

#include "core/host/graph/graph_transaction.h"
#include "core/host/graph/graph_node.h"
#include "core/host/graph/graph_edge.h"
#include "core/host/graph/graph_property.h"
#include "core/host/graph/graph_codec.h"
#include "core/host/graph/graph_manager.h"
#include "core/host/graph/graph_backend.h"
#include "core/host/graph/graph_cursor.h"
#include "core/host/graph/system_graph.h"
#include "core/host/share/share_database.h"
#include "core/common/protocol/message_serialization.h"
#include "core/host/host_controller.h"
#include "core/host/workspace/workspace.h"
#include "storage/storage_manager.h"
#include "third_party/zlib/zlib.h"

namespace host {

char Graph::kClassName[] = "graph";

// static 
void Graph::CreateGraph(const GraphParams& params, base::Callback<void(int, Graph*)> cb) {
  scoped_refptr<HostController> controller = HostController::Instance();
  Workspace* workspace = controller->current_workspace();
  GraphManager* manager = workspace->graph_manager();
  manager->CreateGraph(params.name, params.in_memory, std::move(cb));
}

// static 
void Graph::OpenGraph(const GraphParams& params, base::Callback<void(int, Graph*)> cb) {
  scoped_refptr<HostController> controller = HostController::Instance();
  Workspace* workspace = controller->current_workspace();
  GraphManager* manager = workspace->graph_manager();
  if (params.name.empty()) {
    manager->OpenGraph(params.uuid, std::move(cb));
  } else {
    manager->OpenGraph(params.name, std::move(cb));
  }
}

// static 
bool Graph::DropGraph(const GraphParams& params) {
  bool result = false;
  scoped_refptr<HostController> controller = HostController::Instance();
  Workspace* workspace = controller->current_workspace();
  GraphManager* manager = workspace->graph_manager();
  if (params.name.empty()) {
    result = manager->DropGraph(params.uuid);
  } else {
    result = manager->DropGraph(params.name);
  }
  return result;
}

// static
std::unique_ptr<Graph> Graph::Deserialize(scoped_refptr<ShareDatabase> db, net::IOBuffer* buffer, int size) {
  std::unique_ptr<Graph> result;
  protocol::Graph graph_proto;
  protocol::CompoundBuffer cbuffer;
  cbuffer.Append(buffer, size);
  cbuffer.Lock();
  protocol::CompoundBufferInputStream stream(&cbuffer);
  
  if (!graph_proto.ParseFromZeroCopyStream(&stream)) {
    return {};
  }

  //bool ok = false;
  base::UUID uuid(reinterpret_cast<const uint8_t *>(graph_proto.uuid().data()));

  if (graph_proto.name() == "system") {
    DLOG(INFO) << "Graph::Deserialize: returning system graph '" << graph_proto.name() << "'";
    DCHECK(false);
    // scoped_refptr<HostController> controller = HostController::Instance();
    // Workspace* workspace = controller->current_workspace();
    // result.reset(new SystemGraph(workspace, std::move(uuid), std::move(graph_proto)));
  } else {
    //DLOG(INFO) << "Graph::Deserialize: returning graph '" << graph_proto.name() << "'";
    result.reset(new Graph(db, std::move(uuid), std::move(graph_proto)));
  }
  return result;
}

Graph::Graph(scoped_refptr<ShareDatabase> db, base::UUID uuid, protocol::Graph graph_proto):
  uuid_(std::move(uuid)),
  graph_proto_(std::move(graph_proto)),
  db_(db),
  backend_(new GraphBackend(this)),
  closed_(false),
  managed_(false) {

  graph_proto_.set_memory(false);

  if (db_) {
    backend_->Init(db_, db_->in_memory()); 
  }
}

Graph::Graph(scoped_refptr<ShareDatabase> db, const std::string& name, base::UUID uuid):
  uuid_(std::move(uuid)),
  db_(db),
  backend_(new GraphBackend(this)),
  closed_(false),
  managed_(false) {
  
  graph_proto_.set_name(name);
  graph_proto_.set_uuid(reinterpret_cast<const char*>(uuid_.data), 16);
  graph_proto_.set_memory(false);
  
  if (db_) {
    backend_->Init(db_, db_->in_memory());
  }
}

// Graph::Graph(const std::string& name, base::UUID uuid): 
//   backend_(new GraphBackend(this)) {
  
//   graph_proto_.set_name(name);
//   graph_proto_.set_uuid(reinterpret_cast<const char*>(uuid_.data), 16);
//   graph_proto_.set_memory(true);

//   backend_->Init();
// }

// Graph::Graph(base::UUID uuid, protocol::Graph graph_proto):
//   uuid_(std::move(uuid)),
//   graph_proto_(std::move(graph_proto)),
//   backend_(new GraphBackend(this)),
//   closed_(true),
//   managed_(false) {

//   // this is a deserialized Graph and is in memory
//   // so BindOpenedDatabase() wont get called later
//   if (in_memory()) {
//     backend_->Init();
//   }

// }

Graph::~Graph() {
 
}

void Graph::BindOpenedDatabase(scoped_refptr<ShareDatabase> db) {
  DLOG(INFO) << "Graph::BindOpenedDatabase: " << name();
  db_ = db;
  closed_ = false;

  backend_->Init(db_, db_->in_memory()); 
}

std::unique_ptr<GraphTransaction> Graph::Begin(bool write) {
  // always true now giving write side effects in read only transactions
  // (object bookeeping)
  return backend_->Begin(write);
}

std::unique_ptr<GraphCursor> Graph::CreateCursor(GraphTransaction* transaction) const {
  return backend_->CreateCursor(transaction);
}

size_t Graph::CountEntries(GraphTransaction* transaction) {
  return backend_->CountEntries(transaction);
}

graph_t Graph::GetNextId(GraphTransaction* transaction, GraphKeyspace keyspace) {
  return backend_->GetNextId(transaction, keyspace);
}

void Graph::Close(GraphTransaction* transaction) {
  backend_->Close(transaction);
  closed_ = true;
}

GraphEntry* Graph::GetEntry(GraphTransaction* transaction, graph_t id) {
  return backend_->GetEntry(transaction, id);
}

GraphProperty* Graph::GetProperty(GraphTransaction* transaction, graph_t id) {
  return backend_->GetProperty(transaction, id);
}

GraphNode* Graph::GetNode(GraphTransaction* transaction, graph_t id) {
  return backend_->GetNode(transaction, id);
}

GraphEdge* Graph::GetEdge(GraphTransaction* transaction, graph_t id) {
  return backend_->GetEdge(transaction, id);
}

graph_t Graph::GetLastId(GraphTransaction* transaction) const {
  return 0;
}

graph_t Graph::GetLastIdOf(GraphTransaction* transaction, GraphEntry* entry) const {
  return 0;
}

graph_t Graph::GetLastIdOf(GraphTransaction* transaction, GraphNode* node) const {
  return 0;
}

graph_t Graph::GetLastIdOf(GraphTransaction* transaction, GraphEdge* edge) const {
  return 0;
}
  
graph_t Graph::GetLastIdOf(GraphTransaction* transaction, GraphProperty* property) const {
  return 0;
}

GraphProperty* Graph::GetProperty(GraphTransaction* transaction, base::StringPiece key) const {
  return backend_->GetProperty(transaction, key);
}

GraphProperty* Graph::GetProperty(GraphTransaction* transaction, GraphNode* node, base::StringPiece key) const {
  return backend_->GetProperty(transaction, node, key);
}

GraphProperty* Graph::GetProperty(GraphTransaction* transaction, GraphEdge* edge, base::StringPiece key) const {
  return backend_->GetProperty(transaction, edge, key);
}

GraphProperty* Graph::GetProperty(GraphTransaction* transaction, GraphProperty* property, base::StringPiece key) const {
  return backend_->GetProperty(transaction, property, key);
}

GraphProperty* Graph::SetProperty(GraphTransaction* transaction, base::StringPiece key, base::StringPiece value) {
  GraphProperty* prop = transaction->NewProperty();
  prop->set_key(key.as_string());
  prop->set_value(value.as_string());
  if (!InsertProperty(transaction, prop)) {
    return nullptr;
  }
  return prop;
}

GraphProperty* Graph::SetProperty(GraphTransaction* transaction, GraphNode* node, base::StringPiece key, base::StringPiece value) {
  GraphProperty* prop = transaction->NewProperty();
  prop->set_parent(node);
  prop->set_key(key.as_string());
  prop->set_value(value.as_string());
  if (!InsertProperty(transaction, prop)) {
    return nullptr;
  }
  return prop;
}

GraphProperty* Graph::SetProperty(GraphTransaction* transaction, GraphEdge* edge, base::StringPiece key, base::StringPiece value) {
  GraphProperty* prop = transaction->NewProperty();
  prop->set_parent(edge);
  prop->set_key(key.as_string());
  prop->set_value(value.as_string());
  if (!InsertProperty(transaction, prop)) {
    return nullptr;
  }
  return prop;
}

GraphProperty* Graph::SetProperty(GraphTransaction* transaction, GraphProperty* property, base::StringPiece key, base::StringPiece value) {
  GraphProperty* prop = transaction->NewProperty();
  prop->set_parent(property);
  prop->set_key(key.as_string());
  prop->set_value(value.as_string());
  if (!InsertProperty(transaction, prop)) {
    return nullptr;
  }
  return prop;
}

void Graph::UnsetProperty(GraphTransaction* transaction, base::StringPiece key) {

}

void Graph::UnsetProperty(GraphTransaction* transaction, GraphNode* node, base::StringPiece key) {

}
  
void Graph::UnsetProperty(GraphTransaction* transaction, GraphEdge* edge, base::StringPiece key) {

}

void Graph::UnsetProperty(GraphTransaction* transaction, GraphProperty* property, base::StringPiece key) {

}

GraphNode* Graph::LookupNode(GraphTransaction* transaction, base::StringPiece type, base::StringPiece value) const {
  return backend_->GetNode(transaction, type, value);
}

GraphEdge* Graph::LookupEdge(GraphTransaction* transaction, base::StringPiece type, base::StringPiece value) const {
  return backend_->GetEdge(transaction, type, value);
}

// GraphProperty> Graph::LookupProperty(GraphTransaction* transaction, base::StringPiece type, base::StringPiece value) const {
//   protocol::GraphProperty p;
//   graph_t type_id = 0;
//   graph_t value_id = 0;

//   if (!ResolveBlob(transaction->transaction_, &type_id, type, true) || !ResolveBlob(transaction->transaction_, &value_id, value, true)) {
//     return nullptr;
//   }
//   p.set_type(type_id);
//   p.set_value(value_id);
//   if (!LookupInternal(transaction->transaction_, GraphKeyspace::PROPERTY_INDEX, anchor, &p)) {
//     return nullptr;
//   }
//   return std::make_unique<GraphProperty>(std::move(p));
// }

GraphNode* Graph::ResolveNode(GraphTransaction* transaction, base::StringPiece type, base::StringPiece value) {
  return nullptr;
}

GraphEdge* Graph::ResolveEdge(GraphTransaction* transaction, GraphNode* src, GraphNode* target, base::StringPiece type, base::StringPiece value) {
  return nullptr;
}

bool Graph::GetBlob(GraphTransaction* transaction, graph_t blob_id, std::string* out) const {
  return backend_->GetBlob(transaction, blob_id, out);
}

bool Graph::ResolveBlob(GraphTransaction* transaction, graph_t* ret_id, const std::string& value, bool readonly) const {
  return backend_->ResolveBlob(transaction, ret_id, value, readonly);
}

size_t Graph::CountNodes(GraphTransaction* transaction) {
  return backend_->CountNodes(transaction);
}

size_t Graph::CountEdges(GraphTransaction* transaction) {
  return backend_->CountEdges(transaction);
}

std::unique_ptr<GraphCursor> Graph::GetNodes(GraphTransaction* transaction) {
  return backend_->GetNodes(transaction);
}

std::unique_ptr<GraphCursor> Graph::GetEdges(GraphTransaction* transaction) {
  return backend_->GetEdges(transaction);
}

std::unique_ptr<GraphCursor> Graph::GetNodesOfType(GraphTransaction* transaction, base::StringPiece type) {
  return nullptr;
}

std::unique_ptr<GraphCursor> Graph::GetEdgesOfType(GraphTransaction* transaction, base::StringPiece type) {
  return nullptr;
}

std::unique_ptr<GraphCursor> Graph::GetNodeEdges(GraphTransaction* transaction, GraphNode* node) {
  return nullptr;
}

std::unique_ptr<GraphCursor> Graph::GetNodeEdgesIn(GraphTransaction* transaction, GraphNode* node) {
  return nullptr;
}

std::unique_ptr<GraphCursor> Graph::GetNodeEdgesOut(GraphTransaction* transaction, GraphNode* node) {
  return nullptr;
}

std::unique_ptr<GraphCursor> Graph::GetNodeEdgesDirection(GraphTransaction* transaction, GraphNode* node, GraphDirection direction) {
  return nullptr;
}

std::unique_ptr<GraphCursor> Graph::GetNodeEdgesType(GraphTransaction* transaction, GraphNode* node, base::StringPiece type) {
  return nullptr;
}

std::unique_ptr<GraphCursor> Graph::GetNodeEdgesTypeIn(GraphTransaction* transaction, GraphNode* node, base::StringPiece type) {
  return nullptr;
}

std::unique_ptr<GraphCursor> Graph::GetNodeEdgesTypeOut(GraphTransaction* transaction, GraphNode* node, base::StringPiece type) {
  return nullptr;
}

std::unique_ptr<GraphCursor> Graph::GetNodeEdgesDirectionType(GraphTransaction* transaction, GraphNode* node, GraphDirection direction, base::StringPiece type) {
  return nullptr;
}

std::unique_ptr<GraphCursor> Graph::GetProperties(GraphTransaction* transaction) {
  return nullptr;
}

std::unique_ptr<GraphCursor> Graph::GetNodeProperties(GraphTransaction* transaction, GraphNode* node) {
  return nullptr;
}

std::unique_ptr<GraphCursor> Graph::GetEdgeProperties(GraphTransaction* transaction, GraphEdge* edge) {
  return nullptr;
}

std::unique_ptr<GraphCursor> Graph::GetPropertyProperties(GraphTransaction* transaction, GraphProperty* property) {
  return nullptr;
}

graph_t Graph::DeleteEntry(GraphTransaction* transaction, GraphEntry* entry) {
  return backend_->DeleteEntry(transaction, entry);
}

graph_t Graph::DeleteNode(GraphTransaction* transaction, GraphNode* node) {
  return backend_->DeleteNode(transaction, node);
}

graph_t Graph::DeleteEdge(GraphTransaction* transaction, GraphEdge* edge) {
  return backend_->DeleteEdge(transaction, edge);
}

graph_t Graph::DeleteProperty(GraphTransaction* transaction, GraphProperty* property) {
  return backend_->DeleteProperty(transaction, property);
}

bool Graph::InsertNode(GraphTransaction* transaction, GraphNode* node) {
  return backend_->InsertNode(transaction, node);
}

bool Graph::InsertEdge(GraphTransaction* transaction, GraphEdge* edge) {
  return backend_->InsertEdge(transaction, edge);
}

bool Graph::InsertProperty(GraphTransaction* transaction, GraphProperty* property) {
  return backend_->InsertProperty(transaction, property);
}

scoped_refptr<net::IOBufferWithSize> Graph::Serialize() const {
  return protocol::SerializeMessage(graph_proto_);
}

}
