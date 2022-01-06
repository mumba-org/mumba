// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_GRAPH_GRAPH_H_
#define MUMBA_HOST_GRAPH_GRAPH_H_

#include <unordered_map>

#include "base/macros.h"
#include "base/uuid.h"
#include "base/strings/string_piece.h"
#include "core/common/proto/objects.pb.h"
#include "storage/db/db.h"
#include "storage/torrent.h"
#include "core/host/serializable.h"
#include "core/host/graph/graph_common.h"
#include "third_party/protobuf/src/google/protobuf/message.h"

namespace host {
class GraphTransaction;
class GraphCursor;
class GraphEntry;
class GraphNode;
class GraphEdge;
class GraphEntryBase;
class GraphProperty;
class GraphManager;
class GraphBackend;
class ShareDatabase;

enum class GraphDirection : int {
  IN = 0,
  OUT = 1,
  BOTH = 2
};

struct GraphParams {
  std::string name;
  base::UUID uuid;
  bool in_memory = false;
};

class Graph : public Serializable {
public:

  static char kClassName[];
  
  static void CreateGraph(const GraphParams& params, base::Callback<void(int, Graph*)> cb);
  static void OpenGraph(const GraphParams& params, base::Callback<void(int, Graph*)> cb);
  static bool DropGraph(const GraphParams& params);
  static std::unique_ptr<Graph> Deserialize(scoped_refptr<ShareDatabase> db, net::IOBuffer* buffer, int size);

  ~Graph() override;

  const base::UUID& uuid() const {
    return uuid_;
  }

  const std::string& name() const {
    return graph_proto_.name();
  }

  bool is_managed() const {
    return managed_;
  }

  void set_managed(bool managed) {
    managed_ = managed;
  }

  bool in_memory() const {
    return graph_proto_.memory();
  }

  std::unique_ptr<GraphTransaction> Begin(bool write);
  std::unique_ptr<GraphCursor> CreateCursor(GraphTransaction* transaction) const;
  size_t CountEntries(GraphTransaction* transaction);
  graph_t GetNextId(GraphTransaction* transaction, GraphKeyspace keyspace);
  void Close(GraphTransaction* transaction);

  const std::string& GetKeyspace(GraphKeyspace id) const {
    return kGraphKeyspaces.find(id)->second;
  }

  GraphEntry* GetEntry(GraphTransaction* transaction, graph_t id);
  GraphProperty* GetProperty(GraphTransaction* transaction, graph_t id);
  GraphNode* GetNode(GraphTransaction* transaction, graph_t id);
  GraphEdge* GetEdge(GraphTransaction* transaction, graph_t id);

  graph_t GetLastId(GraphTransaction* transaction) const;
  graph_t GetLastIdOf(GraphTransaction* transaction, GraphEntry* entry) const;
  graph_t GetLastIdOf(GraphTransaction* transaction, GraphNode* node) const;
  graph_t GetLastIdOf(GraphTransaction* transaction, GraphEdge* edge) const;
  graph_t GetLastIdOf(GraphTransaction* transaction, GraphProperty* property) const;

  GraphProperty* GetProperty(GraphTransaction* transaction, base::StringPiece key) const;
  GraphProperty* GetProperty(GraphTransaction* transaction, GraphNode* node, base::StringPiece key) const;
  GraphProperty* GetProperty(GraphTransaction* transaction, GraphEdge* edge, base::StringPiece key) const;
  GraphProperty* GetProperty(GraphTransaction* transaction, GraphProperty* property, base::StringPiece key) const;

  GraphProperty* SetProperty(GraphTransaction* transaction, base::StringPiece key, base::StringPiece value);
  GraphProperty* SetProperty(GraphTransaction* transaction, GraphNode* node, base::StringPiece key, base::StringPiece value);
  GraphProperty* SetProperty(GraphTransaction* transaction, GraphEdge* edge, base::StringPiece key, base::StringPiece value);
  GraphProperty* SetProperty(GraphTransaction* transaction, GraphProperty* property, base::StringPiece key, base::StringPiece value);

  void UnsetProperty(GraphTransaction* transaction, base::StringPiece key);
  void UnsetProperty(GraphTransaction* transaction, GraphNode* node, base::StringPiece key);
  void UnsetProperty(GraphTransaction* transaction, GraphEdge* edge, base::StringPiece key);
  void UnsetProperty(GraphTransaction* transaction, GraphProperty* property, base::StringPiece key);

  bool InsertNode(GraphTransaction* transaction, GraphNode* node);
  bool InsertEdge(GraphTransaction* transaction, GraphEdge* edge);
  bool InsertProperty(GraphTransaction* transaction, GraphProperty* property);

  GraphNode* LookupNode(GraphTransaction* transaction, base::StringPiece type, base::StringPiece value) const;
  GraphEdge* LookupEdge(GraphTransaction* transaction, base::StringPiece type, base::StringPiece value) const;
  //GraphProperty* LookupProperty(GraphTransaction* transaction, base::StringPiece type, base::StringPiece value, graph_t anchor) const;

  GraphNode* ResolveNode(GraphTransaction* transaction, base::StringPiece type, base::StringPiece value);
  GraphEdge* ResolveEdge(GraphTransaction* transaction, GraphNode* src, GraphNode* target, base::StringPiece type, base::StringPiece value);
  bool GetBlob(GraphTransaction* transaction, graph_t blob_id, std::string* out) const;
  bool ResolveBlob(GraphTransaction* transaction, graph_t* ret_id, const std::string& value, bool readonly) const;

  size_t CountNodes(GraphTransaction* transaction);
  size_t CountEdges(GraphTransaction* transaction);

  std::unique_ptr<GraphCursor> GetNodes(GraphTransaction* transaction);
  std::unique_ptr<GraphCursor> GetEdges(GraphTransaction* transaction);
  std::unique_ptr<GraphCursor> GetNodesOfType(GraphTransaction* transaction, base::StringPiece type);
  std::unique_ptr<GraphCursor> GetEdgesOfType(GraphTransaction* transaction, base::StringPiece type);
  std::unique_ptr<GraphCursor> GetNodeEdges(GraphTransaction* transaction, GraphNode* node);
  std::unique_ptr<GraphCursor> GetNodeEdgesIn(GraphTransaction* transaction, GraphNode* node);
  std::unique_ptr<GraphCursor> GetNodeEdgesOut(GraphTransaction* transaction, GraphNode* node);
  std::unique_ptr<GraphCursor> GetNodeEdgesDirection(GraphTransaction* transaction, GraphNode* node, GraphDirection direction);
  std::unique_ptr<GraphCursor> GetNodeEdgesType(GraphTransaction* transaction, GraphNode* node, base::StringPiece type);
  std::unique_ptr<GraphCursor> GetNodeEdgesTypeIn(GraphTransaction* transaction, GraphNode* node, base::StringPiece type);
  std::unique_ptr<GraphCursor> GetNodeEdgesTypeOut(GraphTransaction* transaction, GraphNode* node, base::StringPiece type);
  std::unique_ptr<GraphCursor> GetNodeEdgesDirectionType(GraphTransaction* transaction, GraphNode* node, GraphDirection direction, base::StringPiece type);
  std::unique_ptr<GraphCursor> GetProperties(GraphTransaction* transaction);
  std::unique_ptr<GraphCursor> GetNodeProperties(GraphTransaction* transaction, GraphNode* node);
  std::unique_ptr<GraphCursor> GetEdgeProperties(GraphTransaction* transaction, GraphEdge* edge);
  std::unique_ptr<GraphCursor> GetPropertyProperties(GraphTransaction* transaction, GraphProperty* property);
  graph_t DeleteEntry(GraphTransaction* transaction, GraphEntry* entry);
  graph_t DeleteNode(GraphTransaction* transaction, GraphNode* node);
  graph_t DeleteEdge(GraphTransaction* transaction, GraphEdge* edge);
  graph_t DeleteProperty(GraphTransaction* transaction, GraphProperty* property);

  scoped_refptr<net::IOBufferWithSize> Serialize() const override;

protected:
  Graph(scoped_refptr<ShareDatabase> db, const std::string& name, base::UUID uuid);
  Graph(scoped_refptr<ShareDatabase> db, base::UUID uuid, protocol::Graph graph_proto);
  //Graph(const std::string& name, base::UUID uuid);
  //Graph(base::UUID uuid, protocol::Graph graph_proto);

private:
  friend class GraphManager;

  void BindOpenedDatabase(scoped_refptr<ShareDatabase> db);

  base::UUID uuid_;
  protocol::Graph graph_proto_;
  scoped_refptr<ShareDatabase> db_;
  std::unique_ptr<GraphBackend> backend_;
  bool closed_;
  bool managed_;

  DISALLOW_COPY_AND_ASSIGN(Graph);
};

}

#endif
