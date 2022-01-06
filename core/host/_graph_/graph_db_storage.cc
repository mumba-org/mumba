// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/graph/graph_db_storage.h"

#include "core/host/graph/graph_transaction.h"
#include "core/host/graph/graph_node.h"
#include "core/host/graph/graph_edge.h"
#include "core/host/graph/graph_property.h"
#include "core/host/graph/graph_codec.h"
#include "core/host/graph/graph_manager.h"
#include "core/host/graph/graph_db_transaction.h"
#include "core/host/graph/graph_db_cursor.h"
#include "core/common/protocol/message_serialization.h"
#include "third_party/zlib/zlib.h"

namespace host {

GraphDbStorage::GraphDbStorage(Graph* graph, scoped_refptr<ShareDatabase> db):
 graph_(graph),
 db_(db) {

}

GraphDbStorage::~GraphDbStorage() {

}

std::unique_ptr<GraphTransaction> GraphDbStorage::Begin(bool write) {
  storage::Transaction* db_trans = db_->Begin(write);
  return std::unique_ptr<GraphDbTransaction>(new GraphDbTransaction(graph_, db_trans));
}

std::unique_ptr<GraphCursor> GraphDbStorage::CreateCursor(GraphTransaction* transaction) {
  return transaction->CreateCursor();
}

void GraphDbStorage::Close() {
  db_->Close();
}

size_t GraphDbStorage::CountEntries() {
  storage::Transaction* tr = db_->Begin(false);
  int count = db_->CountItems(tr, GetKeyspace(GraphKeyspace::ENTRY));
  tr->Commit();
  return count;
}

size_t GraphDbStorage::CountNodes(GraphTransaction* transaction) {
  std::unique_ptr<GraphCursor> cursor = GetNodes(transaction);
  // its safe to pass this count as its over the index
  // which have a 1-1 correlation with nodes
  return cursor->Count();
}

size_t GraphDbStorage::CountEdges(GraphTransaction* transaction) {
  std::unique_ptr<GraphCursor> cursor = GetEdges(transaction);
  // its safe to pass this count as its over the index
  // which have a 1-1 correlation with edges
  return cursor->Count();
}

GraphEntry* GraphDbStorage::GetEntry(GraphTransaction* transaction, graph_t id) {
  // GraphEntry* e = transaction->NewEntry(id);
  // // FIXME: LookupInternal would not work for GraphEntry alone.
  // // as its solving the index before going for the entries table
  // if (!LookupInternal(static_cast<GraphDbTransaction *>(transaction)->transaction_, GraphKeyspace::ENTRY, id, e)) {
  //   return nullptr;
  // }
  // return e;

  // this is broken, fix.. 

  // we need to search for the entry on entries keyspace
  // and then get the type.. with that info we can instantiate the right object
  return nullptr;
}

GraphProperty* GraphDbStorage::GetProperty(GraphTransaction* transaction, graph_t id) {
  GraphProperty* p = transaction->NewProperty(id);
  std::string key, value;
  storage::Transaction* tr = static_cast<GraphDbTransaction *>(transaction)->transaction_;
  
  if (!LookupInternal(tr, GraphKeyspace::PROPERTY_INDEX, id, p)) {
    return nullptr;
  }
  if (p->key_id()) {
    DCHECK(GetBlob(tr, p->key_id(), &key));
    p->set_key(key);
  }
  if (p->value_id()) {
    DCHECK(GetBlob(tr, p->value_id(), &value));
    p->set_value(value);
  }
  return p;
}

GraphNode* GraphDbStorage::GetNode(GraphTransaction* transaction, graph_t id) {
  std::string type, value;
  GraphNode* n = transaction->NewNode(id);
  storage::Transaction* tr = static_cast<GraphDbTransaction *>(transaction)->transaction_;
  
  if (!LookupInternal(tr, GraphKeyspace::NODE_INDEX, id, n)) {
    return nullptr;
  }
  if (n->type_id()) {
    DCHECK(GetBlob(tr, n->type_id(), &type));
    n->set_type(type);
  }
  if (n->value_id()) {
    DCHECK(GetBlob(tr, n->value_id(), &value));
    n->set_value(type);
  }
  return n;
}

GraphEdge* GraphDbStorage::GetEdge(GraphTransaction* transaction, graph_t id) {
  std::string type, value;
  GraphEdge* e = transaction->NewEdge(id);
  storage::Transaction* tr = static_cast<GraphDbTransaction *>(transaction)->transaction_;
  
  if (!LookupInternal(tr, GraphKeyspace::EDGE_INDEX, id, e)) {
    return nullptr;
  }
  if (e->type_id()) {
    DCHECK(GetBlob(tr, e->type_id(), &type));
    e->set_type(type);
  }
  if (e->value_id()) {
    DCHECK(GetBlob(tr, e->value_id(), &value));
    e->set_value(type);
  }
  return e;
}

GraphNode* GraphDbStorage::GetNode(GraphTransaction* transaction, base::StringPiece type, base::StringPiece value) {
  // graph_t type_id = 0;
  // graph_t value_id = 0;
  GraphNode* n = transaction->NewNode();

  storage::Transaction* tr = static_cast<GraphDbTransaction *>(transaction)->transaction_;

  n->set_type(type.as_string());
  n->set_value(value.as_string());

  // if (!ResolveBlob(tr, &type_id, n->type(), true) || !ResolveBlob(tr, &value_id, n->value(), true)) {
  //   return nullptr;
  // }
  
  // n->set_type_id(type_id);
  // n->set_value_id(value_id);

  if (!LookupInternal(tr, GraphKeyspace::NODE_INDEX, 0, n)) {
    return nullptr;
  }

  return n;
}

GraphEdge* GraphDbStorage::GetEdge(GraphTransaction* transaction, base::StringPiece type, base::StringPiece value) {
  // graph_t type_id = 0;
  // graph_t value_id = 0;
  GraphEdge* e = transaction->NewEdge();
  
  storage::Transaction* tr = static_cast<GraphDbTransaction *>(transaction)->transaction_;

  e->set_type(type.as_string());
  e->set_value(value.as_string());

  // if (!ResolveBlob(tr, &type_id, e->type(), true) || !ResolveBlob(tr, &value_id, e->value(), true)) {
  //   return nullptr;
  // }
  // e->set_type_id(type_id);
  // e->set_value_id(value_id);

  if (!LookupInternal(tr, GraphKeyspace::EDGE_INDEX, 0, e)) {
    return nullptr;
  }

  return e;
}

GraphProperty* GraphDbStorage::GetProperty(GraphTransaction* transaction, base::StringPiece key) {
  return GetPropertyInternal(transaction, nullptr, key);
}

GraphProperty* GraphDbStorage::GetProperty(GraphTransaction* transaction, GraphNode* node, base::StringPiece key) {
  return GetPropertyInternal(transaction, node, key);
}

GraphProperty* GraphDbStorage::GetProperty(GraphTransaction* transaction, GraphEdge* edge, base::StringPiece key) {
  return GetPropertyInternal(transaction, edge, key);
}

GraphProperty* GraphDbStorage::GetProperty(GraphTransaction* transaction, GraphProperty* property, base::StringPiece key) {
  return GetPropertyInternal(transaction, property, key);
}

GraphProperty* GraphDbStorage::GetPropertyInternal(GraphTransaction* transaction, GraphEntryBase* parent, base::StringPiece key) {
  // graph_t key_id = 0;
  std::string value;

  GraphProperty* p = transaction->NewProperty();
  
  p->set_key(key.as_string());
  if (parent) {
    p->set_parent(parent);
  }

  storage::Transaction* tr = static_cast<GraphDbTransaction *>(transaction)->transaction_;

  // if (!ResolveBlob(tr, &key_id, p->key(), true)) {
  //   return nullptr;
  // }

  // p->set_key_id(key_id);

  if (!LookupInternal(tr, GraphKeyspace::PROPERTY_INDEX, 0, p)) {
    return nullptr;
  }

  if (p->value_id()) {
    DCHECK(GetBlob(tr, p->value_id(), &value));
    p->set_value(value);
  }
  
  return p;
}

std::unique_ptr<GraphCursor> GraphDbStorage::GetNodes(GraphTransaction* transaction) {
  return transaction->CreateCursor(GraphKeyspace::NODE_INDEX);
}

std::unique_ptr<GraphCursor> GraphDbStorage::GetEdges(GraphTransaction* transaction) {
  return transaction->CreateCursor(GraphKeyspace::EDGE_INDEX);
  
}
  
bool GraphDbStorage::InsertNode(GraphTransaction* transaction, GraphNode* node) {
  //DLOG(INFO) << "InsertNode";
  graph_t node_id = node->id();
  // graph_t type_id = 0;
  // graph_t value_id = 0;

  storage::Transaction* tr = static_cast<GraphDbTransaction *>(transaction)->transaction_;
  storage::Cursor* cursor = tr->CreateCursor(GetKeyspace(GraphKeyspace::ENTRY));
  if (!cursor) {
    DLOG(INFO) << "Graph::InsertNode: cursor for entry table failed";
    return false;
  }

  if (node_id == 0) {
    if (!GetNextId(cursor, &node_id)) {
      return false;
    }
    node->set_id(node_id);
  }

  // if (!ResolveBlob(tr, &type_id, node->type(), false) || 
  //     !ResolveBlob(tr, &value_id, node->value(), false)) {
  //   DLOG(INFO) << "InsertNode: failed to resolve type and value blobs";
  //   return false;
  // }
  // node->set_type_id(type_id);
  // node->set_value_id(value_id);

  if (!InsertEntry(cursor, node->id(), node)) {
    DLOG(INFO) << "InsertNode: failed to insert node on entry table";
    return false;
  }
  return InsertNodeIndex(tr, node);
}

bool GraphDbStorage::InsertEdge(GraphTransaction* transaction, GraphEdge* edge) {
  DLOG(INFO) << "InsertEdge";
  graph_t e_id = edge->id();
  // graph_t type_id = 0;
  // graph_t value_id = 0;
  
  storage::Transaction* tr = static_cast<GraphDbTransaction *>(transaction)->transaction_;
  storage::Cursor* cursor = tr->CreateCursor(GetKeyspace(GraphKeyspace::ENTRY));
  if (!cursor) {
    DLOG(INFO) << "Graph::InsertEdge: cursor for entry table failed";
    return false;
  }

  if (e_id == 0) {
    if (!GetNextId(cursor, &e_id)) {
      return false;
    }
    edge->set_id(e_id);
  }

  // if (!ResolveBlob(tr, &type_id, edge->type(), false) || 
  //     !ResolveBlob(tr, &value_id, edge->value(), false)) {
  //   DLOG(INFO) << "InsertEdge: failed to resolve type and value blobs";
  //   return false;
  // }
  // edge->set_type_id(type_id);
  // edge->set_value_id(value_id);

  if (!InsertEntry(cursor, edge->id(), edge)) {
     DLOG(INFO) << "InsertEdge: failed to insert edge on entry table";
    return false;
  }
  return InsertEdgeIndex(tr, edge);
}

bool GraphDbStorage::InsertProperty(GraphTransaction* transaction, GraphProperty* property) {
  graph_t p_id = property->id();
  // graph_t key_id = 0;
  // graph_t value_id = 0;

  storage::Transaction* tr = static_cast<GraphDbTransaction *>(transaction)->transaction_;
  storage::Cursor* cursor = tr->CreateCursor(GetKeyspace(GraphKeyspace::ENTRY));
  if (!cursor) {
    DLOG(INFO) << "Graph::InsertProperty: cursor for entry table failed";
    return false;
  }

  if (p_id == 0) {
    if (!GetNextId(cursor, &p_id)) {
      return false;
    }
    property->set_id(p_id);
  }

  // if (!ResolveBlob(tr, &key_id, property->key(), false) || 
  //     !ResolveBlob(tr, &value_id, property->value(), false)) {
  //   DLOG(INFO) << "InsertProperty: failed to resolve type and value blobs";
  //   return false;
  // }

  // property->set_key_id(key_id);
  // property->set_value_id(value_id);

  if (!InsertEntry(cursor, property->id(), property)) {
    return false;
  }
  return InsertPropertyIndex(tr, property);
}

bool GraphDbStorage::InsertEntry(GraphTransaction* tr, graph_t id, GraphEntryBase* data) {
  storage::Transaction* transaction = static_cast<GraphDbTransaction*>(tr)->transaction_;
  storage::Cursor* cursor = transaction->CreateCursor(GetKeyspace(GraphKeyspace::ENTRY));
  if (!cursor) {
    DLOG(INFO) << "Graph::InsertEntry: cursor for entry table failed";
    return false;
  }
  return InsertEntry(cursor, id, data);
}

graph_t GraphDbStorage::DeleteEntry(GraphTransaction* transaction, GraphEntry* entry) {
  return 0;
  //return DeleteEntry(transaction->transaction_, entry->proto_);
}

graph_t GraphDbStorage::DeleteNode(GraphTransaction* transaction, GraphNode* node) {
  return DeleteEntryInternal(transaction, 0, 0, node);
}

graph_t GraphDbStorage::DeleteEdge(GraphTransaction* transaction, GraphEdge* edge) {
  return DeleteEntryInternal(transaction, 0, 0, edge);
}

graph_t GraphDbStorage::DeleteProperty(GraphTransaction* transaction, GraphProperty* property) {
  return DeleteEntryInternal(transaction, 0, 0, property);
}

bool GraphDbStorage::InsertEntry(storage::Cursor* cursor, graph_t id, GraphEntryBase* data) {
  base::StringPiece key = GraphCodec::EncodeInt(id);
  std::string value;
  if (!data->Encode(&value)) {
    DLOG(INFO) << "Graph::InsertEntry: failed to serialize entry";
    return false;
  }
  auto kv = std::make_pair(key, value);
  //DLOG(INFO) << "Graph::InsertEntry: inserting " << id << " => entry: " << data->kind();
  return cursor->Insert(kv);
}

bool GraphDbStorage::DeleteEntryInternal(GraphTransaction* tr, graph_t new_id, graph_t old_id, GraphEntryBase* entry) {
//bool GraphDbStorage::DeleteEntry(GraphTransaction* tr, graph_t new_id, graph_t old_id, protocol::GraphEntry& entry) {
  // std::string old_key = GraphCodec::EncodeInt(old_id);
  // int r = -1;
  // storage::Cursor* cursor = nullptr;
  // bool match = false;
  // storage::Transaction* transaction = static_cast<GraphDbTransaction*>(tr)->transaction_;
  
  // base::StringPiece old_data = db_->Get(transaction, keyspaces_[ENTRY], old_key);
  
  // //DCHECK(entry->ParseFromString(old_data.as_string()));

  // //std::string new_key = GraphCodec::EncodeId(new_id);

  // //entry->set_id(new_id);
  // entry.set_id(new_id);

  // std::string new_entry_data;
  // //if (!entry->Encode(&new_entry_data)) {
  // if (!entry.SerializeToString(&new_entry_data)) {
  //   return false;
  // }
  // db_->Put(transaction, GetKeyspace(GraphKeyspace::ENTRY), old_key, new_entry_data);
  // if (entry.kind() == protocol::GRAPH_NODE) {
  //   cursor = transaction->CreateCursor(GetKeyspace(GraphKeyspace::PROPERTY_INDEX));
  //   r = cursor->SeekTo(old_key, storage::Seek::EQ, &match);
  //   if (match) {
  //     while (cursor->IsValid()) {
  //       protocol::GraphEntry child_entry;
  //       auto item_kv = cursor->GetKV();
  //       DCHECK(child_entry.ParseFromString(item_kv.second.as_string()));
  //       DeleteEntry(tr, new_id, child_entry.id(), child_entry);
  //       cursor->Next();
  //     }
  //   } else {
  //     DLOG(ERROR) << "Graph deletion: no match found in keyspace 'PROPERTY_INDEX' for entry id " << old_id;
  //   }

  //   cursor = transaction->CreateCursor(GetKeyspace(GraphKeyspace::SOURCE_NODE_INDEX));
  //   r = cursor->SeekTo(old_key, storage::Seek::EQ, &match);
  //   if (match) {
  //     while (cursor->IsValid()) {
  //       protocol::GraphEntry child_entry;
  //       auto item_kv = cursor->GetKV();
  //       DCHECK(child_entry.ParseFromString(item_kv.second.as_string()));
  //       DeleteEntry(tr, new_id, child_entry.id(), child_entry);
  //       cursor->Next();
  //     }
  //   } else {
  //     DLOG(ERROR) << "Graph deletion: no match found in keyspace 'SOURCE_NODE_INDEX' for entry id " << old_id;
  //   }

  //   cursor = transaction->CreateCursor(GetKeyspace(GraphKeyspace::TARGET_NODE_INDEX));
  //   r = cursor->SeekTo(old_key, storage::Seek::EQ, &match);
  //   if (match) {
  //     while (cursor->IsValid()) {
  //       protocol::GraphEntry child_entry;
  //       auto item_kv = cursor->GetKV();
  //       DCHECK(child_entry.ParseFromString(item_kv.second.as_string()));
  //       DeleteEntry(tr, new_id, child_entry.id(), child_entry);
  //       cursor->Next();
  //     }
  //   } else {
  //     DLOG(ERROR) << "Graph deletion: no match found in keyspace 'TARGET_NODE_INDEX' for entry id " << old_id;
  //   }
  // } else {
  //   cursor = transaction->CreateCursor(GetKeyspace(GraphKeyspace::PROPERTY_INDEX));
  //   r = cursor->SeekTo(old_key, storage::Seek::EQ, &match);
  //   if (match) {
  //     while (cursor->IsValid()) {
  //       protocol::GraphEntry child_entry;
  //       auto item_kv = cursor->GetKV();
  //       DCHECK(child_entry.ParseFromString(item_kv.second.as_string()));
  //       DeleteEntry(tr, new_id, child_entry.id(), child_entry);
  //       cursor->Next();
  //     }
  //   } else {
  //     DLOG(ERROR) << "Graph deletion: no match found in keyspace 'PROPERTY_INDEX' for entry id " << old_id;
  //   }
  // }
  // //db_->Delete(tr, keyspaces_[ENTRY], key);
  return true;
}

bool GraphDbStorage::LookupInternal(
  storage::Transaction* transaction,
  GraphKeyspace keyspace,
  graph_t anchor,
  GraphEntryBase* out_entry) const {
  
  bool match = false;
  graph_t id_found = 0;
  std::string index_key;
  std::string id_key;

  if (anchor != 0) {
    //DLOG(INFO) << "LookupInternal: a id was given: " << anchor;
    id_key = GraphCodec::EncodeInt(anchor);
  } else {
    storage::Cursor* index_cursor = transaction->CreateCursor(GetKeyspace(keyspace));
    if (!index_cursor) {
      return false;
    }
    if (!out_entry->EncodeIndex(&index_key)) {
      return false;
    }
    int r = index_cursor->SeekTo(index_key, storage::Seek::LE, &match);
    //int r = index_cursor->SeekTo(index_key, storage::Seek::GE, &match);
    //DLOG(INFO) << "LookupInternal: r = " << r << " match: " << (match ? "true" : "false");
    // Dont know why this hack is necessary.. anyway this is needed mostly for Nodes 
    if (r < 0) {
      index_cursor->Next();
    }
    
    //if (match) {
    if (index_cursor->IsValid()) {  
      auto index_kv = index_cursor->GetKV();
      // recover partial data (with at least the id)
      DCHECK(out_entry->DecodeIndex(index_kv.first.as_string()));
      // if (out_entry->is_edge()) {
      //   GraphEdge* edge = static_cast<GraphEdge*>(out_entry);
      //   //DLOG(INFO) << "LookupInternal: found EDGE on index: id = " << edge->id() << " type: " << edge->type_id() << " value: " << edge->value_id() << " source: " << edge->source_id() << " target: " << edge->target_id();
      // } else if (out_entry->is_node()) {
      //   GraphNode* node = static_cast<GraphNode*>(out_entry);
      //   //DLOG(INFO) << "LookupInternal: found NODE on index: id = " << node->id() << " type: " << node->type_id() << " value: " << node->value_id();
      // } else if (out_entry->is_property()) { 
      //   GraphProperty* prop = static_cast<GraphProperty*>(out_entry);
      //   //DLOG(INFO) << "LookupInternal: found PROPERTY on index: id = " << prop->id() << " parent: " << prop->parent_id() << " key: " << prop->key_id() << " value: " << prop->value_id();
      // }
      id_found = out_entry->id();
      id_key = GraphCodec::EncodeInt(id_found);
    }
  }

  if (id_found == 0) {
    //DLOG(INFO) << "LookupInternal: no index was found. returning false";
    return false;
  }

  storage::Cursor* entry_cursor = transaction->CreateCursor(GetKeyspace(GraphKeyspace::ENTRY));
  entry_cursor->SeekTo(id_key, storage::Seek::EQ, &match);
  if (match) {
    auto entry_kv = entry_cursor->GetKV();
    out_entry->Decode(entry_kv.second.as_string());
    // if (out_entry->is_property()) { 
    //   GraphProperty* prop = static_cast<GraphProperty*>(out_entry);
    //   //DLOG(INFO) << "LookupInternal: found PROPERTY on ENTRY table for key " << id_found << ": id: " << prop->id() << " parent: " << prop->parent_id() << " key: " << prop->key_id() << " value: " << prop->value_id();
    // }
  } else {
    DLOG(INFO) << "LookupInternal: index resolved to id " << out_entry->id() << ", but then it was not found on ENTRY table. This should not happen";
  }

  return match;
}

bool GraphDbStorage::GetBlob(GraphTransaction* transaction, graph_t blob_id, std::string* out) const {
  storage::Transaction* db_tr = static_cast<GraphDbTransaction*>(transaction)->transaction_;
  return GetBlob(db_tr, blob_id, out);
}

bool GraphDbStorage::ResolveBlob(GraphTransaction* transaction, graph_t* ret_id, const std::string& value, bool readonly) const {
  storage::Transaction* db_tr = static_cast<GraphDbTransaction*>(transaction)->transaction_;
  return ResolveBlob(db_tr, ret_id, value, readonly);
}

bool GraphDbStorage::ResolveBlob(storage::Transaction* transaction, graph_t* ret_id, const std::string& value, bool readonly) const {
  bool match_idx = false;
  bool match_blob = false;
  storage::Cursor* blob_cursor = nullptr;
  graph_t id = 0;

  storage::Cursor* index_cursor = transaction->CreateCursor(GetKeyspace(GraphKeyspace::BLOB_INDEX));
  if (!index_cursor) {
    DLOG(INFO) << "Graph::ResolveBlob: cursor for blob index table failed";
    return false;
  }
  std::string index_key = GraphCodec::EncodeBlobHash(value);
  // we need a exact match
  int rc = index_cursor->SeekTo(index_key, storage::Seek::EQ, &match_idx);
  if (match_idx) {
    auto idx_data = index_cursor->GetKV();
    graph_t blob_id = GraphCodec::DecodeId(idx_data.second.as_string());
    blob_cursor = transaction->CreateCursor(GetKeyspace(GraphKeyspace::BLOB));
    if (!blob_cursor) {
      DLOG(INFO) << "Graph::ResolveBlob: cursor for blob table failed";
      *ret_id = 0;
      return false;
    }
    std::string blob_key = GraphCodec::EncodeInt(blob_id);
    rc = blob_cursor->SeekTo(blob_key, storage::Seek::EQ, &match_blob);
    // note: match_blob should be true as match_idx implies match blob
    //       or else something is really broken as we have an index pointing to nothing
    if (match_blob) {
      auto blob_kv = blob_cursor->GetKV();
      if (blob_kv.second == value) {
        *ret_id = blob_id;
        return true;
      } else {
        DLOG(INFO) << "ResolveBlob: BAD INTEGRITY! found " << blob_id << " on blob table but payload dont match";
      }
    } else {
      DLOG(INFO) << "ResolveBlob: BAD INTEGRITY! " << blob_id << " was not found on blob table";
    }
  }

  if (readonly) {
    if (!match_idx) {
      *ret_id = 0;
    }
    return match_idx;
  }

  if (!blob_cursor) {
    blob_cursor = transaction->CreateCursor(GetKeyspace(GraphKeyspace::BLOB));
  }

  GetNextId(blob_cursor, &id);
  *ret_id = id;

  // add blob entry
  std::string blob_key = GraphCodec::EncodeInt(id);
  storage::KeyValuePair blob_kv(blob_key, value);
  DCHECK(blob_cursor->Insert(blob_kv));

	// and add index entry
  storage::KeyValuePair index_kv(index_key, blob_key);
  DCHECK(index_cursor->Insert(index_kv));

  return true;
}

bool GraphDbStorage::GetBlob(storage::Transaction* transaction, graph_t blob_id, std::string* out) const {
  bool match_blob = false;
  storage::Cursor* blob_cursor = transaction->CreateCursor(GetKeyspace(GraphKeyspace::BLOB));
  if (!blob_cursor) {
    DLOG(INFO) << "Graph::GetBlob: cursor for blob table failed";
    return false;
  }
  std::string blob_key = GraphCodec::EncodeInt(blob_id);
  blob_cursor->SeekTo(blob_key, storage::Seek::EQ, &match_blob);

  if (match_blob) {
    auto blob_kv = blob_cursor->GetKV();
    out->assign(blob_kv.second.as_string());
    return true;
  }

  return false;
}

bool GraphDbStorage::InsertNodeIndex(storage::Transaction* transaction, GraphNode* node) {
  std::string key;
  base::StringPiece value;
  if (!node->EncodeIndex(&key)) {
    DLOG(INFO) << "Graph::InsertNodeIndex: failed to serialize node";
    return false;
  }
  auto kv = std::make_pair(key, value);
  storage::Cursor* cursor = transaction->CreateCursor(GetKeyspace(GraphKeyspace::NODE_INDEX));
  if (!cursor) {
    DLOG(INFO) << "Graph::InsertNodeIndex: cursor for node index table failed";
    return false;
  }
  return cursor->Insert(kv);
}

bool GraphDbStorage::InsertEdgeIndex(storage::Transaction* transaction, GraphEdge* edge) {
  std::string key, target_key, source_key;
  base::StringPiece value;

  if (!edge->EncodeIndex(&key)) {
    DLOG(INFO) << "Graph::InsertEdgeIndex: failed to serialize edge index";
    return false;
  }

  auto kv = std::make_pair(key, value);
  storage::Cursor* cursor = transaction->CreateCursor(GetKeyspace(GraphKeyspace::EDGE_INDEX));
  if (!cursor) {
    DLOG(INFO) << "Graph::InsertEdgeIndex: cursor for edge index table failed";
    return false;
  }
  if (!cursor->Insert(kv)) {
    return false;
  }

  if (!edge->EncodeTargetIndex(&target_key)) {
    DLOG(INFO) << "Graph::InsertEdgeIndex: failed to serialize edge target index";
    return false;
  }

  storage::Cursor* tgt_cursor = transaction->CreateCursor(GetKeyspace(GraphKeyspace::TARGET_NODE_INDEX));
  if (!tgt_cursor) {
    DLOG(INFO) << "Graph::InsertEdgeIndex: cursor for target node index table failed";
    return false;
  }

  auto tgt_kv = std::make_pair(target_key, value);
  if (!tgt_cursor->Insert(tgt_kv)) {
    return false;
  }

  if (!edge->EncodeSourceIndex(&source_key)) {
    DLOG(INFO) << "Graph::InsertEdgeIndex: failed to serialize edge source index";
    return false;
  }

  storage::Cursor* src_cursor = transaction->CreateCursor(GetKeyspace(GraphKeyspace::SOURCE_NODE_INDEX));
  if (!src_cursor) {
    DLOG(INFO) << "Graph::InsertEdgeIndex: cursor for target node index table failed";
    return false;
  }

  auto src_kv = std::make_pair(source_key, value);
  if (!src_cursor->Insert(src_kv)) {
    return false;
  }

  return true;
}

bool GraphDbStorage::InsertPropertyIndex(storage::Transaction* transaction, GraphProperty* property) {
  std::string key;
  base::StringPiece value;

  if (!property->EncodeIndex(&key)) {
    DLOG(INFO) << "Graph::InsertPropertyIndex: failed to serialize node";
    return false;
  }
  auto kv = std::make_pair(key, value);
  storage::Cursor* cursor = transaction->CreateCursor(GetKeyspace(GraphKeyspace::PROPERTY_INDEX));
  if (!cursor) {
    DLOG(INFO) << "Graph::InsertPropertyIndex: cursor for entry table failed";
    return false;
  }
  return cursor->Insert(kv);
}

graph_t GraphDbStorage::GetNextId(GraphTransaction* transaction, GraphKeyspace keyspace) const {
  GraphDbTransaction* transaction_impl = static_cast<GraphDbTransaction*>(transaction);
  storage::Transaction* tr = transaction_impl->transaction_;
  graph_t next_id = transaction_impl->next_id();
  if (next_id == 0) {
    storage::Cursor* cursor = tr->CreateCursor(GetKeyspace(keyspace));
    cursor->Last();
    if (cursor->IsValid()) {
      auto kv = cursor->GetKV();
      graph_t last_id = GraphCodec::DecodeId(kv.first.as_string());
      transaction_impl->set_next_id(last_id);
    }
  }
  transaction_impl->set_next_id(++next_id);
  return transaction_impl->next_id();
}

bool GraphDbStorage::GetNextId(storage::Cursor* cursor, graph_t* id) const {
  *id = 1;
	// while (cursor->IsValid()) {
  //   auto kv = cursor->GetKV();
	// 	graph_t cur_id = 0;
  //   if (!GraphCodec::DecodeInt(kv.first.as_string(), &cur_id)) {
  //     return false;
  //   }
	// 	if (0 == anchor || cur_id < anchor){
	// 		*id = cur_id;
	// 		break;
	// 	}
  //   cursor->Next();
	// }
  cursor->Last();
  if (cursor->IsValid()) {
    auto kv = cursor->GetKV();
    graph_t cur_id = GraphCodec::DecodeId(kv.first.as_string());
    //if (0 == anchor || cur_id < anchor) {
    *id = cur_id + 1;
	  //}
  }
  return true;
}

graph_t GraphDbStorage::GetMaxId(GraphTransaction* transaction, GraphEntry* entry) {
  graph_t max_id, id;
  storage::Transaction* tr = static_cast<GraphDbTransaction*>(transaction)->transaction_;
  storage::Cursor* cursor = tr->CreateCursor(GetKeyspace(GraphKeyspace::PROPERTY_INDEX));
  // if (anchor) {
  //   max_id = (entry->next_id() && entry->next_id() < anchor) ? entry->next_id() : entry->id();
  //   while (GetNextId(cursor, &id)){
  //     if (id >= anchor) {
	// 			continue;
  //     }
  //     GraphEntry* e = GetEntry(transaction, id);
	// 		if (e->next_id()){
	// 			if (e->next_id() < anchor && e->next_id() > max_id) {
	// 				max_id = e->next_id();
  //       }
	// 		} else if (e->id() > max_id){
	// 			max_id = e->id();
	// 		}
  //   } 
  // } else {
    max_id = entry->next_id() ? entry->next_id() : entry->id();
		while(GetNextId(cursor, &id)){
			GraphEntry* e = GetEntry(transaction, id);
      if (e->next_id()) {
				if (e->next_id() > max_id) {
					max_id = e->next_id();
        }
			} else if (e->id() > max_id){
				max_id = e->id();
			}
		}
  //}
  return max_id;
}

}