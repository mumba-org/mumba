// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/graph/graph_model.h"

#include "core/host/graph/graph.h"
#include "core/host/graph/graph_manager.h"
#include "core/host/share/share_database.h"
#include "core/host/workspace/workspace.h"

namespace host {

GraphModel::GraphModel(GraphManager* manager, scoped_refptr<ShareDatabase> db, DatabasePolicy policy):
 manager_(manager),
 policy_(policy),
 db_(db) {
  
}

GraphModel::~GraphModel() {
  graphs_.clear();
  db_ = nullptr;
}

void GraphModel::Load(base::Callback<void(int, int)> cb) {
  LoadGraphsFromDB(std::move(cb));
}

size_t GraphModel::CountGraphs() {
  base::AutoLock lock(graph_vector_lock_);
  size_t size = graphs_.size();
  return size;
}

Graph* GraphModel::GetGraph(const base::UUID& uuid) {
  base::AutoLock lock(graph_vector_lock_);
  for (auto it = graphs_.begin(); it != graphs_.end(); ++it) {
    if ((*it)->uuid() == uuid) {
      return it->get();
    }
  }
  return nullptr;
}

Graph* GraphModel::GetGraph(const std::string& name) {
  base::AutoLock lock(graph_vector_lock_);
  for (auto it = graphs_.begin(); it != graphs_.end(); ++it) {
    if ((*it)->name() == name) {
      return it->get();
    }
  }
  return nullptr;
}

void GraphModel::InsertGraph(std::unique_ptr<Graph> graph, bool persist) {
  Graph* ptr = graph.get();
  AddGraph(std::move(graph));
  if (persist) {
    InsertGraphToDB(ptr->uuid(), ptr);
  }
}

void GraphModel::DeleteGraph(const base::UUID& uuid) {
  Graph* found = GetGraph(uuid);
  if (found) {
    DeleteGraph(found);
  }
}

void GraphModel::DeleteGraph(const std::string& name) {
  Graph* found = GetGraph(name);
  if (found) {
    DeleteGraph(found);
  }
}

void GraphModel::DeleteGraph(Graph* graph) {
  RemoveGraphFromDB(graph);
  RemoveGraph(graph);
}

void GraphModel::AddGraph(std::unique_ptr<Graph> graph) {
  base::AutoLock lock(graph_vector_lock_);
  graphs_.push_back(std::move(graph));
}

void GraphModel::RemoveGraph(const base::UUID& uuid) {
  Graph* found = GetGraph(uuid);
  if (found) {
    RemoveGraph(found);
  }
}

void GraphModel::RemoveGraph(const std::string& name) {
  Graph* found = GetGraph(name);
  if (found) {
    RemoveGraph(found);
  }
}

void GraphModel::RemoveGraph(Graph* graph) {
  base::AutoLock lock(graph_vector_lock_);
  for (auto it = graphs_.begin(); it != graphs_.end(); ++it) {
    if (it->get() == graph) {
      graphs_.erase(it);
      return;
    }
  }
}

void GraphModel::InsertGraphToDB(const base::UUID& id, Graph* graph) {
  scoped_refptr<net::IOBufferWithSize> data = graph->Serialize();
  if (data) {
    MaybeOpen();
    storage::Transaction* trans = db_->Begin(true);
    bool ok = db_->Put(trans, Graph::kClassName, graph->name(), base::StringPiece(data->data(), data->size()));
    ok ? trans->Commit() : trans->Rollback();
    if (!ok) {
      DLOG(ERROR) << "inserting graph " << graph->name() << " failed";
    }
    MaybeClose();
  }
}

void GraphModel::RemoveGraphFromDB(Graph* graph) {
  MaybeOpen();
  storage::Transaction* trans = db_->Begin(true);
  bool ok = db_->Delete(trans, Graph::kClassName, graph->name());
  ok ? trans->Commit() : trans->Rollback();
  MaybeClose();
}

void GraphModel::LoadGraphsFromDB(base::Callback<void(int, int)> cb) {
  size_t count = 0;
  MaybeOpen();
  storage::Transaction* trans = db_->Begin(false);
  storage::Cursor* it = trans->CreateCursor(Graph::kClassName);
  if (!it) {
    DLOG(ERROR) << "GraphModel::LoadGraphsFromDB: creating cursor for 'graph' failed.";
    std::move(cb).Run(net::ERR_FAILED, count);
    return;
  }
  it->First();
  while (it->IsValid()) {
    bool valid = false;
    storage::KeyValuePair kv = storage::DbDecodeKV(it->GetData(), &valid);
    if (valid) {
      scoped_refptr<net::StringIOBuffer> buffer = new net::StringIOBuffer(kv.second.as_string());
      std::unique_ptr<Graph> p = Graph::Deserialize(db_, buffer.get(), kv.second.size());
      if (p) {
        Graph* ptr = p.get();
        p->set_managed(true);
        graph_vector_lock_.Acquire();
        graphs_.push_back(std::move(p));
        graph_vector_lock_.Release();
        manager_->OnGraphLoadedOnModel(ptr);
      } else {
        LOG(ERROR) << "failed to deserialize graph";
      }
    } else {
      LOG(ERROR) << "failed to deserialize graph: it->GetValue() returned nothing";
    }
    it->Next();
    count++;
  }
  trans->Commit();
  MaybeClose();
  std::move(cb).Run(net::OK, count);
}

void GraphModel::MaybeOpen() {
  if (policy_ != DatabasePolicy::OpenClose) {
    return;
  }
  if (!db_->is_open()) {
    db_->Open();
  }
}

void GraphModel::MaybeClose() {
  if (policy_ != DatabasePolicy::OpenClose) {
    return;
  }
  if (db_->is_open()) {
    db_->Close();
  }
}

void GraphModel::OnDatabasePolicyChanged(DatabasePolicy new_policy) {
  policy_ = new_policy;
}

}
