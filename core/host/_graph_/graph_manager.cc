// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/graph/graph_manager.h"

#include "core/host/graph/graph.h"
#include "core/host/graph/graph_common.h"
#include "core/host/graph/graph_manager.h"
#include "core/host/graph/graph_storage.h"
#include "core/host/graph/graph_system_storage.h"
#include "core/host/graph/system_graph.h"
#include "core/host/graph/graph_db_storage.h"
#include "core/host/workspace/workspace.h"
#include "storage/storage_manager.h"

namespace host {

GraphManager::GraphManager(GraphManagerDelegate* delegate): delegate_(delegate) {
  
}

GraphManager::~GraphManager() {
  
}

void GraphManager::Init(scoped_refptr<ShareDatabase> db, DatabasePolicy policy) {
  graphs_ = std::make_unique<GraphModel>(this, db, policy);
  graphs_->Load(base::Bind(&GraphManager::OnLoad, base::Unretained(this)));
}

void GraphManager::Shutdown() {
  graphs_.reset();
}

void GraphManager::CreateGraph(const std::string& name, bool in_memory, base::Callback<void(int, Graph*)> cb) {
  std::vector<std::string> keyspaces = kGraphKeyspaceNames;
  if (!in_memory) {
    delegate_->CreateDatabase(
      name, 
      std::move(keyspaces),
      base::Bind(&GraphManager::OnGraphCreated, base::Unretained(this), name, in_memory, base::Passed(std::move(cb))));
  } else {
    OnGraphCreated(name, true, std::move(cb), net::OK);
  }
}

void GraphManager::CreateSystemGraph(Workspace* workspace, scoped_refptr<ShareDatabase> db, const std::string& name, base::Callback<void(int, Graph*)> cb) {
  std::unique_ptr<Graph> graph(new SystemGraph(workspace, db, name, base::UUID::generate()));
  Graph* reference = graph.get();
  graphs_->InsertGraph(std::move(graph), true);
  if (!cb.is_null()) {
    std::move(cb).Run(net::OK, reference);
  }
  NotifyGraphCreated(net::OK, reference);
}

void GraphManager::OpenGraph(const std::string& name, base::Callback<void(int, Graph*)> cb) {
  delegate_->OpenDatabase(
    name, 
    base::Bind(&GraphManager::OnGraphOpened, base::Unretained(this), base::UUID(), name, base::Passed(std::move(cb))));
}

void GraphManager::OpenGraph(const base::UUID& uuid, base::Callback<void(int, Graph*)> cb) {
  delegate_->OpenDatabase(
    uuid, 
    base::Bind(&GraphManager::OnGraphOpened, base::Unretained(this), uuid, std::string(), base::Passed(std::move(cb))));
}

bool GraphManager::DropGraph(const std::string& name) {
  bool ok = delegate_->DeleteDatabase(name);
  if (ok) {
    graphs_->DeleteGraph(name);
  }
  return ok;
}

bool GraphManager::DropGraph(const base::UUID& uuid) {
  bool ok = delegate_->DeleteDatabase(uuid);
  if (ok) {
    graphs_->DeleteGraph(uuid);
  }
  return ok;
}

void GraphManager::OnGraphLoadedOnModel(Graph* graph) {
  //if (graph->in_memory()) {
  //  OnGraphLoaded(graph, net::OK);
  //} else {
    delegate_->OpenDatabase(
      graph->uuid(), 
      base::Bind(&GraphManager::OnGraphLoaded,
        base::Unretained(this), 
        base::Unretained(graph)));
  //}
}

void GraphManager::OnGraphCreated(const std::string& name, bool in_memory, base::Callback<void(int, Graph*)> cb, int64_t result) {
  Graph* reference = nullptr;
  if (result == net::OK) {
    std::unique_ptr<Graph> graph;
    //if (!in_memory) {
      scoped_refptr<ShareDatabase> db = delegate_->GetDatabase(name);
      if (!db) {
        DLOG(ERROR) << "Create graph error: no graph named '" << name << "'";
        cb.Run(net::ERR_FAILED, nullptr);
        return;
      }
      graph.reset(new Graph(db, name, db->id()));
    // } else {
    //   graph.reset(new Graph(db, name, base::UUID::generate()));
    // }
    reference = graph.get();
    graphs_->InsertGraph(std::move(graph), !in_memory);
  }
  if (!cb.is_null()) {
    std::move(cb).Run(result, reference);
  }
  NotifyGraphCreated(result, reference);
}

void GraphManager::OnGraphOpened(const base::UUID& uuid, const std::string& name, base::Callback<void(int, Graph*)> cb, int64_t result) {
  Graph* reference = nullptr;
  if (result == net::OK) {
    scoped_refptr<ShareDatabase> db = name.empty() ? delegate_->GetDatabase(uuid) : delegate_->GetDatabase(name);
    std::unique_ptr<Graph> graph(new Graph(db, name.empty() ? db->name() : name, db->id()));
    reference = graph.get();
    graphs_->InsertGraph(std::move(graph));
  }
  if (!cb.is_null()) {
    std::move(cb).Run(result, reference);
  }
  NotifyGraphOpen(result, reference);
}

void GraphManager::OnGraphLoaded(Graph* graph, int64_t result) {
  if (result == net::OK) {
    //if (!graph->in_memory()) {
      scoped_refptr<ShareDatabase> db = delegate_->GetDatabase(graph->uuid());
      DCHECK(db);
      graph->BindOpenedDatabase(db);
    //}
  } else {
    DLOG(INFO) << "error loading database " << graph->uuid().to_string() << " for graph";
  }
  //delegate_->OnGraphOpen(result, graph);
  NotifyGraphOpen(result, graph);
}

void GraphManager::AddObserver(GraphManagerObserver* observer) {
  observers_.push_back(observer);
}

void GraphManager::RemoveObserver(GraphManagerObserver* observer) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    if (observer == *it) {
      observers_.erase(it);
      return;
    }
  }
}

void GraphManager::OnLoad(int r, int count) {
  NotifyGraphsLoad(r, count);
}

void GraphManager::NotifyGraphCreated(int r, Graph* graph) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    GraphManagerObserver* observer = *it;
    observer->OnGraphCreated(r, graph);
  }
}

void GraphManager::NotifyGraphOpen(int r, Graph* graph) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    GraphManagerObserver* observer = *it;
    observer->OnGraphOpen(r, graph);
  }
}

void GraphManager::NotifyGraphRemoved(int r, Graph* graph) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    GraphManagerObserver* observer = *it;
    observer->OnGraphRemoved(r, graph);
  }
}

void GraphManager::NotifyGraphsLoad(int r, int count) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    GraphManagerObserver* observer = *it;
    observer->OnGraphsLoad(r, count);
  }
}


}
