// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_GRAPH_GRAPH_MANAGER_H_
#define MUMBA_HOST_GRAPH_GRAPH_MANAGER_H_

#include "base/macros.h"
#include "base/uuid.h"
#include "base/callback.h"
#include "base/strings/string_piece.h"
#include "storage/torrent.h"
#include "storage/db/db.h"
#include "core/host/graph/graph_model.h"
#include "core/host/graph/graph_manager_delegate.h"
#include "core/host/graph/graph_manager_observer.h"

namespace host {
class Workspace;
class Graph;
class GraphStorage;
class ShareDatabase;
/*
 * There might be many graphs for each workspace
 * The graph manager, as the name implies, helps to manage them
 */
class GraphManager {
public:
 GraphManager(GraphManagerDelegate* delegate);
 ~GraphManager();

 void Init(scoped_refptr<ShareDatabase> db, DatabasePolicy policy);
 void Shutdown();

 GraphModel* model() const {
   return graphs_.get();
 }

 size_t CountGraphs() const {
   return graphs_->CountGraphs();
 }
 Graph* GetGraph(const base::UUID& uuid) const {
   return graphs_->GetGraph(uuid);
 }
 Graph* GetGraph(const std::string& name) const {
   return graphs_->GetGraph(name);
 }
 void CreateGraph(const std::string& name, bool in_memory, base::Callback<void(int, Graph*)> cb = base::Callback<void(int, Graph*)>());
 void CreateSystemGraph(Workspace* workspace, scoped_refptr<ShareDatabase> db, const std::string& name, base::Callback<void(int, Graph*)> cb = base::Callback<void(int, Graph*)>());
 void OpenGraph(const std::string& name, base::Callback<void(int, Graph*)> cb = base::Callback<void(int, Graph*)>());
 void OpenGraph(const base::UUID& uuid, base::Callback<void(int, Graph*)> cb = base::Callback<void(int, Graph*)>());
 bool DropGraph(const std::string& name);
 bool DropGraph(const base::UUID& uuid);

 // called back from model, on the event of graph loading over workspace database
 void OnGraphLoadedOnModel(Graph* graph);

 void AddObserver(GraphManagerObserver* observer);
 void RemoveObserver(GraphManagerObserver* observer);

private:
 
 void OnGraphCreated(const std::string& name, bool in_memory, base::Callback<void(int, Graph*)> cb, int64_t result);
 void OnGraphOpened(const base::UUID& uuid, const std::string& name, base::Callback<void(int, Graph*)> cb, int64_t result);
 void OnGraphLoaded(Graph* graph, int64_t result);

 void OnLoad(int r, int count);

 void NotifyGraphCreated(int r, Graph* graph);
 void NotifyGraphOpen(int r, Graph* graph);
 void NotifyGraphRemoved(int r, Graph* graph);
 void NotifyGraphsLoad(int r, int count);

 GraphManagerDelegate* delegate_;
 
 std::unique_ptr<GraphModel> graphs_;
 std::vector<GraphManagerObserver*> observers_;

 DISALLOW_COPY_AND_ASSIGN(GraphManager);
};

}

#endif
