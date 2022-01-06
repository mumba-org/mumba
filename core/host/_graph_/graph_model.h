// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_GRAPH_GRAPH_MODEL_H_
#define MUMBA_HOST_GRAPH_GRAPH_MODEL_H_

#include <vector>
#include <memory>

#include "base/macros.h"
#include "base/uuid.h"
#include "base/strings/string_piece.h"
#include "storage/db/db.h"
#include "core/host/database_policy.h"

namespace host {
class Graph;
class GraphManager;
class ShareDatabase;

class GraphModel : public DatabasePolicyObserver {
public:
 GraphModel(GraphManager* manager, scoped_refptr<ShareDatabase> db, DatabasePolicy policy);
 ~GraphModel();

 void Load(base::Callback<void(int, int)> cb);
 size_t CountGraphs();
 Graph* GetGraph(const base::UUID& uuid);
 Graph* GetGraph(const std::string& name);
 void InsertGraph(std::unique_ptr<Graph> graph, bool persist = true);
 void DeleteGraph(const base::UUID& uuid);
 void DeleteGraph(const std::string& name); 
 void DeleteGraph(Graph* graph);
 
private:
 
 void AddGraph(std::unique_ptr<Graph> graph); 
 void RemoveGraph(const base::UUID& uuid);
 void RemoveGraph(const std::string& name);
 void RemoveGraph(Graph* graph);

 void InsertGraphToDB(const base::UUID& id, Graph* graph);
 void RemoveGraphFromDB(Graph* graph);
 void LoadGraphsFromDB(base::Callback<void(int, int)> cb);

 void MaybeOpen();
 void MaybeClose();

 void OnDatabasePolicyChanged(DatabasePolicy new_policy) override;
 
 GraphManager* manager_;
 DatabasePolicy policy_;
 scoped_refptr<ShareDatabase> db_;
 base::Lock graph_vector_lock_;
 std::vector<std::unique_ptr<Graph>> graphs_;

 DISALLOW_COPY_AND_ASSIGN(GraphModel);
};

}

#endif
