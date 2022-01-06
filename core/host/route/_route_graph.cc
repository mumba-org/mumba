// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/route/route_graph.h"

#include "core/host/graph/graph.h"
#include "core/host/graph/graph_transaction.h"
#include "core/host/graph/graph_cursor.h"
#include "core/host/graph/graph_node.h"
#include "core/host/route/route_entry.h"
#include "core/host/route/route_model.h"
#include "core/host/route/route_scheme.h"
#include "core/host/route/route_registry.h"

namespace host {

RouteGraph::RouteGraph(RouteRegistry* registry, Graph* graph): 
  registry_(registry), 
  graph_(graph), 
  current_(nullptr), 
  count_(0) {
  
}

RouteGraph::~RouteGraph() {

}

size_t RouteGraph::count() {
  if (count_ == 0) {
    auto tr = graph_->Begin(false);
    count_ = tr->CountNodes();
    tr->Commit();
  }
  return count_;
}

RouteEntry* RouteGraph::GetCurrent() const {
  return current_;
}

RouteEntry* RouteGraph::Get(size_t offset) const {
  return nullptr;
}

bool RouteGraph::GoTo(const std::string& scheme, const std::string& path) {
  std::string type = scheme;
  std::string value = path.substr(1);
  // std::string type, value;
  // size_t offset = path.find_first_of("/");
  // if (offset != std::string::npos) {
  //   type = path.substr(0, offset);
  //   value = path.substr(offset + 1);
  // }

  std::unique_ptr<GraphTransaction> tr = graph_->Begin(false);
  std::unique_ptr<GraphCursor> nodes = graph_->GetNodes(tr.get());
  //DLOG(INFO) << "RouteGraph::GoTo: nodes on cursor => " << nodes->Count();
  while (nodes->HasNext()) {
    GraphNode* node = nodes->GetNode();
    //DLOG(INFO) << "RouteGraph::GoTo: solving '" << type << ":" << value << "'. looking at node => '" << node->type() << ":" << node->value() << "'";
    if (base::EqualsCaseInsensitiveASCII(node->value(), value)) {
      //DLOG(INFO) << "RouteGraph::GoTo: match for value '" << value << "'!";
      // FIXME: accessing model ptr here can trigger synchronization issues, giving we are doing this from another thread.
      // RouteEntry* entry_ptr = new RouteEntry();
      // RouteModel::OwnedEntry entry(entry_ptr);
      // entry->set_type(common::mojom::RouteEntryType::kROUTE_ENTRY_TYPE_ENTRY);
      // entry->set_name(value);
      // entry->set_url(GURL(type + ":" + value));
      // registry_->model()->AddEntry(std::move(entry));
      if (base::EqualsCaseInsensitiveASCII(node->type(), "url")) {
        //DLOG(INFO) << "RouteGraph::GoTo: node " << node->id() << " is a url already. so just fetching from the url registry";
        RouteEntry* entry_ptr = registry_->model()->GetEntry(scheme, path);
        //DLOG(INFO) << "RouteGraph::GoTo: asking for entry scheme: " << scheme << " path: " << path << " on url registry";
        DCHECK(entry_ptr);
        current_ = entry_ptr;
        tr->Commit();
        return true;
      } else {
        DLOG(INFO) << "RouteGraph::GoTo: node " << node->id() << " is not a url. we need to see if it can be rendered and if so, add a url for it";
      }
    }
    
    nodes->Next();
  }
  tr->Commit();
  return false;
}

bool RouteGraph::GoNext() {
  return false;
}

bool RouteGraph::GoPrevious() {
  return false;
}


}