// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/storage/namespace.h"

#include "base/bind.h"
#include "base/callback.h"
#include "core/domain/id_generator.h"
//#include "core/domain/io/connection.h"
#include "core/shared/domain/storage/stream_session.h"
//#include "core/domain/io/connection_pool.h"
//#include "core/domain/concept/concept_graph.h"
#include "core/shared/domain/storage/namespace_storage.h"
#include "core/shared/domain/storage/namespace_manager.h"

namespace domain {

Namespace::Namespace(NamespaceManager* manager, const base::UUID& id, //const std::string& name,
  bool in_memory):
 manager_(manager),
 //connection_pool_(new ConnectionPool()),
 id_(id),
// name_(name),
 initialized_(false),
 in_memory_(in_memory),
 weak_factory_(this) {
  
}

Namespace::Namespace(NamespaceManager* manager, bool in_memory): // const std::string& name, bool in_memory): 
  manager_(manager),
  //connection_pool_(new ConnectionPool()),
  id_(base::UUID::generate()),
  //name_(name),
  initialized_(false),
  in_memory_(in_memory),
  weak_factory_(this) {

}

Namespace::~Namespace() {
  //routes_.clear();
  sessions_.clear();
}

disk::Disk* Namespace::disk() const {
  return manager_->disk();
}

// void Namespace::Initialize() {
  
// }

void Namespace::Initialize(base::Closure on_init, scoped_refptr<base::TaskRunner> reply_to) {
  const base::FilePath& namespaces_path = manager_->namespaces_path();

  //DLOG(INFO) << "namespaces_path: " << namespaces_path;
  
  if (initialized_) {
    return;
  }

  storage_.reset(new NamespaceStorage(
    this,//weak_factory_.GetWeakPtr(), 
    in_memory_));

  storage_->Initialize(id_, namespaces_path, std::move(on_init), reply_to);
}

void Namespace::Shutdown() {
  if (!initialized_) {
    return;
  }

  storage_->Shutdown();
  //connection_pool_->Shutdown();
  initialized_ = false;
}


void Namespace::AddObserver(NamespaceObserver* observer) {
  observers_.push_back(observer);
}

void Namespace::RemoveObserver(NamespaceObserver* observer) {
  for (auto it = observers_.begin(); it != observers_.end(); it++) {
    if (*it == observer) {
      observers_.erase(it);
      return;
    }
  }
}

// ConceptNode* Namespace::CreateConcept(const std::string& name, const std::string& type_name) {
//   std::unique_ptr<ConceptNode> concept(new ConceptNode(this, name, type_name));
//   ConceptNode* handle = concept.get();
//   AddConcept(std::move(concept));
//   return handle;
// }

// ConceptNode* Namespace::GetConcept(const std::string& name) const {
//   auto it = routes_.find(name);
//   if (it != routes_.end()) {
//     return it->second.get();
//   }
//   return nullptr;
//}

// void Namespace::AddConcept(std::unique_ptr<ConceptNode> concept) {
//   ConceptNode* concept_handle = concept.get();
//   routes_.emplace(std::make_pair(concept_handle->name(), std::move(concept)));
//   // if its managed its already persisted on the graph
//   // just add it to the on-heap cache
//   if (!concept_handle->is_managed()) {
//     // new concept just living on heap eg. when it comes from CreateConcept()
//     // todo: enforce the in_memory policy too
//     concept_graph_->AddNode(concept_handle, base::Bind(&Namespace::OnConceptAddOnGraph, base::Unretained(this)));
//   }
//   NotifyConceptAdded(concept_handle);
// }

// void Namespace::RemoveConcept(const std::string& concept_name) {
//   auto it = routes_.find(concept_name);
//   if (it != routes_.end()) {
//     NotifyConceptRemoved(it->second.get());
//     routes_.erase(it);
//     return;
//   }
// }

StreamSession* Namespace::CreateSession() {
  std::unique_ptr<StreamSession> session(new StreamSession());
  StreamSession* ptr = session.get();
  AddSession(std::move(session));
  return ptr;
}

void Namespace::AddSession(std::unique_ptr<StreamSession> session) {
  StreamSession* sess_handle = session.get();
  sessions_.emplace(std::make_pair(session->id(), std::move(session)));
  NotifySessionAdded(sess_handle);
}

void Namespace::RemoveSession(const base::UUID& sess_id) {
  auto it = sessions_.find(sess_id);
  if (it != sessions_.end()) {
    NotifySessionRemoved(it->second.get());
    sessions_.erase(it);
    return;
  } 
}

void Namespace::OnNamespaceStorageInit(bool result, base::Closure on_init) {
  //DLOG(INFO) << "NamespaceStorageInit. ok? " << result;
  //std::vector<std::unique_ptr<ConceptNode>> routes;
  // We should fill the persisted routes here now..
  if (result) { // ok
   // DCHECK(storage_->graph_db());
    //concept_graph_.reset(new ConceptGraph(storage_->graph_db()));
    //if (!concept_graph_->Init()) {
    //  LOG(ERROR) << "concept graph initialization failed";
    //
    //}
    //if (!concept_graph_->FillAllNodes(this, &routes)) {
    //  LOG(ERROR) << "loading nodes from concept graph failed";  
    //}

    //DLOG(INFO) << "adding routes. count: " << routes.size();
    //for (auto it = routes.begin(); it != routes.end(); it++) {
    //  AddConcept(std::move(*it));
    //}

    initialized_ = true;
  } else {
    LOG(ERROR) << "error initializing namespace storage";
  }

  if (!on_init.is_null()) {
    //DLOG(INFO) << "calling on_init callback";
    on_init.Run();
  }
}

// void Namespace::OnConceptStateChanged(ConceptNode* concept, ConceptState new_state) {
//   if (new_state == ConceptState::Up) {
//     NotifyConceptUp(concept);
//   } else if (new_state == ConceptState::Down) {
//     NotifyConceptDown(concept);
//   }
// }

// void Namespace::OnConceptSubscribe(ConceptNode* concept, StreamSession* session) {
  
// }

// void Namespace::OnConceptUnsubscribe(ConceptNode* concept, StreamSession* session) {

// }

// void Namespace::NotifyConceptAdded(ConceptNode* concept) {
//   for (auto it = observers_.begin(); it != observers_.end(); ++it) {
//     (*it)->OnConceptAdded(concept);
//   }
// }

// void Namespace::NotifyConceptRemoved(ConceptNode* concept) {
//   for (auto it = observers_.begin(); it != observers_.end(); ++it) {
//     (*it)->OnConceptRemoved(concept);
//   }
//}

// void Namespace::NotifyConceptUp(ConceptNode* concept) {
//   for (auto it = observers_.begin(); it != observers_.end(); ++it) {
//     (*it)->OnConceptUp(concept);
//   }
// }

// void Namespace::NotifyConceptDown(ConceptNode* concept) {
//   for (auto it = observers_.begin(); it != observers_.end(); ++it) {
//     (*it)->OnConceptDown(concept);
//   }
//}

void Namespace::NotifySessionAdded(StreamSession* sess) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    (*it)->OnSessionAdded(sess);
  }
}

void Namespace::NotifySessionRemoved(StreamSession* sess) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    (*it)->OnSessionRemoved(sess);
  }
}

//void Namespace::OnConceptAddOnGraph(bool result) {
//  if (!result) {
//    LOG(ERROR) << "concept not added on Graph. error";
//  }  
    //LOG(INFO) << "Concept added on Graph with success";
  //} else {
  //  LOG(INFO) << "Concept not added on Graph. error";
  //}
//}

}