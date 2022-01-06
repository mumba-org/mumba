// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_NAMESPACE_H_
#define MUMBA_DOMAIN_NAMESPACE_H_

#include <memory>
#include <unordered_map>
#include <string>

#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "base/files/file_path.h"
#include "core/shared/domain/storage/namespace_storage.h"
#include "core/shared/domain/storage/mount_info.h"
#//include "core/shell/concept/concept_node.h"
#include "base/uuid.h"
//#include "disk/disk.h"

//namespace data {
//class Schema;  
//}

namespace domain {
class NamespaceManager;
class StreamSession;
class ConnectionPool;
class Connection;
//class ConceptGraph;

class NamespaceObserver {
public:
  virtual ~NamespaceObserver() {}
 // virtual void OnConceptAdded(ConceptNode* concept) = 0;
 // virtual void OnConceptRemoved(ConceptNode* concept) = 0;
 // virtual void OnConceptUp(ConceptNode* concept) = 0;
 // virtual void OnConceptDown(ConceptNode* concept) = 0;
  virtual void OnSessionAdded(StreamSession* sess) = 0;
  virtual void OnSessionRemoved(StreamSession* sess) = 0;
};

class Namespace : public NamespaceStorage::Delegate {//,
                //public ConceptNode::Delegate {
public:
  Namespace(NamespaceManager* manager, 
      const base::UUID& id, 
      //const std::string& name, 
      bool in_memory);
  
  Namespace(
    NamespaceManager* manager, 
    //const std::string& name, 
    bool in_memory);

  ~Namespace() override;

  const base::UUID& id() const {
    return id_;
  }

  const std::string& mount_point() const {
    if (is_mounted()) {
      return mounted_at()->mount_point;
    }
    return empty_;
  }

  MountInfo* mounted_at() const {
    return mounted_at_;
  }

  void set_mounted_at(MountInfo* mounted_at) {
    mounted_at_ = mounted_at;
  }

  bool is_mounted() const {
    return mounted_at_ != nullptr;
  }

  bool initialized() const {
    return initialized_;
  }

  // ConnectionPool* connection_pool() const {
  //   return connection_pool_.get();
  // }

  disk::Disk* disk() const;

  void Initialize(base::Closure on_init, scoped_refptr<base::TaskRunner> reply_to);
  void Shutdown();

  void AddObserver(NamespaceObserver* observer);
  void RemoveObserver(NamespaceObserver* observer);

//  ConceptNode* CreateConcept(const std::string& name, const std::string& type_name);
 // ConceptNode* GetConcept(const std::string& name) const;
 // void AddConcept(std::unique_ptr<ConceptNode> concept);
 // void RemoveConcept(const std::string& concept_name);

  StreamSession* CreateSession();
  void AddSession(std::unique_ptr<StreamSession> session);
  void RemoveSession(const base::UUID& sess_id);
   
private:
  
  // NamespaceStorage::Delegate
  //void OnFilesystemInit(int error_code, int fs_id, Filesystem::State state) override;
  //void OnDatabaseInit(int error_code, int db_id, Database::State state) override;
  void OnNamespaceStorageInit(bool result, base::Closure on_init) override;

  // ConceptNode::Delegate
  //void OnConceptStateChanged(ConceptNode* concept, ConceptState new_state) override;
  //void OnConceptSubscribe(ConceptNode* concept, StreamSession* session) override;
  //void OnConceptUnsubscribe(ConceptNode* concept, StreamSession* session) override;
 
  //void NotifyConceptAdded(ConceptNode* concept);
  //void NotifyConceptRemoved(ConceptNode* concept);
  //void NotifyConceptUp(ConceptNode* concept);
  //void NotifyConceptDown(ConceptNode* concept);
  void NotifySessionAdded(StreamSession* sess);
  void NotifySessionRemoved(StreamSession* sess);

  //void OnConceptAddOnGraph(bool result);
    
  NamespaceManager* manager_; 

  std::unique_ptr<NamespaceStorage> storage_;

  std::vector<NamespaceObserver*> observers_;

 // std::unordered_map<std::string, std::unique_ptr<ConceptNode>> routes_;

  //std::unique_ptr<ConceptGraph> concept_graph_;

  std::unordered_map<base::UUID, std::unique_ptr<StreamSession>> sessions_;

  base::UUID id_;

  bool initialized_;

  bool in_memory_;

  MountInfo* mounted_at_;

  std::string empty_;

  base::WeakPtrFactory<Namespace> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(Namespace);
};

}

#endif