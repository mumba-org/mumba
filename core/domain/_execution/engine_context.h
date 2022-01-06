// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_MODULE_CONTEXT_H_
#define MUMBA_DOMAIN_MODULE_CONTEXT_H_

#include <memory>

#include "base/memory/ref_counted.h"
#include "base/synchronization/lock.h"
#include "base/single_thread_task_runner.h"
#include "core/domain/concept/concept_node.h"

namespace domain {
class Namespace;

class EngineContext : public ConceptNode::Handler {
public:
  class Delegate {
  public:
    virtual ~Delegate() {}
    //virtual scoped_refptr<base::SingleThreadTaskRunner> CreateTaskRunner() = 0;
    virtual void OnBind(const std::string& concept_name, ConceptNode::Handler* handler) = 0;
    virtual void OnStateChanged(ConceptNode* concept, ConceptState new_state) = 0;
    virtual void OnSub(ConceptNode* concept, StreamSession* session) = 0;
    virtual void OnUnsub(ConceptNode* concept, StreamSession* session) = 0;
  };

  EngineContext(Delegate* delegate, Namespace* ns);
  ~EngineContext();

  Namespace* ns() const {
    return ns_;
  }

  // The event loop on the client side, have a dedicated thread
  // we ask our delegate for it
  //scoped_refptr<base::SingleThreadTaskRunner> CreateEventQueueTaskRunner();
  
  void BindConceptHandler(const std::string& concept_name);

private:

  void OnStateChanged(ConceptNode* concept, ConceptState new_state) override;
  void OnSub(ConceptNode* concept, StreamSession* session) override;
  void OnUnsub(ConceptNode* concept, StreamSession* session) override;
  
  // to call delegate from the Engine
  base::Lock mutex_;

  Delegate* delegate_;

  Namespace* ns_;

  DISALLOW_COPY_AND_ASSIGN(EngineContext);
};

}

#endif