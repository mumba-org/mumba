// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/execution/engine_context.h"

#include "core/shared/domain/storage/namespace.h"

namespace domain {

EngineContext::EngineContext(Delegate* delegate, Namespace* ns): 
  delegate_(delegate),
  ns_(ns) {
  // not an option
  //DCHECK(delegate_);
}

EngineContext::~EngineContext() {

}

// scoped_refptr<base::SingleThreadTaskRunner> EngineContext::CreateEventQueueTaskRunner() {
//   base::AutoLock lock(mutex_);
//   return delegate_->CreateTaskRunner();
// }

void EngineContext::BindConceptHandler(const std::string& concept_name) {
  base::AutoLock lock(mutex_);
  ConceptNode* concept = ns_->GetConcept(concept_name);
  if (!concept) {
    LOG(ERROR) << "EngineContext::BindConceptHandler: concept '" << concept_name << "' not found";
    return;
  }
  concept->AttachHandler(this);
  delegate_->OnBind(concept_name, this);
}

void EngineContext::OnStateChanged(ConceptNode* concept, ConceptState new_state) {
  base::AutoLock lock(mutex_);
  delegate_->OnStateChanged(concept, new_state); 
}

void EngineContext::OnSub(ConceptNode* concept, StreamSession* session) {
  base::AutoLock lock(mutex_);
  delegate_->OnSub(concept, session);
}

void EngineContext::OnUnsub(ConceptNode* concept, StreamSession* session) {
  base::AutoLock lock(mutex_);
  delegate_->OnUnsub(concept, session);
}

}