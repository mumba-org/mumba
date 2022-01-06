// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/concept/concept_subscription.h"

#include "core/shared/domain/storage/stream_session.h"
#include "core/domain/concept/concept_node.h"

namespace domain {

ConceptSubscription::ConceptSubscription(ConceptNode* concept, StreamSession* session):
  concept_(concept), 
  session_(session) {
  
  session_->AddSubscription(this);
}

ConceptSubscription::~ConceptSubscription() {
  
}

void ConceptSubscription::Unsubscribe() {
  session_->RemoveSubscription(this);
  concept_->Unsubscribe(this);
}

void ConceptSubscription::Push() {
  
}

// Pull some data from it
void ConceptSubscription::Pull() {
  
}

}