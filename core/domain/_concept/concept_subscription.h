// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_CONCEPT_CONCEPT_SUBSCRIPTION_H_
#define MUMBA_DOMAIN_CONCEPT_CONCEPT_SUBSCRIPTION_H_

#include "base/macros.h"

namespace domain {
class StreamSession;
class ConceptNode;

class ConceptSubscription {
public:
  ConceptSubscription(ConceptNode* concept, StreamSession* session);
  ~ConceptSubscription();

  StreamSession* session() const {
    return session_;
  }

  // disconnect from concept
  void Unsubscribe();
  // Push some data into it
  void Push();
  // Pull some data from it
  void Pull();

private:
  
  ConceptNode* concept_;

  StreamSession* session_;

  DISALLOW_COPY_AND_ASSIGN(ConceptSubscription);
};

}

#endif