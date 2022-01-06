// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_EXECUTION_STREAM_SESSION_H_
#define MUMBA_DOMAIN_EXECUTION_STREAM_SESSION_H_

#include "base/macros.h"
#include "base/uuid.h"

namespace domain {
class StreamQueue;
class ConceptSubscription;

class StreamSession {
public:
  StreamSession();
  ~StreamSession();

  const base::UUID& id() const {
    return id_;
  }

  void AddSubscription(ConceptSubscription* subscription);
  void RemoveSubscription(ConceptSubscription* subscription);

private:

  base::UUID id_;

  std::unique_ptr<StreamQueue> queue_;
  
  // owned by ConceptNode
  std::vector<ConceptSubscription *> subscriptions_;

  DISALLOW_COPY_AND_ASSIGN(StreamSession);
};

}

#endif