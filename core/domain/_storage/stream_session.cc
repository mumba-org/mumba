// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/storage/stream_session.h"

//#include "core/domain/execution/stream_queue.h"

namespace domain {

StreamSession::StreamSession():
 id_(base::UUID::generate()){//,
 //queue_(new StreamQueue()) {

}

StreamSession::~StreamSession() {
  subscriptions_.clear();
}

void StreamSession::AddSubscription(ConceptSubscription* subscription) {
  subscriptions_.push_back(subscription);
}

void StreamSession::RemoveSubscription(ConceptSubscription* subscription) {
  for (auto it = subscriptions_.begin(); it != subscriptions_.end(); it++) {
    if (subscription == *it) {
      subscriptions_.erase(it);
    }
  }
}

}