// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/concept/concept_node.h"

#include "base/task_scheduler/post_task.h"
#include "core/shared/domain/storage/stream_session.h"
#include "data/type.h"
#include "core/domain/concept/concept_subscription.h"

namespace domain {

namespace {

std::vector<std::shared_ptr<data::Field>> any_fields = {
  data::CreateField("rowid", std::make_shared<data::Int64Type>()),
  data::CreateField("name", std::make_shared<data::StringType>()),
};
 
std::vector<std::shared_ptr<data::Field>> module_fields = {
  data::CreateField("rowid", std::make_shared<data::Int64Type>()),
  data::CreateField("name", std::make_shared<data::StringType>()),
  data::CreateField("creator", std::make_shared<data::StringType>()),
  data::CreateField("size", std::make_shared<data::Int64Type>())
};

std::vector<std::shared_ptr<data::Field>> blob_fields = {
  data::CreateField("rowid", std::make_shared<data::Int64Type>()),
  data::CreateField("name", std::make_shared<data::StringType>()),
  data::CreateField("size", std::make_shared<data::Int64Type>())
};
 
std::shared_ptr<data::Schema> CreateSchemaForType(const std::string& type_name) {
  if (type_name == "module") {
    return data::CreateSchema(module_fields);
  } else if (type_name == "blob") {
    return data::CreateSchema(blob_fields);
  }
  return data::CreateSchema(any_fields);
}

}

ConceptNode::ConceptNode(Delegate* delegate, uint64_t gid, const std::string& name, const std::string& type_name):
  gid_(gid),
  name_(name),
  type_name_(type_name),
  state_(ConceptState::Down),
  delegate_(delegate),
  managed_(false),
  handle_(nullptr) {

  
  data_.reset(new ConceptData(CreateSchemaForType(type_name)));
}

ConceptNode::ConceptNode(Delegate* delegate, const std::string& name, const std::string& type_name):
  gid_(0),
  name_(name),
  type_name_(type_name),
  state_(ConceptState::Down),
  delegate_(delegate),
  managed_(false),
  handle_(nullptr) {

  data_.reset(new ConceptData(CreateSchemaForType(type_name)));
}

ConceptNode::~ConceptNode() {
  for (auto it = subscriptions_.begin(); it != subscriptions_.end(); it++) {
    delete *it;    
  }
  subscriptions_.clear();
}

void ConceptNode::AttachHandler(Handler* handler) {
  handlers_.push_back(handler);
}

void ConceptNode::DetachHandler(Handler* handler) {
  for (auto it = handlers_.begin(); it != handlers_.end(); it++) { 
    if (handler == *it) {
      handlers_.erase(it);
      break;
    }
  }
}

ConceptSubscription* ConceptNode::Subscribe(StreamSession* session) {
  ConceptSubscription* subscription = new ConceptSubscription(this, session);
  subscriptions_.push_back(subscription);
  NotifyHandlersSub(session);
  delegate_->OnConceptSubscribe(this, session);
  return subscription;
}

void ConceptNode::Unsubscribe(ConceptSubscription* subscription) {
  NotifyHandlersUnsub(subscription->session());
  delegate_->OnConceptUnsubscribe(this, subscription->session());
  for (auto it = subscriptions_.begin(); it != subscriptions_.end(); it++) {
    if (subscription == *it) {
      delete *it;
      subscriptions_.erase(it);
      break;
    }
  }
}

void ConceptNode::OnStateChanged(ConceptState old_state, ConceptState new_state) {
  NotifyHandlersStateChanged(new_state);
  delegate_->OnConceptStateChanged(this, new_state);
}

void ConceptNode::NotifyHandlersStateChanged(ConceptState new_state) {
  base::PostTask(
    FROM_HERE,
    base::BindOnce(
      &ConceptNode::NotifyHandlersStateChangedImpl,
      base::Unretained(this),
      new_state));
}

void ConceptNode::NotifyHandlersSub(StreamSession* session) {
  base::PostTask(
    FROM_HERE,
    base::BindOnce(
      &ConceptNode::NotifyHandlersSubImpl,
      base::Unretained(this),
      base::Unretained(session)));
}

void ConceptNode::NotifyHandlersUnsub(StreamSession* session) {
  base::PostTask(
    FROM_HERE,
    base::BindOnce(
      &ConceptNode::NotifyHandlersUnsubImpl,
      base::Unretained(this),
      base::Unretained(session)));
}

void ConceptNode::NotifyHandlersStateChangedImpl(ConceptState new_state) {
  for (auto it = handlers_.begin(); it != handlers_.end(); it++) { 
    (*it)->OnStateChanged(this, new_state);
  }
}

void ConceptNode::NotifyHandlersSubImpl(StreamSession* session) {
  for (auto it = handlers_.begin(); it != handlers_.end(); it++) { 
    (*it)->OnSub(this, session);
  }
}

void ConceptNode::NotifyHandlersUnsubImpl(StreamSession* session) {
  for (auto it = handlers_.begin(); it != handlers_.end(); it++) { 
    (*it)->OnUnsub(this, session);
  }
}

}