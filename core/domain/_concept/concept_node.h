// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_CONCEPT_CONCEPT_NODE_H_
#define MUMBA_DOMAIN_CONCEPT_CONCEPT_NODE_H_

#include <memory>
#include <string>
#include <vector>

#include "base/macros.h"
#include "data/table.h"
#include "core/domain/concept/concept_data.h"
#include "core/shared/domain/storage/graph/lemongraph.h"

namespace domain {
class StreamSession;
class ConceptSubscription;
class ConceptGraph;

enum class ConceptState {
  Up,
  Down
};

// Concept: pode ser do tipo One/Sample ou Many

// (actors) -> many - correspende a uma table
// (actors/woody_allen) -> one - corresponde a uma row na table actors

// <node: woody_allen> <edge: is_one_of> <node: actors>

// TODO: como associar um handler ?
// lembrando que os módulos irao dar 'bind'
// em determinados conceptos, e precisamos associar o handler
// do concept para ser processado no código handler no módulo

// Ideia: fazer todos passarem pela "bilheteria" (booking) e pegarem um 'ticket'
// o Ticket tem a informação do tópic a ser criado, por quanto tempo,
// quais as permissoes e qual o handler associado

class ConceptNode {
public:
  class Delegate {
  public:
    virtual ~Delegate() {}
    virtual void OnConceptStateChanged(ConceptNode* concept, ConceptState new_state) = 0;
    virtual void OnConceptSubscribe(ConceptNode* concept, StreamSession* session) = 0;
    virtual void OnConceptUnsubscribe(ConceptNode* concept, StreamSession* session) = 0;
  };

  class Handler {
  public:
    virtual ~Handler() {}
    virtual void OnStateChanged(ConceptNode* concept, ConceptState new_state) = 0;
    virtual void OnSub(ConceptNode* concept, StreamSession* session) = 0;
    virtual void OnUnsub(ConceptNode* concept, StreamSession* session) = 0;
  };

  ConceptNode(Delegate* delegate, uint64_t gid, const std::string& name, const std::string& type_name);
  ConceptNode(Delegate* delegate, const std::string& name, const std::string& type_name);
  ~ConceptNode();

  const std::string& name() const {
    return name_;
  }

  const std::string& type_name() const {
    return type_name_;
  }

  uint64_t gid() const {
    return gid_;
  }

  bool is_up() const {
    return state_ == ConceptState::Up;
  }

  bool is_managed() const {
    return managed_;
  }

  ConceptState state() const {
    return state_;
  }

  void set_state(ConceptState state) {
    if (state == state_)
      return;

    ConceptState old_state = state_;
    state_ = state;
    OnStateChanged(old_state, state);
  }

  void up() {
    set_state(ConceptState::Up);
  }

  void down() {
    set_state(ConceptState::Down);
  }

  ConceptData* data() const {
    return data_.get();
  }

  std::shared_ptr<data::Schema> schema() const {
    return data_->schema();
  }

  // TODO: manage the bounded streams here
  ConceptSubscription* Subscribe(StreamSession* session);
  void Unsubscribe(ConceptSubscription* subscription);

  void AttachHandler(Handler* handler);
  void DetachHandler(Handler* handler);

private:
  
  friend class ConceptGraph;
  
  void OnStateChanged(ConceptState old_state, ConceptState new_state);

  // handlers
  void NotifyHandlersStateChanged(ConceptState new_state);
  void NotifyHandlersSub(StreamSession* session);
  void NotifyHandlersUnsub(StreamSession* session);

  void NotifyHandlersStateChangedImpl(ConceptState new_state);
  void NotifyHandlersSubImpl(StreamSession* session);
  void NotifyHandlersUnsubImpl(StreamSession* session);
  
  uint64_t gid_;

  std::string name_;

  std::string type_name_;

  ConceptState state_;

  std::vector<ConceptSubscription *> subscriptions_;

  std::vector<Handler *> handlers_;

  std::unique_ptr<ConceptData> data_;

  Delegate* delegate_;

  bool managed_;
 
  // the graph db handle
  node_t handle_;

  DISALLOW_COPY_AND_ASSIGN(ConceptNode);
};

}

#endif