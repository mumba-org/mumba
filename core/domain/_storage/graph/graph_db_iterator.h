// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_NAMESPACE_GRAPH_GRAPH_ITERATOR_H_
#define MUMBA_DOMAIN_NAMESPACE_GRAPH_GRAPH_ITERATOR_H_

#include "base/optional.h"
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
#include "core/shared/domain/storage/graph/lemongraph.h"
#pragma clang diagnostic push

namespace domain {
class GraphDbTransaction;

template <class T>
class GraphDbIterator {
public:
  GraphDbIterator(GraphDbTransaction* transaction, graph_iter_t handle): 
    transaction_(transaction),
    handle_(handle) {}

  GraphDbIterator(const GraphDbIterator &other) {
    handle_ = other.handle_; 
  } 

  ~GraphDbIterator() {
    graph_iter_close(handle_);
  }

  GraphDbTransaction* transaction() const {
    return transaction_;
  }

  bool Next(T* value) {
    entry_t entry = graph_iter_next(handle_);
    if (!entry || (entry && entry->rectype == GRAPH_DELETION)) {
      return false;
    }
    *value = T::Cast(transaction_, entry);
    return true;
  }

private:
  GraphDbTransaction* transaction_;
  graph_iter_t handle_;
};

}

#endif