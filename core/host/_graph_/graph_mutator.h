// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_GRAPH_GRAPH_MUTATOR_H_
#define MUMBA_HOST_GRAPH_GRAPH_MUTATOR_H_

#include "base/macros.h"
#include "core/host/graph/graph_entry.h"

namespace host {
class GraphTransaction;

template <class T>
class GraphMutator {
public:
 virtual ~GraphMutator() {}
 virtual void AddEntry(GraphTransaction* tr, T* entry) = 0;
 virtual void RemoveEntry(GraphTransaction* tr, T* entry) = 0;
 virtual void AddEntries(GraphTransaction* tr) = 0;
};

}

#endif