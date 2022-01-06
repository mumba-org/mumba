// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/graph/graph_system_cursor.h"

namespace host {

GraphSystemCursor::GraphSystemCursor() {

}

GraphSystemCursor::~GraphSystemCursor() {

}

GraphEntryBase* GraphSystemCursor::Get() const {
  return nullptr;
}

bool GraphSystemCursor::HasNext() const {
  return false;
}

void GraphSystemCursor::Next() {
  
}

void GraphSystemCursor::Close() {
  closed_ = true;
}

size_t GraphSystemCursor::Count() {
  return 0;
}

}