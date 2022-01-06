// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/graph/graph_db_cursor.h"
#include "core/host/graph/graph_codec.h"
#include "core/host/graph/graph_transaction.h"

namespace host {

namespace {

base::StringPiece DecodePayload(const storage::KeyValuePair& kv, GraphKeyspace keyspace) {
  base::StringPiece r;
  switch (keyspace) {
    case GraphKeyspace::ENTRY: {
      r = kv.second;
      break;
    }
    case GraphKeyspace::NODE_INDEX:
    case GraphKeyspace::EDGE_INDEX: {
      r = kv.first;
      break;
    }
    default:
      return r;  
  }
  return r;
}

GraphEntryBase* DecodeEntry(GraphTransaction* tr, base::StringPiece payload, GraphKeyspace keyspace) {
  GraphEntryBase* r = nullptr;
  std::string str_payload = payload.as_string();
  switch (keyspace) {
    case GraphKeyspace::ENTRY: {
      protocol::GraphKind kind = GraphCodec::PeekType(str_payload);
      if (kind == protocol::GRAPH_NODE) {
        r = tr->NewNode();
      } else if (kind == protocol::GRAPH_EDGE) {
        r = tr->NewEdge();
      } else if (kind == protocol::GRAPH_PROPERTY) {
        r = tr->NewProperty();
      }
      DCHECK(r);
      r->Decode(str_payload);
      break;
    }
    case GraphKeyspace::NODE_INDEX: {
      r = tr->NewNode();
      r->DecodeIndex(str_payload);
      break;
    }
    case GraphKeyspace::EDGE_INDEX: {
      r = tr->NewEdge();
      r->DecodeIndex(str_payload);
      break;
    }
    default:
      DCHECK(false);
  }
  DCHECK(r);
  return r;
}

}

GraphDbCursor::GraphDbCursor(GraphTransaction* transaction, storage::Cursor* cursor, GraphKeyspace keyspace):
  transaction_(transaction),
  cursor_(cursor),
  keyspace_(keyspace) {

  cursor_->First();
}

GraphDbCursor::~GraphDbCursor() {

}

GraphEntryBase* GraphDbCursor::Get() const {
  auto kv = cursor_->GetKV();
  base::StringPiece payload = DecodePayload(kv, keyspace_);
  GraphEntryBase* result = DecodeEntry(transaction_, payload, keyspace_);
  result->set_managed(true);
  return result;
}

bool GraphDbCursor::HasNext() const {
  return cursor_->IsValid();
}

void GraphDbCursor::Next() {
  cursor_->Next();
}

void GraphDbCursor::Close() {
  //transaction_->CloseCursor(this);
  closed_ = true;
}

size_t GraphDbCursor::Count() {
  return cursor_->Count();
}

}