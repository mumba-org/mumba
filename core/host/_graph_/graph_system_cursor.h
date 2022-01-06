// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_GRAPH_GRAPH_SYSTEM_CURSOR_H_
#define MUMBA_HOST_GRAPH_GRAPH_SYSTEM_CURSOR_H_

#include "base/macros.h"
#include "storage/db/db.h"
#include "core/host/graph/graph_common.h"
#include "core/host/graph/graph_cursor.h"
#include "storage/db/db.h"
#include "storage/torrent.h"

namespace host {

class GraphSystemCursor : public GraphCursor {
public:
  GraphSystemCursor();
  ~GraphSystemCursor() override;

  GraphEntryBase* Get() const override;
  
  bool HasNext() const override;
  void Next() override;
  void Close() override;
  size_t Count() override;

private:

  bool closed_;
  
  DISALLOW_COPY_AND_ASSIGN(GraphSystemCursor);
};

}

#endif
