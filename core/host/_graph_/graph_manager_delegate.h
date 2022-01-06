// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_GRAPH_GRAPH_MANAGER_DELEGATE_H_
#define MUMBA_HOST_GRAPH_GRAPH_MANAGER_DELEGATE_H_

#include "base/macros.h"
#include "base/uuid.h"
#include "base/callback.h"
#include "base/strings/string_piece.h"
#include "storage/torrent.h"
#include "storage/db/db.h"
#include "core/host/graph/graph_model.h"
#include "core/host/share/share_database.h"

namespace host {

class GraphManagerDelegate {
public:
  virtual ~GraphManagerDelegate() {}
  virtual scoped_refptr<ShareDatabase> GetDatabase(const base::UUID& uuid) = 0;
  virtual scoped_refptr<ShareDatabase> GetDatabase(const std::string& name) = 0;
  virtual scoped_refptr<ShareDatabase> CreateDatabase(const std::string& name, std::vector<std::string> keyspaces, base::Callback<void(int64_t)> cb) = 0;
  virtual scoped_refptr<ShareDatabase> OpenDatabase(const base::UUID& uuid, base::Callback<void(int64_t)> cb) = 0;
  virtual scoped_refptr<ShareDatabase> OpenDatabase(const std::string& name, base::Callback<void(int64_t)> cb) = 0;
  virtual bool DeleteDatabase(const base::UUID& uuid) = 0;
  virtual bool DeleteDatabase(const std::string& name) = 0;
};

}

#endif