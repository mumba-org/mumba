// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_API_API_NODE_H_
#define MUMBA_HOST_API_API_NODE_H_

#include <string>

#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "base/uuid.h"

namespace host {
class SharePeer;

class APINode {
public:
  APINode(SharePeer* peer);
  ~APINode();  

  SharePeer* peer() const {
    return peer_;
  }

private:
  
  SharePeer* peer_;

  DISALLOW_COPY_AND_ASSIGN(APINode);
};

}

#endif