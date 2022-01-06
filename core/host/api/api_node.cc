// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/api/api_node.h"

#include "core/host/share/share_peer.h"

namespace host {

APINode::APINode(SharePeer* peer): peer_(peer) {

}

APINode::~APINode() {

}

}