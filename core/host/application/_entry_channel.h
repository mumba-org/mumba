// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_CORE_HOST_APPLICATION_ENTRY_CHANNEL_H_
#define MUMBA_CORE_HOST_APPLICATION_ENTRY_CHANNEL_H_

#include "base/macros.h"

namespace host {
class EntryNode;
/*
 *  A channel will represent a rpc stream method
 *  that can receive a streaming read/write of protobuf messages
 * (in grpc parlance a bidi stream rpc method)
 */

class EntryChannel {
public:
  EntryChannel();
  ~EntryChannel();
 
  void AddWatch(EntryNode* node);
  void RemoveWatch(EntryNode* node);

private:

  DISALLOW_COPY_AND_ASSIGN(EntryChannel);
};

}

#endif