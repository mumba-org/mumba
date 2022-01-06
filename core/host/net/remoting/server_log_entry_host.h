// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_NET_SERVER_LOG_ENTRY_HOST_H_
#define MUMBA_HOST_NET_SERVER_LOG_ENTRY_HOST_H_

#include "core/host/net/transport.h"

namespace host {

class ServerLogEntry;

// Constructs a log entry for a session state change.
// Currently this is either connection or disconnection.
std::unique_ptr<ServerLogEntry> MakeLogEntryForSessionStateChange(
    bool connected);

// Constructs a log entry for a heartbeat.
std::unique_ptr<ServerLogEntry> MakeLogEntryForHeartbeat();

// Adds fields describing the host to this log entry.
void AddHostFieldsToLogEntry(ServerLogEntry* entry);

// Adds a field describing connection type (direct/stun/relay).
void AddConnectionTypeToLogEntry(ServerLogEntry* entry,
                                 TransportRoute::RouteType type);

}  // namespace remoting

#endif  // REMOTING_HOST_SERVER_LOG_ENTRY_HOST_H_
