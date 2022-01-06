// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Common IPC messages used for child processes.
// Multiply-included message file, hence no include guard.

#ifndef CORE_COMMON_CHILD_PROCESS_MESSAGES_H_
#define CORE_COMMON_CHILD_PROCESS_MESSAGES_H_

#include <string>
#include <vector>

#include "base/memory/shared_memory.h"
//#include "base/tracked_objects.h"
#include "base/values.h"
#include "base/tuple.h"
#include "ipc/ipc_message_macros.h"
#include "core/shared/common/content_export.h"

#ifndef INTERNAL_CORE_COMMON_CHILD_PROCESS_MESSAGES_H_
#define INTERNAL_CORE_COMMON_CHILD_PROCESS_MESSAGES_H_

#define IPC_MESSAGE_START ChildProcessMsgStart
#undef IPC_MESSAGE_EXPORT
#define IPC_MESSAGE_EXPORT CONTENT_EXPORT

// Messages sent from the browser to the child process.

// Sent in response to ChildProcessHostMsg_ShutdownRequest to tell the child
// process that it's safe to shutdown.
IPC_MESSAGE_CONTROL0(ChildProcessMsg_Shutdown)

// heartbeat checking
IPC_MESSAGE_CONTROL0(ChildProcessMsg_Heartbeat)

////////////////////////////////////////////////////////////////////////////////
// Messages sent from the child process to the browser.

IPC_MESSAGE_CONTROL0(ChildProcessHostMsg_ShutdownRequest)

IPC_MESSAGE_CONTROL0(ChildProcessHostMsg_HeartbeatReply)


#endif  // INTERNAL_CORE_COMMON_CHILD_PROCESS_MESSAGES_H_


#endif  // CORE_COMMON_CHILD_PROCESS_MESSAGES_H_
