// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Multiply-included message file, so no include guard.

#include <string>
#include <vector>

#include "base/macros.h"
#include "core/common/common_param_traits.h"
#include "ipc/ipc_message_macros.h"

#undef IPC_MESSAGE_EXPORT
#define IPC_MESSAGE_EXPORT
#define IPC_MESSAGE_START UtilityMsgStart

//------------------------------------------------------------------------------
// Utility process messages:
// These are messages from the host to the utility process.

IPC_MESSAGE_CONTROL0(UtilityMsg_BatchMode_Started)
IPC_MESSAGE_CONTROL0(UtilityMsg_BatchMode_Finished)
