// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <vector>

#include "base/macros.h"
#include "base/files/file_path.h"
#include "core/common/common_param_traits.h"
#include "ipc/ipc_message_macros.h"
#include "core/common/url.h"
#include "base/uuid.h"
#include "core/common/common_data.h"
#include "core/common/request_codes.h"

#undef IPC_MESSAGE_EXPORT
#define IPC_MESSAGE_EXPORT
#define IPC_MESSAGE_START ReplMsgStart

//------------------------------------------------------------------------------
// Batch process messages:
// These are messages from the host to the batch process.

////------------------------------------------------------------------------------
//// Batch process host messages:
//// These are messages from the batch process to the host.

