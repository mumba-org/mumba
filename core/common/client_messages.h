// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_COMMON_CLIENT_MESSAGES_H_
#define CORE_COMMON_CLIENT_MESSAGES_H_

#include <string>
#include <vector>

#include "base/macros.h"
#include "base/files/file_path.h"
#include "base/strings/string_piece.h"
#include "core/common/common_param_traits.h"
#include "ipc/ipc_message_macros.h"
//#include "core/common/url.h"
#include "base/uuid.h"
//#include "core/common/common_data.h"
//#include "core/common/request_codes.h"
#include "net/base/io_buffer.h"
#include "core/shared/common/content_export.h"

#ifndef INTERNAL_CORE_COMMON_CLIENT_MESSAGES_H_
#define INTERNAL_CORE_COMMON_CLIENT_MESSAGES_H_

#define IPC_MESSAGE_START ClientMsgStart
#undef IPC_MESSAGE_EXPORT
#define IPC_MESSAGE_EXPORT CONTENT_EXPORT 

//------------------------------------------------------------------------------
// Batch process messages:
// These are messages from the host to the client process.

IPC_MESSAGE_CONTROL0(ClientHostMsg_ConnectionReady)
IPC_MESSAGE_CONTROL1(ClientHostMsg_QueryReply,
                     std::string /* reply */)

IPC_MESSAGE_CONTROL1(ClientHostMsg_ControlReply,
                     std::string /* reply */)

////------------------------------------------------------------------------------
//// Batch process host messages:
//// These are messages from the batch process to the host.

IPC_MESSAGE_CONTROL1(ClientMsg_QueryRequest,
                     std::string /* request */)

  IPC_MESSAGE_CONTROL1(ClientMsg_ControlRequest,
                       std::string /* request */)


//IPC_MESSAGE_CONTROL1(ClientMsg_Request,
//                     base::StringPiece /* request */)  


#endif // INTERNAL_CORE_COMMON_CLIENT_MESSAGES_H_

#endif // CORE_COMMON_CLIENT_MESSAGES_H_