// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_COMMON_APPLICATION_MESSAGES_H_
#define CORE_COMMON_APPLICATION_MESSAGES_H_

#include "ipc/ipc_message_macros.h"

//#include "core/common/query_code.h"
//#include "core/common/query_result.h"
//#include "core/common/request_generated.h"
#include "core/common/common_param_traits.h"
#include "core/common/message_descriptor.h"
#include "core/shared/common/content_export.h"

#ifndef INTERNAL_CORE_COMMON_APPLICATION_MESSAGES_H_
#define INTERNAL_CORE_COMMON_APPLICATION_MESSAGES_H_

#define IPC_MESSAGE_START ApplicationMsgStart
#undef IPC_MESSAGE_EXPORT
#define IPC_MESSAGE_EXPORT CONTENT_EXPORT 

//IPC_STRUCT_TRAITS_BEGIN(common::QueryResult)
//IPC_STRUCT_TRAITS_MEMBER(code)
//IPC_STRUCT_TRAITS_MEMBER(format)
//IPC_STRUCT_TRAITS_MEMBER(data)
//IPC_STRUCT_TRAITS_MEMBER(message)
//IPC_STRUCT_TRAITS_MEMBER(is_insert)
//IPC_STRUCT_TRAITS_END()


// Messages sent from the engine to the application process.

// IPC_MESSAGE_CONTROL1(ApplicationMsg_Reply,
//                      common::MessageDescriptor
//                      );

// Messages sent from the application to the engine.

// IPC_MESSAGE_CONTROL2(ApplicationHostMsg_Request,
//                      request::Status,
//                      common::MessageDescriptor 
//                      );

#endif

#endif