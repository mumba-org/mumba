// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <vector>

#include "base/macros.h"
#include "base/files/file_path.h"
#include "core/common/shell_info.h"
#include "core/common/common_param_traits.h"
#include "ipc/ipc_message_macros.h"

#undef IPC_MESSAGE_EXPORT
#define IPC_MESSAGE_EXPORT
#define IPC_MESSAGE_START ModuleMsgStart


// Module process messages:
//  from host to module

IPC_MESSAGE_CONTROL0(ModuleMsg_ModuleLoad)

IPC_MESSAGE_CONTROL0(ModuleMsg_ModuleUnload)


// Module process host messages:
//  from module to host

IPC_MESSAGE_CONTROL1(ModuleHostMsg_ModuleLoadResult,
                     bool)

IPC_MESSAGE_CONTROL1(ModuleHostMsg_ModuleUnloadResult,
                     bool)