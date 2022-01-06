// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_IPC_SHIMS_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_IPC_SHIMS_H_

#include "Globals.h"

// TODO: O Ideal é ao inves de oferecermos a interface generica do IPC
// oferecermos apenas os ipc's especificos para as mensagens pré-definidas
// entre a engine e as aplicações
// ex: IPCSendHello, IPCSendRequest(..create namespace, drop namespace..)
// ou IPCCreateNamespace, IPCDropNamespace
// e também criamos um shim que seria um message receiver que processaria
// as mensagens pré-determinadas recebidas e as rotearia para os interessados

typedef void* IPCChannelRef;

// We use this so we can pass this struct as void* 
// reusing the same method Swift does
// but with the possibility to comply with cgo rules

// FUTURE: consider using this handle to Swift and Go
// where in Go it will keep the int handle
// and in swift, it will be the heap memory pointer
//typedef void* CgoReference;

// TODO: we need to create a special header and source
// only for this helper
//EXPORT CgoReference _CgoCreateReference(int handle_id);
//EXPORT void _CgoDestroyReference(CgoReference ref);
//EXPORT int _CgoGetHandleID(CgoReference ref);
//EXPORT void _CgoSetHandleID(CgoReference ref, int handle_id);

typedef void (*CIPCShutdownCallback)(void* handle);
typedef void (*CIPCConnectionErrorCallback)();

// shell specific IPC message handlers

//typedef void (*CIPCContainerInitCallback)(void* handle);
//typedef void (*CIPCContainerQueryCallback)(void* handle, const char* data);
//typedef void (*CIPCContainerLaunchCallback)(void* handle, const char* data);
//typedef void (*CIPCContainerExecuteCallback)(void* handle, const char* data);
//typedef void (*CIPCContainerBuildCallback)(void* handle);
//typedef void (*CIPCContainerShutdownCallback)(void* handle);

EXPORT IPCChannelRef _IPCChannelConnect(const char* channel_id);
EXPORT void _IPCChannelCleanup(IPCChannelRef handle);
EXPORT void _IPCChannelSetCaller(IPCChannelRef handle, void* caller);
EXPORT void _IPCChannelSetShutdownHandler(IPCChannelRef handle, CIPCShutdownCallback cb);
EXPORT void _IPCChannelSetConnectionErrorHandler(IPCChannelRef handle, CIPCConnectionErrorCallback cb);
EXPORT void _IPCChannelSendShutdown(IPCChannelRef handle);

// shell specific
// EXPORT void _IPCChannelContainerSetInitHandler(IPCChannelRef handle, CIPCContainerInitCallback cb);
// EXPORT void _IPCChannelContainerSetQueryHandler(IPCChannelRef handle, CIPCContainerQueryCallback cb);
// EXPORT void _IPCChannelContainerSetLaunchHandler(IPCChannelRef handle, CIPCContainerLaunchCallback cb);
// EXPORT void _IPCChannelContainerSetExecuteHandler(IPCChannelRef handle, CIPCContainerExecuteCallback cb);
// EXPORT void _IPCChannelContainerSetBuildHandler(IPCChannelRef handle, CIPCContainerBuildCallback cb);
// EXPORT void _IPCChannelContainerSetShutdownHandler(IPCChannelRef handle, CIPCContainerShutdownCallback cb);

// EXPORT void _IPCChannelContainerSendInitAck(IPCChannelRef handle, int status);
// EXPORT void _IPCChannelContainerSendQueryAck(IPCChannelRef handle, int status);
// EXPORT void _IPCChannelContainerSendBuildAck(IPCChannelRef handle, int status);
// EXPORT void _IPCChannelContainerSendLaunchAck(IPCChannelRef handle, int status);
// EXPORT void _IPCChannelContainerSendExecuteAck(IPCChannelRef handle, int status);
// EXPORT void _IPCChannelContainerSendShutdownAck(IPCChannelRef handle, int status);

#endif
