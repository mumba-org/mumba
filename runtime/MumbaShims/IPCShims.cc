// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "IPCShims.h"

#include "base/path_service.h"
//#include "base/memory/scoped_ptr.h"
#include "base/message_loop/message_loop.h"
#include "base/threading/thread.h"
#include "base/synchronization/waitable_event.h"
#include "core/shared/common/paths.h"
#include "core/shared/common/child_process_messages.h"
#include "IPCClientThread.h"

struct IPCChannel { 
 std::unique_ptr<IPCClientThread> ipc_thread;
 base::Thread io_thread;
 base::WaitableEvent shutdown_event;

 IPCChannel(): 
   io_thread("Mumba_IPCClientIOThread"), 
   shutdown_event(base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED)  {}

};

IPCChannelRef _IPCChannelConnect(const char* channel_id) {
 base::FilePath socket_path;

 base::MessageLoop* message_loop = base::MessageLoop::current();
 
 if (!message_loop) {
   return nullptr;
 }

 base::PathService::Get(common::DIR_SOCKETS, &socket_path);

 IPCChannel* chan = new IPCChannel();
 chan->io_thread.StartWithOptions(base::Thread::Options(base::MessageLoop::TYPE_IO, 0));
 chan->ipc_thread.reset(new IPCClientThread(message_loop));
 
 if (!chan->ipc_thread->Init(socket_path, channel_id, chan->io_thread.message_loop(), &chan->shutdown_event)) {
   return nullptr;
 }
 
 return chan;
}

void _IPCChannelCleanup(IPCChannelRef handle) {
 IPCChannel* channel = reinterpret_cast<IPCChannel *>(handle);
 
 channel->shutdown_event.Signal();
 
 if (channel->ipc_thread) {
  channel->ipc_thread->Shutdown();
 }
 
 channel->io_thread.Stop(); 
}

void _IPCChannelSendShutdown(IPCChannelRef handle) {
 IPCChannel* channel = reinterpret_cast<IPCChannel *>(handle);
 channel->ipc_thread->Send(new ChildProcessHostMsg_ShutdownRequest);
}

void _IPCChannelSetCaller(IPCChannelRef handle, void* caller) {
 IPCChannel* channel = reinterpret_cast<IPCChannel *>(handle);
 channel->ipc_thread->set_handle(caller); 
}

void _IPCChannelSetShutdownHandler(IPCChannelRef handle, CIPCShutdownCallback cb) {
 IPCChannel* channel = reinterpret_cast<IPCChannel *>(handle);
 channel->ipc_thread->set_shutdown_callback(cb);
}

void _IPCChannelSetConnectionErrorHandler(IPCChannelRef handle, CIPCConnectionErrorCallback cb) {
 IPCChannel* channel = reinterpret_cast<IPCChannel *>(handle);
 channel->ipc_thread->set_connection_error_callback(cb);
}

// void _IPCChannelContainerSetInitHandler(IPCChannelRef handle, CIPCContainerInitCallback cb) {
//  IPCChannel* channel = reinterpret_cast<IPCChannel *>(handle);
//  channel->ipc_thread->set_container_init_callback(cb);
// }

// void _IPCChannelContainerSetQueryHandler(IPCChannelRef handle, CIPCContainerQueryCallback cb) {
//  IPCChannel* channel = reinterpret_cast<IPCChannel *>(handle);
//  channel->ipc_thread->set_container_query_callback(cb);
// }

// void _IPCChannelContainerSetExecuteHandler(IPCChannelRef handle, CIPCContainerExecuteCallback cb) {
//  IPCChannel* channel = reinterpret_cast<IPCChannel *>(handle);
//  channel->ipc_thread->set_container_execute_callback(cb);
// }

// void _IPCChannelContainerSetLaunchHandler(IPCChannelRef handle, CIPCContainerLaunchCallback cb) {
//  IPCChannel* channel = reinterpret_cast<IPCChannel *>(handle);
//  channel->ipc_thread->set_container_launch_callback(cb);
// }

// void _IPCChannelContainerSetBuildHandler(IPCChannelRef handle, CIPCContainerBuildCallback cb) {
//  IPCChannel* channel = reinterpret_cast<IPCChannel *>(handle);
//  channel->ipc_thread->set_container_build_callback(cb);
// }

// void _IPCChannelContainerSetShutdownHandler(IPCChannelRef handle, CIPCContainerShutdownCallback cb) {
//  IPCChannel* channel = reinterpret_cast<IPCChannel *>(handle);
//  channel->ipc_thread->set_container_shutdown_callback(cb);
// }

// void _IPCChannelContainerSendInitAck(IPCChannelRef handle, int status) {
//  IPCChannel* channel = reinterpret_cast<IPCChannel *>(handle);
//  RequestInfo info;
//  channel->ipc_thread->Send(new ContainerHostMsg_InitAck(info, uuid_t(), static_cast<ResultStatus>(status)));
// }

// void _IPCChannelContainerSendQueryAck(IPCChannelRef handle, int status) {
//  IPCChannel* channel = reinterpret_cast<IPCChannel *>(handle);
//  RequestInfo info;
//  channel->ipc_thread->Send(new ContainerHostMsg_QueryAck(info, uuid_t(), static_cast<ResultStatus>(status), std::string()));
// }

// void _IPCChannelContainerSendBuildAck(IPCChannelRef handle, int status) {
//  IPCChannel* channel = reinterpret_cast<IPCChannel *>(handle);
//  RequestInfo info;
//  channel->ipc_thread->Send(new ContainerHostMsg_BuildAck(info, uuid_t(), static_cast<ResultStatus>(status)));
// }

// void _IPCChannelContainerSendExecuteAck(IPCChannelRef handle, int status) {
//  IPCChannel* channel = reinterpret_cast<IPCChannel *>(handle);
//  RequestInfo info;
//  channel->ipc_thread->Send(new ContainerHostMsg_ExecuteAck(info, uuid_t(), static_cast<ResultStatus>(status), std::string()));
// }

// void _IPCChannelContainerSendLaunchAck(IPCChannelRef handle, int status) {
//  IPCChannel* channel = reinterpret_cast<IPCChannel *>(handle);
//  RequestInfo info;
//  channel->ipc_thread->Send(new ContainerHostMsg_LaunchAck(info, uuid_t(), static_cast<ResultStatus>(status)));
// }

// void _IPCChannelContainerSendShutdownAck(IPCChannelRef handle, int status) {
//  IPCChannel* channel = reinterpret_cast<IPCChannel *>(handle);
//  RequestInfo info;
//  channel->ipc_thread->Send(new ContainerHostMsg_ShutdownAck(info, uuid_t(), static_cast<ResultStatus>(status)));
// }