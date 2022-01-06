// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_IPC_LIENT_THREAD_H__
#define MUMBA_RUNTIME_MUMBA_SHIMS_IPC_LIENT_THREAD_H__

#include <string>

#include "IPCShims.h"
#include "base/memory/shared_memory.h"
#include "base/memory/weak_ptr.h"
#include "base/memory/ref_counted.h"
#include "base/message_loop/message_loop.h"
#include "base/synchronization/waitable_event.h"
#include "base/threading/thread.h"
#include "ipc/ipc_sender.h"
#include "ipc/ipc_listener.h"
#include "ipc/message_router.h"

namespace IPC {
class Channel;
struct ChannelHandle;
class ChannelProxy;
class SyncChannel;
class SyncMessageFilter;
class MessageFilter;
}  // namespace IPC

// namespace common {
// struct QueryResult;  
// }

class IPCThreadSafeSender;

class IPCClientThread : public IPC::Sender,
                        public IPC::Listener {
public:

 static IPCClientThread* current();

 explicit IPCClientThread(base::MessageLoop* message_loop);
 
 ~IPCClientThread() override;
 
 bool Init(const base::FilePath& channel_path, 
  const std::string& channel_name, 
  base::MessageLoop* io_message_loop,
  base::WaitableEvent* shutdown_event);

 void Shutdown();
 // IPC::Sender implementation:
 bool Send(IPC::Message* msg) override;

 //IPC::SyncChannel* channel() { return channel_.get(); }

 IPC::MessageRouter* GetRouter();

 base::MessageLoop* message_loop() const { return message_loop_; }
 
 void set_handle(void* handle) {
   handle_ = handle;
 }

 void set_shutdown_callback(CIPCShutdownCallback shutdown_cb) {
   shutdown_cb_ = shutdown_cb;
 }

 void set_connection_error_callback(CIPCConnectionErrorCallback conn_error_cb) {
   conn_error_cb_ = conn_error_cb;
 }

//  void set_container_init_callback(CIPCContainerInitCallback init_cb) {
//    init_cb_ = init_cb;
//  }

//  void set_container_launch_callback(CIPCContainerLaunchCallback launch_cb) {
//    launch_cb_ = launch_cb;
//  }
 
//  void set_container_execute_callback(CIPCContainerExecuteCallback execute_cb) {
//    execute_cb_ = execute_cb;
//  }
 
//  void set_container_query_callback(CIPCContainerQueryCallback query_cb) {
//    query_cb_ = query_cb;
//  }

//  void set_container_build_callback(CIPCContainerBuildCallback build_cb) {
//    build_cb_ = build_cb;
//  }

//  void set_container_shutdown_callback(CIPCContainerShutdownCallback shutdown_cb) {
//    container_shutdown_cb_ = shutdown_cb;
//  }

 IPCThreadSafeSender* thread_safe_sender() const {
  return thread_safe_sender_.get();
 }

 void AddRoute(int32_t routing_id, IPC::Listener* listener);
 void RemoveRoute(int32_t routing_id);
 int GenerateRoutingID();

 void AddFilter(IPC::MessageFilter* filter);
 void RemoveFilter(IPC::MessageFilter* filter);

 void Quit();

private:

 class IPCClientThreadMessageRouter : public IPC::MessageRouter {
 public:
  // |sender| must outlive this object.
  explicit IPCClientThreadMessageRouter(IPC::Sender* sender);
  bool Send(IPC::Message* msg) override;
 private:
  IPC::Sender* const sender_;
 };

 void OnProcessFinalRelease();

 virtual bool OnControlMessageReceived(const IPC::Message& msg);

 // IPC::Listener implementation:
 bool OnMessageReceived(const IPC::Message& msg) override;
 void OnChannelConnected(int32_t peer_pid) override;
 void OnChannelError() override;

 // IPC message handlers.
 void OnShutdown();
 void OnChannelEstablished(IPC::ChannelHandle handle);
 //void OnReply(const common::MessageDescriptor& desc);

 // void OnContainerInit(const RequestInfo& info,
 //                      const uuid_t& uuid);
 // void OnContainerQuery(const std::string& query);
 // void OnContainerLaunch(const std::string& cmd);
 // void OnContainerExecute(const std::string& query);
 // void OnContainerBuild();
 // void OnContainerShutdown();
 
 void EnsureConnected();

 std::string channel_name_;

 base::FilePath channel_path_;

 bool repl_mode_;

 // Allows threads other than the main thread to send sync messages.
 scoped_refptr<IPC::SyncMessageFilter> sync_message_filter_;

 scoped_refptr<IPCThreadSafeSender> thread_safe_sender_;

 IPCClientThreadMessageRouter router_;

 base::MessageLoop* message_loop_;

 std::unique_ptr<IPC::ChannelProxy> channel_;

 bool channel_error_;

 CIPCShutdownCallback shutdown_cb_;
 
 CIPCConnectionErrorCallback conn_error_cb_;

 //CIPCContainerInitCallback init_cb_;
 //CIPCContainerQueryCallback query_cb_;
 //CIPCContainerExecuteCallback execute_cb_;
 //CIPCContainerLaunchCallback launch_cb_;
 //CIPCContainerBuildCallback build_cb_;
 //CIPCContainerShutdownCallback container_shutdown_cb_;

 void* handle_;

 base::WeakPtrFactory<IPCClientThread> weak_factory_;

 DISALLOW_COPY_AND_ASSIGN(IPCClientThread);
};

#endif