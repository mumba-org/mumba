// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "IPCClientThread.h"

#include <memory>

#include "IPCThreadSafeSender.h"
#include "base/allocator/allocator_extension.h"
#include "base/base_switches.h"
#include "base/command_line.h"
#include "base/debug/leak_annotations.h"
#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/message_loop/message_loop.h"
#include "base/message_loop/timer_slack.h"
#include "base/process/kill.h"
#include "base/process/process_handle.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/synchronization/condition_variable.h"
#include "base/synchronization/lock.h"
#include "base/threading/thread_local.h"
#include "base/strings/string_util.h"
#include "ipc/ipc_logging.h"
#include "ipc/ipc_sync_channel.h"
#include "ipc/ipc_sync_message_filter.h"
#include "ipc/ipc_channel_mojo.h"

namespace {

// How long to wait for a connection to the browser process before giving up.
const int kConnectionTimeoutS = 5;

base::LazyInstance<base::ThreadLocalPointer<IPCClientThread>>::DestructorAtExit g_lazy_tls =
 LAZY_INSTANCE_INITIALIZER;
 
class IPCClientSyncMessageFilter : public IPC::SyncMessageFilter {
 public:
  IPCClientSyncMessageFilter(
      base::WaitableEvent* shutdown_event,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner)
      : SyncMessageFilter(shutdown_event),
        task_runner_(task_runner) {}

  void OnFilterAdded(IPC::Channel* sender) override {
    SyncMessageFilter::OnFilterAdded(sender);
  }

 private:
  ~IPCClientSyncMessageFilter() override {}
  
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
};


// engine::BlockInputStreamPtr GetBlockInputStream(const std::string& name, engine::ReadBuffer& buf){
//   // TODO: fixme! layer violation. We cannot use symbols from the engine:: namespace here
//   // 
//   //engine::ContainerPool context;
//   engine::Block sample;
  
//   //if (name == "Native") {
// 		return std::make_shared<engine::NativeBlockInputStream>(buf);
//   //} else if (name == "TabSeparated") {
// 	//	return std::make_shared<engine::BlockInputStreamFromRowInputStream>(std::make_shared<engine::TabSeparatedRowInputStream>(buf, sample), sample, 60000);  
//   //} else if (name == "Values") {
// 	//  return std::make_shared<engine::BlockInputStreamFromRowInputStream>(std::make_shared<engine::ValuesRowInputStream>(buf, context), sample, 60000);	
//   //} else {
//   //  return {};
//   //}
// }

} // namespace

IPCClientThread::IPCClientThreadMessageRouter::IPCClientThreadMessageRouter(
 IPC::Sender* sender)
 : sender_(sender) {}

bool IPCClientThread::IPCClientThreadMessageRouter::Send(IPC::Message* msg) {
 return sender_->Send(msg);
}


// static 
IPCClientThread* IPCClientThread::current() {
 return g_lazy_tls.Pointer()->Get();
}

IPCClientThread::IPCClientThread(base::MessageLoop* message_loop)
 : router_(this),
  message_loop_(message_loop),
  channel_error_(false),
  shutdown_cb_(nullptr),
  conn_error_cb_(nullptr),
  handle_(nullptr),
  weak_factory_(this) {
}


IPCClientThread::~IPCClientThread() {

}

bool IPCClientThread::Init(
  const base::FilePath& channel_path, 
  const std::string& channel_name, 
  base::MessageLoop* io_message_loop,
  base::WaitableEvent* shutdown_event) {
 
 channel_name_ = channel_name;
 channel_path_ = channel_path.AppendASCII(channel_name);

 g_lazy_tls.Pointer()->Set(this);

//  channel_ = IPC::SyncChannel::Create(
//   this,
//   io_message_loop->task_runner(),
//   shutdown_event);

//  if(!channel_) {
//    return false;
//  }

//  channel_->Init(channel_name_, IPC::Channel::MODE_LIENT, true);

 mojo::MessagePipe pipe;
  std::unique_ptr<IPC::ChannelFactory> channel_factory =
      IPC::ChannelMojo::CreateClientFactory(
          std::move(pipe.handle0), io_message_loop->task_runner(),
          base::ThreadTaskRunnerHandle::Get());

  channel_.reset(new IPC::ChannelProxy(
    this, 
    io_message_loop->task_runner(),
    base::ThreadTaskRunnerHandle::Get()));

  if(!channel_) {
    return false;
  }

  channel_->Init(std::move(channel_factory), true);

 sync_message_filter_ =
  new IPCClientSyncMessageFilter(shutdown_event, io_message_loop->task_runner());
 thread_safe_sender_ = new IPCThreadSafeSender(
     io_message_loop->task_runner(), sync_message_filter_.get());
 channel_->AddFilter(sync_message_filter_.get());
 
 int connection_timeout = kConnectionTimeoutS;
 base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
     FROM_HERE,
     base::BindOnce(&IPCClientThread::EnsureConnected,
                weak_factory_.GetWeakPtr()),
                base::TimeDelta::FromSeconds(connection_timeout));

  return true;
}

void IPCClientThread::Shutdown() {
 message_loop_ = nullptr;
 channel_->RemoveFilter(sync_message_filter_.get());
 channel_->ClearIPCTaskRunner();
 g_lazy_tls.Pointer()->Set(nullptr);
}

void IPCClientThread::AddRoute(int32_t routing_id, IPC::Listener* listener) {
 router_.AddRoute(routing_id, listener);
}

void IPCClientThread::RemoveRoute(int32_t routing_id) {
 router_.RemoveRoute(routing_id);
}

int IPCClientThread::GenerateRoutingID() {
 int routing_id = MSG_ROUTING_NONE;
 //Send(new EngineHostMsg_GenerateRoutingID(&routing_id));
 return routing_id;
}

void IPCClientThread::AddFilter(IPC::MessageFilter* filter) {
 channel_->AddFilter(filter);
}

void IPCClientThread::RemoveFilter(IPC::MessageFilter* filter) {
 channel_->RemoveFilter(filter);
}

bool IPCClientThread::Send(IPC::Message* msg) {
 DCHECK(base::MessageLoop::current() == message_loop());
 if (!channel_) {
  delete msg;
  return false;
 }

 return channel_->Send(msg);
}

IPC::MessageRouter* IPCClientThread::GetRouter() {
 DCHECK(base::MessageLoop::current() == message_loop());
 return &router_;
}

bool IPCClientThread::OnControlMessageReceived(const IPC::Message& msg) {
 return false;
}

bool IPCClientThread::OnMessageReceived(const IPC::Message& msg) {
 bool handled = true;

  //IPC_BEGIN_MESSAGE_MAP(IPCClientThread, msg)
  // IPC_MESSAGE_HANDLER(ChildProcessMsg_Shutdown, OnShutdown)
   //IPC_MESSAGE_HANDLER(ApplicationMsg_Reply, OnReply)
   // IPC_MESSAGE_HANDLER(ContainerMsg_Init, OnContainerInit)
   // IPC_MESSAGE_HANDLER(ContainerMsg_Query, OnContainerQuery)
   // IPC_MESSAGE_HANDLER(ContainerMsg_Execute, OnContainerExecute)
   // IPC_MESSAGE_HANDLER(ContainerMsg_Launch, OnContainerLaunch)
   // IPC_MESSAGE_HANDLER(ContainerMsg_Build, OnContainerBuild)
   // IPC_MESSAGE_HANDLER(ContainerMsg_Shutdown, OnContainerShutdown)
   //IPC_MESSAGE_UNHANDLED(handled = false)
   //IPC_END_MESSAGE_MAP()

   if (handled)
    return true;

  if (msg.routing_id() == MSG_ROUTING_CONTROL)
   return OnControlMessageReceived(msg);

  return router_.OnMessageReceived(msg);
 }

void IPCClientThread::OnChannelConnected(int32_t peer_pid) {
  //LOG(INFO) << "IPCClientThread::OnChannelConnected";
  channel_error_ = false; 
  weak_factory_.InvalidateWeakPtrs();
}

void IPCClientThread::OnChannelError() {
  channel_error_ = true;
}

void IPCClientThread::OnShutdown() {
 //DLOG(INFO) << "OnShutdown";
 if (shutdown_cb_ && handle_) {
  //DLOG(INFO) << "calling shutdown callback"; 
  shutdown_cb_(handle_);
 }
}

void IPCClientThread::OnProcessFinalRelease() {
 if (channel_error_) {
  //base::MessageLoop::current()->QuitNow();
  return;
 }

 // The child process shutdown sequence is a request response based mechanism,
 // where we send out an initial feeler request to the child process host
 // instance in the browser to verify if it's ok to shutdown the child process.
 // The browser then sends back a response if it's ok to shutdown. This avoids
 // race conditions if the process refcount is 0 but there's an IPC message
 // inflight that would addref it.
 //Send(new ChildProcessHostMsg_ShutdownRequest);
}

//void IPCClientThread::OnReply(const common::MessageDescriptor& desc) {
 // TODO: devemos mandar pra ser processado na main thread!!
  
 //std::cout << "format: " << result.format << std::endl << "data: " << std::endl << result.data << std::endl;
 
 //if (result.code == common::QUERY_RESULT) {
 
//   engine::ReadBufferFromString buf(reply.header);
//   //engine::CompressedReadBuffer compressed_buf(buf);
//   engine::BlockInputStreamPtr block_in = GetBlockInputStream(reply.format, buf);
  
//   if(!block_in) {
//     LOG(ERROR) << "unknown/unhandled block format: " << reply.format;
//     Send(new ChildProcessHostMsg_ShutdownRequest);
//     return;
//   }

//   engine::Block block = block_in->read();

//   engine::WriteBufferFromFileDescriptor std_out(STDOUT_FILENO);
//   engine::BlockOutputStreamPtr block_out = 
//     //std::make_shared<engine::BlockOutputStreamFromRowOutputStream>(std::make_shared<engine::JSONRowOutputStream>(std_out, block));
//     std::make_shared<engine::PrettySpaceBlockOutputStream>(std_out);
//     //std::make_shared<engine::TabSeparatedBlockOutputStream>(std_out);
//     //std::make_shared<engine::PrettyCompactBlockOutputStream>(std_out);
//     //std::make_shared<engine::BlockOutputStreamFromRowOutputStream>(std::make_shared<engine::TabSeparatedRowOutputStream>(std_out, block, true));
  
//   //if (block.rows() != 0) {
//     block_in->readPrefix();
//     block_out->writePrefix();
//     while(block) {
// 			block_out->write(block);
//       block = block_in->read();
//     }
      
//     block_in->readSuffix();
// 		block_out->writeSuffix();  
// 	  block_out->flush();
//   //} else if(result.is_insert) {
//   //  block_out->writePrefix();
//   //  block_out->write(block);
// 	//  block_out->flush();
//     //std::cout << "Ok - No Result" << std::endl; 
//   //} else {
//   //  std::cout << "{empty}" << std::endl; 
//   //}
// //  } else if(result.code == common::QUERY_NORESULT) {
// //    std::string msg = "{}";
// //    if (!result.message.empty())
// //      msg + ": " + result.message;
     
// //    std::cout << msg << std::endl;
// //  } else if(result.code == common::QUERY_ERROR){
// //    std::cout << "error: " << result.data << std::endl;
// //  }
 
 //Send(new ChildProcessHostMsg_ShutdownRequest);
//}

void IPCClientThread::Quit() {
  //message_loop_->QuitNow();
  base::RunLoop::QuitCurrentDeprecated();
}

void IPCClientThread::EnsureConnected() {
  VLOG(0) << "ChildThreadImpl::EnsureConnected()";
  OnShutdown();
}

// void IPCClientThread::OnContainerInit(const RequestInfo& info, const uuid_t& uuid) {
//   //DLOG(INFO) << "OnContainerInit";
//   if (init_cb_ && handle_) {
//     init_cb_(handle_);
//   }
// }

// void IPCClientThread::OnContainerQuery(const std::string& query) {
//   if (query_cb_ && handle_) {
//     query_cb_(handle_, query.c_str());
//   }
// }

// void IPCClientThread::OnContainerLaunch(const std::string& cmd) {
//   if (launch_cb_ && handle_) {
//     launch_cb_(handle_, cmd.c_str());
//   }
// }

// void IPCClientThread::OnContainerExecute(const std::string& query) {
//   if (execute_cb_ && handle_) {
//     execute_cb_(handle_, query.c_str());
//   }
// }

// void IPCClientThread::OnContainerBuild() {
//   if (build_cb_ && handle_) {
//     build_cb_(handle_);
//   }
// }

// void IPCClientThread::OnContainerShutdown() {
//   //DLOG(INFO) << "OnContainerShutdown";
//   if (container_shutdown_cb_ && handle_) {
//     container_shutdown_cb_(handle_);
//   }
// }
