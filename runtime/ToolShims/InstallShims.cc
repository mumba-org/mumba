// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "InstallShims.h"

#include <memory>

#include "base/command_line.h"
#include "base/at_exit.h"
#include "base/process/launch.h"
#include "base/threading/thread.h"
#include "base/files/file_util.h"
#include "base/files/file.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/task_scheduler/task_scheduler.h"
#include "base/strings/string_number_conversions.h"
#include "base/synchronization/waitable_event.h"
#include "base/hash.h"
#include "net/base/io_buffer.h"
#include "crypto/secure_hash.h"
#include "crypto/sha2.h"
#include "ipc/ipc_channel.h"
#include "ipc/ipc_channel_factory.h"
#include "ipc/ipc_channel_mojo.h"
#include "mojo/edk/embedder/embedder.h"
#include "mojo/edk/embedder/named_platform_handle_utils.h"
#include "mojo/edk/embedder/named_platform_handle.h"
#include "mojo/edk/embedder/peer_connection.h"
#include "mojo/edk/embedder/scoped_platform_handle.h"
#include "mojo/public/cpp/platform/named_platform_channel.h"
#include "mojo/public/cpp/system/isolated_connection.h"
#include "mojo/edk/embedder/scoped_ipc_support.h"
#include "third_party/protobuf/src/google/protobuf/text_format.h"
#include "core/common/client_messages.h"
#include "core/common/proto/control.pb.h"
#include "core/common/proto/internal.pb.h"
#include "core/common/protocol/message_serialization.h"

const char kIPC_ADDRESS[] = "/tmp/hello_ipc";

class IPCClient : public IPC::Listener,
                  public IPC::Sender {
public:
  IPCClient(
    const scoped_refptr<base::SingleThreadTaskRunner>& ipc_task_runner,
    base::Closure quit_closure): 
      named_channel_handle_(kIPC_ADDRESS),
      ipc_task_runner_(ipc_task_runner),
      main_task_runner_(base::ThreadTaskRunnerHandle::Get()),
      connected_(false),
      timeout_(false),
      quit_closure_(std::move(quit_closure)),
      reply_event_(
        base::WaitableEvent::ResetPolicy::AUTOMATIC, 
        base::WaitableEvent::InitialState::NOT_SIGNALED),
      weak_factory_(this) {

  }
  
  ~IPCClient() override {
  
  }

  bool connected() const { 
    return connected_;
  }

  void Init(const std::string& package_name, const base::FilePath& package_path) {

    package_name_ = package_name;

    package_path_ = package_path;

    mojo::edk::ScopedIPCSupport ipc_support(
      base::ThreadTaskRunnerHandle::Get(),
      mojo::edk::ScopedIPCSupport::ShutdownPolicy::FAST);

    channel_handle_ = 
      mojo::edk::CreateClientHandle(named_channel_handle_);

    if (!channel_handle_.is_valid())  {
      LOG(ERROR) << "mojo::edk::CreateClientHandle";
      return;
    }

    mojo::ScopedMessagePipeHandle pipe = 
      mojo_connection_.Connect(mojo::edk::ConnectionParams(
        mojo::edk::TransportProtocol::kLegacy,
        std::move(channel_handle_)));

    channel_ =
      IPC::Channel::CreateClient(pipe.release(),
                                 this, 
                                 base::ThreadTaskRunnerHandle::Get());
    if (!channel_) {
      LOG(ERROR) << "failed to open channel";
      return;
    }

    if (!channel_->Connect()) {
      LOG(ERROR) << "failed to connect channel";
      return;
    }

  }

  void Shutdown() {
    if (connected_) {
      channel_->Close();
      connected_ = false;
    }
    channel_.reset();
  }

  bool Send(IPC::Message* msg) override {
    if (!connected_) {
      LOG(ERROR) << "cannot send message: disconnected";
      return false;
    }
    return channel_->Send(msg);
  }

  bool OnMessageReceived(const IPC::Message& message) override {
    bool handled = true;
    IPC_BEGIN_MESSAGE_MAP(IPCClient, message)
      IPC_MESSAGE_HANDLER(ClientHostMsg_ConnectionReady, OnConnectionReady)
      IPC_MESSAGE_HANDLER(ClientHostMsg_ControlReply, OnControlReply)
      IPC_MESSAGE_UNHANDLED(handled = false)
    IPC_END_MESSAGE_MAP() 
    return handled;
  }

  void OnChannelConnected(int32_t peer_pid) override {
    connected_ = true;
    
    printf("connected to ipc:%s\n", kIPC_ADDRESS);
    
    main_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&IPCClient::SendControlRequest, 
        base::Unretained(this)));
  }

  void OnChannelError() override {
    connected_ = false;
    printf("connection lost. exiting..\n");
    OnExit();
  }

  void OnConnectionReady() {}

  void OnControlReply(const std::string& reply) {
    weak_factory_.InvalidateWeakPtrs();
    ProcessControlReply(reply);
  }
  
  void OnBadMessageReceived(const IPC::Message& message) override {
    LOG(INFO) << "OnBadMessageReceived";
  }

private:
  
  void SendControlRequest() {
    ipc_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&IPCClient::SendControlRequestImpl, 
        base::Unretained(this)));
  
    ipc_task_runner_->PostDelayedTask(
       FROM_HERE,
       base::BindOnce(&IPCClient::OnQueryTimeout,
                      weak_factory_.GetWeakPtr()),
       base::TimeDelta::FromSeconds(5));
  }

  void SendControlRequestImpl() {
    protocol::ControlMessage control_message;    
    protocol::PackageInstall* install_message = control_message.mutable_package_install();
    install_message->set_package_name(package_name_);
    install_message->set_package_path(package_path_.value());

    //scoped_refptr<net::IOBufferWithSize> message_buf = 
    //  protocol::SerializeAndFrameMessage(control_message);
    std::string buf;
    if (!control_message.SerializeToString(&buf)) {
      LOG(ERROR) << "failed to serialize control message";
      OnExit();
      return;
    }

    channel_->Send(
      new ClientMsg_ControlRequest(buf));
        //std::string(reinterpret_cast<char *>(message_buf->data()), message_buf->size())));
  }

  void ProcessControlReply(const std::string& reply) {
    printf("received reply: '%s'\n", reply.c_str());

    ipc_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&IPCClient::OnExit,
                     base::Unretained(this)));
  }

  void OnQueryTimeout() {
    printf("query timeout\n");

    timeout_ = true;
    
    ipc_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&IPCClient::OnExit,
                     base::Unretained(this)));
  }

  void OnExit() {
    weak_factory_.InvalidateWeakPtrs();
    quit_closure_.Run();
  }

  mojo::edk::NamedPlatformHandle named_channel_handle_;
  mojo::edk::ScopedPlatformHandle channel_handle_;
  mojo::edk::PeerConnection mojo_connection_; 
  std::unique_ptr<IPC::Channel> channel_;
  scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner_;
  scoped_refptr<base::SingleThreadTaskRunner> main_task_runner_;
  bool connected_;
  bool timeout_;
  base::Closure quit_closure_;
  std::string package_name_;
  base::FilePath package_path_;
  base::WaitableEvent reply_event_;
  base::WeakPtrFactory<IPCClient> weak_factory_;
};

int _mumba_install_main(int argc, char** argv) {
  base::CommandLine::Init(argc, argv);
  base::AtExitManager at_exit;
  base::Thread ipc_thread("ipc");
  
  base::Thread::Options io_options;
  io_options.message_loop_type = base::MessageLoop::TYPE_IO;
  io_options.timer_slack = base::TIMER_SLACK_MAXIMUM;
  
  base::CommandLine* cmd = base::CommandLine::ForCurrentProcess();

  if (!cmd->HasSwitch("package_name") || !cmd->HasSwitch("path")) {
    printf("usage: --package_name=[name] --path=[package path]");
    return 1;
  }

  std::string package_name = cmd->GetSwitchValueASCII("package_name");
  base::FilePath package_path = cmd->GetSwitchValuePath("path");

  if (!base::PathExists(package_path)) {
    printf("error: package file %s not found\n", package_path.value().c_str());
    return 1;
  }
 
  base::TaskScheduler::CreateAndStartWithDefaultParams("task_scheduler");

  mojo::edk::Init();

  ipc_thread.StartWithOptions(io_options);

  std::unique_ptr<base::MessageLoop> main_message_loop(new base::MessageLoopForIO());

  base::RunLoop loop;

  std::unique_ptr<IPCClient> client(new IPCClient(ipc_thread.task_runner(), loop.QuitWhenIdleClosure()));
  
  ipc_thread.task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(
      &IPCClient::Init, 
      base::Unretained(client.get()),
      package_name,
      package_path)
  );

  loop.Run();

  ipc_thread.task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(
      &IPCClient::Shutdown, 
      base::Unretained(client.get())));

  ipc_thread.Stop();

  base::TaskScheduler::GetInstance()->Shutdown();

  return 0;
}