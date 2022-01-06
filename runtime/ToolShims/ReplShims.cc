// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ReplShims.h"

#include "linenoise.h"
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
#include "crypto/secure_hash.h"
#include "crypto/sha2.h"
#include "graphql/parser.h"
#include "db/db.h"
#include "db/sqliteInt.h"
#include "data/io/memory.h"
#include "data/ipc/reader.h"
#include "data/pretty_print.h"
#include "data/record_batch.h"
#include "data/status.h"
#include "data/table.h"
#include "data/type.h"
#include "data/type_traits.h"
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
#include "core/common/query/query_encoder.h"
#include "core/common/query/query_decoder.h"
//#include "remoting/host/chromoting_messages.h"
#include "core/common/client_messages.h"
#include "third_party/protobuf/src/google/protobuf/text_format.h"

const char kIPC_ADDRESS[] = "/tmp/hello_ipc";
char kWorld[] = " World";

void completion(const char *buf, linenoiseCompletions *lc) {
    if (buf[0] == 'q') {
      linenoiseAddCompletion(lc,"query");
    } else if (buf[0] == 'm') {
      linenoiseAddCompletion(lc,"mutation");
    } else if (buf[0] == 's') {
      linenoiseAddCompletion(lc,"subscription");
    }
}

char *hints(const char *buf, int *color, int *bold) {
    if (!strcasecmp(buf,"hello")) {
        *color = 35;
        *bold = 0;
        return kWorld;
    }
    return NULL;
}

class X : public IPC::Listener,
          public IPC::Sender {
public:
  X(const scoped_refptr<base::SingleThreadTaskRunner>& ipc_task_runner,
    base::Closure quit_closure): 
      named_channel_handle_(kIPC_ADDRESS),
      graphql_parser_(new graphql::Parser()),
      ipc_task_runner_(ipc_task_runner),
      main_task_runner_(base::ThreadTaskRunnerHandle::Get()),
      //remote_parse_(true),
      //remote_parse_(false),
      connected_(false),
      timeout_(false),
      quit_closure_(std::move(quit_closure)),
      reply_event_(
        base::WaitableEvent::ResetPolicy::AUTOMATIC, 
        base::WaitableEvent::InitialState::NOT_SIGNALED),
      weak_factory_(this) {

  }
  
  ~X() override {
  
  }

  bool connected() const { 
    return connected_;
  }

  void Init() {
    mojo::edk::ScopedIPCSupport ipc_support(
      base::ThreadTaskRunnerHandle::Get(),
      mojo::edk::ScopedIPCSupport::ShutdownPolicy::FAST);

    channel_handle_ = 
      mojo::edk::CreateClientHandle(named_channel_handle_);

    if (!channel_handle_.is_valid())  {
      //LOG(ERROR) << "mojo::edk::CreateClientHandle";
      //OnExit();
      RunRepl();
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
      //ipc_thread.Stop();
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
    IPC_BEGIN_MESSAGE_MAP(X, message)
      IPC_MESSAGE_HANDLER(ClientHostMsg_ConnectionReady, OnConnectionReady)
      IPC_MESSAGE_HANDLER(ClientHostMsg_QueryReply, OnQueryReply)
      IPC_MESSAGE_UNHANDLED(handled = false)
    IPC_END_MESSAGE_MAP() 
    return handled;
  }

  void OnChannelConnected(int32_t peer_pid) override {
    //LOG(INFO) << "OnChannelConnected";
    connected_ = true;
    printf("connected to ipc:%s\n", kIPC_ADDRESS);
    main_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&X::RunRepl, base::Unretained(this)));
  }

  void OnChannelError() override {
    connected_ = false;
    printf("connection lost. exiting..");
    OnExit();
    //LOG(INFO) << "OnChannelError";
  }

  void OnConnectionReady() {
     
  }

  void OnQueryReply(const std::string& reply) {
    weak_factory_.InvalidateWeakPtrs();
    last_reply_ = reply;
    reply_event_.Signal();
  }
  
  void OnBadMessageReceived(const IPC::Message& message) override {
    LOG(INFO) << "OnBadMessageReceived";
  }

private:
  
  void RunRepl() {
    char *line;
    scoped_refptr<net::IOBufferWithSize> buf;
    common::QueryEncoder enc;
    common::QueryDecoder dec;

    linenoiseSetCompletionCallback(completion);
    //linenoiseSetHintsCallback(hints);

    /* Load history from file. The history file is just a plain text file
     * where entries are separated by newlines. */
    linenoiseHistoryLoad("history.txt"); /* Load the history at startup */

    //if (!server_) {
    while((line = linenoise("# ")) != NULL) {
      /* Do something with the string. */
      if (line[0] != '\0' && line[0] != '/') {
        //if (remote_parse_) {
          auto node = graphql_parser_->Parse(line);
          if (!node) {
            last_reply_ = graphql_parser_->GetLastErrorMessage();
            printf("%s\n", last_reply_.c_str());
            continue;
          }
          //std::string buf_str;
          buf = enc.EncodeRequest(node.get());

          if (buf->size() == 0) {
            LOG(ERROR) << "failed to encode the query";
            last_reply_ = "failed to encode the query";
            printf("%s\n", last_reply_.c_str());
            continue;
          }

      //    std::string hex = base::HexEncode(buf->data(), buf->size());
        //  printf("encoded (size: %d)\n%s\n", buf->size(), hex.c_str());

          ipc_task_runner_->PostTask(
            FROM_HERE,
            base::BindOnce(&X::SendRequest, 
              base::Unretained(this),
              buf));
        
          ipc_task_runner_->PostDelayedTask(
            FROM_HERE,
            base::BindOnce(&X::OnQueryTimeout,
                           weak_factory_.GetWeakPtr()),
            base::TimeDelta::FromSeconds(5));

          reply_event_.Wait();
        //} else {
        //  auto node = graphql_parser_->Parse(line);
       //   if (!node) {
       //     last_reply_ = graphql_parser_->GetLastErrorMessage();
        //  } else {
        //    //node->Print(&last_reply_);
        //    buf = enc.EncodeRequest(node.get());
        //    last_reply_.assign(buf->data(), buf->size());
        //  }
        //}
        //if (buf && buf->size() > 0) {
        //  std::string decoded;
        //  std::string hex = base::HexEncode(buf->data(), buf->size());
        //  printf("encoded size: %d\n%s\n", buf->size(), hex.c_str());
        //  std::unique_ptr<protocol::QueryRequest> req = dec.DecodeRequest(buf);
        //  if (req ) {//&& google::protobuf::TextFormat::PrintToString(*req, &decoded)) {
        //    base::SStringPrintf(&decoded, "request {\n id: %d, statements: %d\n}\n", req->request_id(), req->statement_count());
        //    printf("decoded:\n%s\n", decoded.c_str());
        //  }
        //} else {
          if (!connected_) {
            printf("connection lost. exiting..\n");
            break;
          }

          if (timeout_) {
            timeout_ = false;
            printf("%s\n", last_reply_.c_str());
            continue;
          }

          common::QueryDecoder dec;
          std::unique_ptr<protocol::QueryReply> reply = dec.DecodeReply(last_reply_);
          if (!reply) {
            printf("failed to decode reply string\n");
            continue;
          }
          if (reply->status() != protocol::QueryReply::STATUS_OK) {
            printf("reply error code: %d \n", reply->status());
          } else if (reply->content_type() == protocol::QueryReply::CONTENT_RECORD_BATCH) {
            if (!reply->content().size()) {
              printf("content where the record batch should be is empty (%zu):\n%s\n", 
                reply->content().size(),
                reply->content().c_str());
              continue;
            }

            std::shared_ptr<data::RecordBatch> rows;
            std::shared_ptr<data::Schema> schema;

            auto schema_buf = std::make_shared<data::Buffer>(reply->content_schema());
            data::BufferReader schema_stream(schema_buf);

            auto batch_buf = std::make_shared<data::Buffer>(reply->content());
            data::BufferReader batch_stream(batch_buf);

            auto status = data::ReadSchema(&schema_stream, &schema);
            if (!status.ok()) {
              printf("ReadSchema() failed to deserialize schema\n");
              continue;
            }

            status = data::ReadRecordBatch(schema, &batch_stream, &rows);
            if (!status.ok()) {
              printf("ReadRecordBatch() failed to deserialize record batch\n");
              continue;
            }

            std::ostringstream sink;
            status = data::PrettyPrint(*rows, 0, &sink);
            if (!status.ok()) {
              printf("failed to print record batch\n");
            } else {
              printf("%s", sink.str().c_str());
            }
           } else {
            printf("reply ok, but not of record batch type. not handling it\n");
           }
        //}
        
        //linenoiseHistoryAdd(line); /* Add to the history. */
        //linenoiseHistorySave("history.txt"); /* Save the history on disk. */
      }// else if (!strncmp(line,"/historylen",11)) {
        /* The "/historylen" command will change the history len. */
       // int len = atoi(line+11);
        //linenoiseHistorySetMaxLen(len);
      //} //else if (line[0] == '/') {
      //    printf("Unreconized command: %s\n", line);
      //}
      free(line);
    }
      //LOG(INFO) << "r = " << ok;
    //}
    ipc_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&X::OnExit,
                     base::Unretained(this)));
  }

  void SendRequest(scoped_refptr<net::IOBufferWithSize> buf) {
    //std::string hex = base::HexEncode(buf->data(), buf->size());
    //printf("sending payload (size: %d)\n%s\n", buf->size(), hex.c_str());
    channel_->Send(new ClientMsg_Request(std::string(reinterpret_cast<char *>(buf->data()), buf->size())));
  }

  void OnQueryTimeout() {
    //LOG(INFO) << "OnQueryTimeout";
    last_reply_ = "query timeout";
    timeout_ = true;
    reply_event_.Signal();
  }

  void OnExit() {
    //LOG(INFO) << "OnExit";
    weak_factory_.InvalidateWeakPtrs();
    std::move(quit_closure_).Run();
  }

  //std::unique_ptr<mojo::IsolatedConnection> mojo_connection_;
  mojo::edk::NamedPlatformHandle named_channel_handle_;
  mojo::edk::ScopedPlatformHandle channel_handle_;
  mojo::edk::PeerConnection mojo_connection_; 
  std::unique_ptr<IPC::Channel> channel_;
  std::string last_reply_;
  std::unique_ptr<graphql::Parser> graphql_parser_;
  scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner_;
  scoped_refptr<base::SingleThreadTaskRunner> main_task_runner_;
 // bool remote_parse_;
  bool connected_;
  bool timeout_;
  base::Closure quit_closure_;
  base::WaitableEvent reply_event_;
  base::WeakPtrFactory<X> weak_factory_;
  //bool server_;
};

int IPCMain() {
  base::AtExitManager at_exit;
  bool is_server = false;
  base::Thread ipc_thread("ipc");
  
  base::Thread::Options io_options;
  io_options.message_loop_type = base::MessageLoop::TYPE_IO;
  io_options.timer_slack = base::TIMER_SLACK_MAXIMUM;
  
  base::CommandLine* cmd = base::CommandLine::ForCurrentProcess();

  auto args = cmd->GetArgs();

  if (!args.size()) {
    is_server = true;
  }
 
  base::TaskScheduler::CreateAndStartWithDefaultParams("task_scheduler");

  mojo::edk::Init();

  ipc_thread.StartWithOptions(io_options);

  std::unique_ptr<base::MessageLoop> main_message_loop(new base::MessageLoopForIO());

  base::RunLoop loop;

  std::unique_ptr<X> x(new X(ipc_thread.task_runner(), loop.QuitWhenIdleClosure()));
  
//  if (!ipc_channel) {
//    LOG(ERROR) << "failed to open channel";
//    ipc_thread.Stop();
//    return 1;
//  }

  ipc_thread.task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(
      &X::Init, 
      base::Unretained(x.get()))
  );

  loop.Run();

  ipc_thread.task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(
      &X::Shutdown, 
      base::Unretained(x.get())));

  ipc_thread.Stop();

  base::TaskScheduler::GetInstance()->Shutdown();

  return 0;
}

int _mumba_repl_main(int argc, char** argv) {
  base::CommandLine::Init(argc, argv);
  return IPCMain();
}