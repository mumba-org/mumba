#include <utility>

#include "base/command_line.h"
#include "base/base64.h"
#include "base/message_loop/message_loop.h"
#include "base/task_scheduler/task_scheduler.h"
#include "base/task_scheduler/post_task.h"
#include "base/run_loop.h"
#include "base/macros.h"
#include "base/strings/string_util.h"
#include "base/callback_helpers.h"
#include "base/rand_util.h"
#include "base/at_exit.h"
#include "base/strings/string_number_conversions.h"
#include "remoting/protocol/webrtc_transport.h"
#include "jingle/glue/thread_wrapper.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/url_request/url_request_context_getter.h"
#include "remoting/base/compound_buffer.h"
#include "remoting/proto/event.pb.h"
//#include "remoting/protocol/fake_authenticator.h"
#include "remoting/base/constants.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "remoting/protocol/p2p_stream_socket.h"
#include "remoting/protocol/authenticator.h"
#include "remoting/protocol/channel_authenticator.h"
#include "remoting/protocol/message_channel_factory.h"
#include "remoting/protocol/message_pipe.h"
#include "remoting/protocol/message_serialization.h"
#include "remoting/protocol/network_settings.h"
#include "remoting/protocol/transport_context.h"
#include "remoting/signaling/fake_signal_strategy.h"
#include "third_party/libjingle_xmpp/xmllite/xmlelement.h"

namespace {

const char kChannelName[] = "test_channel";
const char kAuthKey[] = "test_auth_key";
}

class FakeChannelAuthenticator : public remoting::protocol::ChannelAuthenticator {
 public:
  FakeChannelAuthenticator(bool accept, bool async): result_(accept ? net::OK : net::ERR_FAILED),
      async_(async),
      weak_factory_(this) {}

  ~FakeChannelAuthenticator() override = default;

  // ChannelAuthenticator interface.
  void SecureAndAuthenticate(std::unique_ptr<remoting::protocol::P2PStreamSocket> socket,
                             const DoneCallback& done_callback) override {

    socket_ = std::move(socket);

    done_callback_ = done_callback;

    if (async_) {
      if (result_ != net::OK) {
        // Don't write anything if we are going to reject auth to make test
        // ordering deterministic.
        did_write_bytes_ = true;
      } else {
        scoped_refptr<net::IOBuffer> write_buf = new net::IOBuffer(1);
        write_buf->data()[0] = 0;
        int result = socket_->Write(
            write_buf.get(), 1,
            base::Bind(&FakeChannelAuthenticator::OnAuthBytesWritten,
                      weak_factory_.GetWeakPtr()),
            TRAFFIC_ANNOTATION_FOR_TESTS);
        if (result != net::ERR_IO_PENDING) {
          // This will not call the callback because |did_read_bytes_| is
          // still set to false.
          OnAuthBytesWritten(result);
        }
      }

      scoped_refptr<net::IOBuffer> read_buf = new net::IOBuffer(1);
      int result =
          socket_->Read(read_buf.get(), 1,
                        base::Bind(&FakeChannelAuthenticator::OnAuthBytesRead,
                                  weak_factory_.GetWeakPtr()));
      if (result != net::ERR_IO_PENDING)
        OnAuthBytesRead(result);
    } else {
      CallDoneCallback();
    }
  }

 private:
  void OnAuthBytesWritten(int result) {
    //EXPECT_EQ(1, result);
    //EXPECT_FALSE(did_write_bytes_);
    did_write_bytes_ = true;
    if (did_read_bytes_)
      CallDoneCallback();
  }
  
  void OnAuthBytesRead(int result) {
    //EXPECT_EQ(1, result);
    //EXPECT_FALSE(did_read_bytes_);
    did_read_bytes_ = true;
    if (did_write_bytes_)
      CallDoneCallback();
  }

  void CallDoneCallback() {
    if (result_ != net::OK)
      socket_.reset();
    base::ResetAndReturn(&done_callback_).Run(result_, std::move(socket_));
  }

  const int result_;
  const bool async_;

  std::unique_ptr<remoting::protocol::P2PStreamSocket> socket_;
  DoneCallback done_callback_;

  bool did_read_bytes_ = false;
  bool did_write_bytes_ = false;

  base::WeakPtrFactory<FakeChannelAuthenticator> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(FakeChannelAuthenticator);
};

class FakeAuthenticator : public remoting::protocol::Authenticator {
 public:
  enum Type {
    HOST,
    CLIENT,
  };

  enum Action {
    ACCEPT,
    REJECT,
    REJECT_CHANNEL
  };

  struct Config {
    Config() {}
    Config(Action action) : action(action) {}
    Config(int round_trips, Action action, bool async)
     : round_trips(round_trips), action(action), async(async) {}

    int round_trips = 1;
    Action action = Action::ACCEPT;
    bool async = true;
  };

  FakeAuthenticator(Type type,
                    Config config,
                    const std::string& local_id,
                    const std::string& remote_id) : 
                    type_(type), 
                    config_(config), 
                    local_id_(local_id), 
                    remote_id_(remote_id) {
  //EXPECT_TRUE((!local_id_.empty() && !remote_id_.empty()) ||
   //           config.round_trips == 0);
  }

  // Special constructor for authenticators in ACCEPTED or REJECTED state that
  // don't exchange any messages.
  FakeAuthenticator(Action action): FakeAuthenticator(CLIENT,
                        FakeAuthenticator::Config(0, action, true),
                        std::string(),
                        std::string()) {}

  ~FakeAuthenticator() override = default;

  // Set the number of messages that the authenticator needs to process before
  // started() returns true.  Default to 0.
  void set_messages_till_started(int messages) { 
    messages_till_started_ = messages;
  }

  // Sets auth key to be returned by GetAuthKey(). Must be called when
  // |round_trips| is set to 0.
  void set_auth_key(const std::string& auth_key) { auth_key_ = auth_key; }

  // When pause_message_index is set the authenticator will pause in
  // PROCESSING_MESSAGE state after that message, until
  // TakeResumeClosure().Run() is called.
  void set_pause_message_index(int pause_message_index) {
    pause_message_index_ = pause_message_index;
  }

  void Resume() {
    base::ResetAndReturn(&resume_closure_).Run();
  }

  // Authenticator interface.
  State state() const override {
    //EXPECT_LE(messages_, config_.round_trips * 2);

    if (messages_ == pause_message_index_ && !resume_closure_.is_null())
      return PROCESSING_MESSAGE;

    if (messages_ >= config_.round_trips * 2) {
      if (config_.action == REJECT) {
        return REJECTED;
      } else {
        return ACCEPTED;
      }
    }

    // Don't send the last message if this is a host that wants to
    // reject a connection.
    if (messages_ == config_.round_trips * 2 - 1 && type_ == HOST &&
        config_.action == REJECT) {
      return REJECTED;
    }

    // We are not done yet. process next message.
    if ((messages_ % 2 == 0 && type_ == CLIENT) ||
        (messages_ % 2 == 1 && type_ == HOST)) {
      return MESSAGE_READY;
    } else {
      return WAITING_MESSAGE;
    }
  }

  bool started() const override {
    return messages_ > messages_till_started_;
  }

  RejectionReason rejection_reason() const override {
    return INVALID_CREDENTIALS;
  }

  void ProcessMessage(const buzz::XmlElement* message,
                      const base::Closure& resume_callback) override {

    //EXPECT_EQ(WAITING_MESSAGE, state());
    std::string id =
        message->TextNamed(buzz::QName(remoting::kChromotingXmlNamespace, "id"));
    //EXPECT_EQ(id, base::IntToString(messages_));

    // On the client receive the key in the last message.
    if (type_ == CLIENT && messages_ == config_.round_trips * 2 - 1) {
      std::string key_base64 =
          message->TextNamed(buzz::QName(remoting::kChromotingXmlNamespace, "key"));
      //EXPECT_TRUE(!key_base64.empty());
      //EXPECT_TRUE(base::Base64Decode(key_base64, &auth_key_));
    }

    // Receive peer's id.
    if (messages_ < 2) {
      CHECK(remote_id_ == message->Attr(buzz::QName("", "id")));
    }

    ++messages_;
    if (messages_ == pause_message_index_) {
      resume_closure_ = resume_callback;
      return;
    }
    resume_callback.Run();
  }

  std::unique_ptr<buzz::XmlElement> GetNextMessage() override {
    //EXPECT_EQ(MESSAGE_READY, state());

    std::unique_ptr<buzz::XmlElement> result(new buzz::XmlElement(
        buzz::QName(remoting::kChromotingXmlNamespace, "authentication")));
    buzz::XmlElement* id = new buzz::XmlElement(
        buzz::QName(remoting::kChromotingXmlNamespace, "id"));
    id->AddText(base::IntToString(messages_));
    result->AddElement(id);

    // Send local id in the first outgoing message.
    if (messages_ < 2) {
      result->AddAttr(buzz::QName("", "id"), local_id_);
    }

    // Add authentication key in the last message sent from host to client.
    if (type_ == HOST && messages_ == config_.round_trips * 2 - 1) {
      auth_key_ =  base::RandBytesAsString(16);
      buzz::XmlElement* key = new buzz::XmlElement(
          buzz::QName(remoting::kChromotingXmlNamespace, "key"));
      std::string key_base64;
      base::Base64Encode(auth_key_, &key_base64);
      key->AddText(key_base64);
      result->AddElement(key);
    }

    ++messages_;
    return result;
  }

  const std::string& GetAuthKey() const override {
    return auth_key_;
  }

  std::unique_ptr<remoting::protocol::ChannelAuthenticator> CreateChannelAuthenticator()
      const override {
    return std::make_unique<FakeChannelAuthenticator>(
      config_.action != REJECT_CHANNEL, config_.async);
  }

 protected:
  const Type type_;
  const Config config_;
  const std::string local_id_;
  const std::string remote_id_;

  // Total number of messages that have been processed.
  int messages_ = 0;
  // Number of messages that the authenticator needs to process before started()
  // returns true.  Default to 0.
  int messages_till_started_ = 0;

  int pause_message_index_ = -1;
  base::Closure resume_closure_;

  std::string auth_key_;

  DISALLOW_COPY_AND_ASSIGN(FakeAuthenticator);
};


class TestTransportEventHandler : public remoting::protocol::WebrtcTransport::EventHandler {
 public:
  typedef base::Callback<void(remoting::protocol::ErrorCode error)> ErrorCallback;
  typedef base::Callback<void(const std::string& name,
                              std::unique_ptr<remoting::protocol::MessagePipe> pipe)>
      IncomingChannelCallback;

  TestTransportEventHandler() = default;
  ~TestTransportEventHandler() override = default;

  // All callbacks must be set before the test handler is passed to a Transport
  // object.
  void set_connecting_callback(const base::Closure& callback) {
    connecting_callback_ = callback;
  }
  void set_connected_callback(const base::Closure& callback) {
    connected_callback_ = callback;
  }
  void set_error_callback(const ErrorCallback& callback) {
    error_callback_ = callback;
  }
  void set_incoming_channel_callback(const IncomingChannelCallback& callback) {
    incoming_channel_callback_ = callback;
  }

  // WebrtcTransport::EventHandler interface.
  void OnWebrtcTransportConnecting() override {
    if (!connecting_callback_.is_null())
      connecting_callback_.Run();
  }
  void OnWebrtcTransportConnected() override {
    if (!connected_callback_.is_null())
      connected_callback_.Run();
  }
  void OnWebrtcTransportError(remoting::protocol::ErrorCode error) override {
    error_callback_.Run(error);
  }
  void OnWebrtcTransportIncomingDataChannel(
      const std::string& name,
      std::unique_ptr<remoting::protocol::MessagePipe> pipe) override {
    if (!incoming_channel_callback_.is_null()) {
      incoming_channel_callback_.Run(name, std::move(pipe));
    } else {
      LOG(ERROR) << "Received unexpected incoming channel.";
    }
  }
  void OnWebrtcTransportMediaStreamAdded(
      scoped_refptr<webrtc::MediaStreamInterface> stream) override {}
  void OnWebrtcTransportMediaStreamRemoved(
      scoped_refptr<webrtc::MediaStreamInterface> stream) override {}

 private:
  base::Closure connecting_callback_;
  base::Closure connected_callback_;
  ErrorCallback error_callback_;
  IncomingChannelCallback incoming_channel_callback_;

  DISALLOW_COPY_AND_ASSIGN(TestTransportEventHandler);
};

class TestMessagePipeEventHandler : public remoting::protocol::MessagePipe::EventHandler {
 public:
  TestMessagePipeEventHandler() = default;
  ~TestMessagePipeEventHandler() override = default;

  void set_open_callback(const base::Closure& callback) {
    open_callback_ = callback;
  }
  void set_message_callback(const base::Closure& callback) {
    message_callback_ = callback;
  }
  void set_closed_callback(const base::Closure& callback) {
    closed_callback_ = callback;
  }

  bool is_open() { return is_open_; }
  const std::list<std::unique_ptr<remoting::CompoundBuffer>>& received_messages() {
    return received_messages_;
  }

  // MessagePipe::EventHandler interface.
  void OnMessagePipeOpen() override {
    is_open_ = true;
    if (!open_callback_.is_null())
      open_callback_.Run();
  }
  void OnMessageReceived(std::unique_ptr<remoting::CompoundBuffer> message) override {
    received_messages_.push_back(std::move(message));
    if (!message_callback_.is_null())
      message_callback_.Run();
  }
  void OnMessagePipeClosed() override {
    if (!closed_callback_.is_null()) {
      closed_callback_.Run();
    } else {
      LOG(ERROR) << "Channel closed unexpectedly.";
    }
  }

 private:
  bool is_open_ = false;
  base::Closure open_callback_;
  base::Closure message_callback_;
  base::Closure closed_callback_;

  std::list<std::unique_ptr<remoting::CompoundBuffer>> received_messages_;

  DISALLOW_COPY_AND_ASSIGN(TestMessagePipeEventHandler);
};

class Client {
public:
  Client() {}
  ~Client() = default;

  void Init() {
    network_settings_ = 
    remoting::protocol::NetworkSettings(remoting::protocol::NetworkSettings::NAT_TRAVERSAL_OUTGOING);
    client_transport_.reset(
        new remoting::protocol::WebrtcTransport(jingle_glue::JingleThreadWrapper::current(),
                            remoting::protocol::TransportContext::ForTests(remoting::protocol::TransportRole::CLIENT),
                            &client_event_handler_));
    client_authenticator_.reset(
        new FakeAuthenticator(FakeAuthenticator::ACCEPT));
    client_authenticator_->set_auth_key(kAuthKey);

  }

  void Start() {
    client_event_handler_.set_connected_callback(
      base::Bind(&Client::OnConnection, base::Unretained(this)));

    client_event_handler_.set_error_callback(
        base::Bind(&Client::OnSessionError, base::Unretained(this),
                   remoting::protocol::TransportRole::CLIENT));
    client_transport_->Start(
        client_authenticator_.get(),
        base::Bind(&Client::ProcessTransportInfo, base::Unretained(this)));
  }

  void OnConnection() {
    LOG(INFO)<< "client connected";
  }

  void Exit() {
    client_message_pipe_.reset();
    client_transport_.reset();
  }

  void ProcessTransportInfo(std::unique_ptr<buzz::XmlElement> transport_info) {
    LOG(INFO) << "ProcessTransportInfo";
    // DCHECK(target_transport);

    // // Reformat the message to normalize line endings by removing CR symbol.
    // if (normalize_line_endings) {
    //   std::string xml = transport_info->Str();
    //   base::ReplaceChars(xml, "\r", std::string(), &xml);
    //   transport_info.reset(buzz::XmlElement::ForStr(xml));
    // }

    // DCHECK(
    //     (*target_transport)->ProcessTransportInfo(transport_info.get()));
  }

  void ExpectClientDataStream() {
    client_event_handler_.set_incoming_channel_callback(base::Bind(
        &Client::OnIncomingChannel, base::Unretained(this)));
  }

  
  void OnIncomingChannel(const std::string& name,
                         std::unique_ptr<remoting::protocol::MessagePipe> pipe) {
    //EXPECT_EQ(kChannelName, name);
    client_message_pipe_ = std::move(pipe);
    client_message_pipe_->Start(&client_message_pipe_event_handler_);

    //if (run_loop_ && host_message_pipe_event_handler_.is_open())
   //   run_loop_->Quit();
  }

  void OnHostChannelConnected() {
    //if (run_loop_ && client_message_pipe_event_handler_.is_open())
    //  run_loop_->Quit();
  }

  void OnSessionError(remoting::protocol::TransportRole role, remoting::protocol::ErrorCode error) {
    client_error_ = error;
  }

private:
 std::unique_ptr<remoting::protocol::WebrtcTransport> client_transport_;
 TestTransportEventHandler client_event_handler_;
 std::unique_ptr<FakeAuthenticator> client_authenticator_;
 std::unique_ptr<remoting::protocol::MessagePipe> client_message_pipe_;
 TestMessagePipeEventHandler client_message_pipe_event_handler_;
 remoting::protocol::ErrorCode client_error_ = remoting::protocol::OK;
 remoting::protocol::NetworkSettings network_settings_;
};

class Server {
public:
  Server() {}
  ~Server() = default;

  void Init() {
    network_settings_ = 
    remoting::protocol::NetworkSettings(remoting::protocol::NetworkSettings::NAT_TRAVERSAL_OUTGOING);
    host_transport_.reset(
        new remoting::protocol::WebrtcTransport(jingle_glue::JingleThreadWrapper::current(),
                            remoting::protocol::TransportContext::ForTests(remoting::protocol::TransportRole::SERVER),
                            &host_event_handler_));
    host_authenticator_.reset(new FakeAuthenticator(FakeAuthenticator::ACCEPT));
    host_authenticator_->set_auth_key(kAuthKey);
  }

  void Start() {
    host_event_handler_.set_connected_callback(base::DoNothing());
    
    host_event_handler_.set_error_callback(
        base::Bind(&Server::OnSessionError, base::Unretained(this),
                   remoting::protocol::TransportRole::SERVER));
    
    host_transport_->Start(
        host_authenticator_.get(),
        base::Bind(&Server::ProcessTransportInfo,
                   base::Unretained(this)));
  }

  void Exit() {
    host_message_pipe_.reset();
    host_transport_.reset();
  }

  void ProcessTransportInfo(std::unique_ptr<buzz::XmlElement> transport_info) {
    LOG(INFO) << "ProcessTransportInfo";
    // DCHECK(target_transport);

    // // Reformat the message to normalize line endings by removing CR symbol.
    // if (normalize_line_endings) {
    //   std::string xml = transport_info->Str();
    //   base::ReplaceChars(xml, "\r", std::string(), &xml);
    //   transport_info.reset(buzz::XmlElement::ForStr(xml));
    // }

    // DCHECK(
    //     (*target_transport)->ProcessTransportInfo(transport_info.get()));
  }


  // void ExpectClientDataStream() {
  //   client_event_handler_.set_incoming_channel_callback(base::Bind(
  //       &Server::OnIncomingChannel, base::Unretained(this)));
  // }

  void CreateHostDataStream() {
    host_message_pipe_ = host_transport_->CreateOutgoingChannel(kChannelName);
    host_message_pipe_->Start(&host_message_pipe_event_handler_);
    host_message_pipe_event_handler_.set_open_callback(base::Bind(
        &Server::OnHostChannelConnected, base::Unretained(this)));
  }

  void OnIncomingChannel(const std::string& name,
                         std::unique_ptr<remoting::protocol::MessagePipe> pipe) {
    //EXPECT_EQ(kChannelName, name);
    host_message_pipe_ = std::move(pipe);
    host_message_pipe_->Start(&host_message_pipe_event_handler_);
  }

  void OnHostChannelConnected() {
    LOG(INFO) << "OnHostChannelConnected";
  }

  void OnSessionError(remoting::protocol::TransportRole role, remoting::protocol::ErrorCode error) {
    LOG(INFO) << "OnSessionError";
    host_error_ = error;
  }

  void OnHostChannelClosed() {
    LOG(INFO) << "OnHostChannelClosed";
    host_message_pipe_.reset();
  }

private:
  //base::ThreadChecker thread_checker_;
  std::unique_ptr<remoting::protocol::WebrtcTransport> host_transport_;
  TestTransportEventHandler host_event_handler_;
  std::unique_ptr<FakeAuthenticator> host_authenticator_;
  std::unique_ptr<remoting::protocol::MessagePipe> host_message_pipe_;
  TestMessagePipeEventHandler host_message_pipe_event_handler_;
  remoting::protocol::ErrorCode host_error_ = remoting::protocol::OK;
  remoting::protocol::NetworkSettings network_settings_;
};

int main(int argc, char** argv) {
  Client client;
  Server server;
  base::MessageLoop mloop{base::MessageLoop::Type::TYPE_IO};
  base::RunLoop runloop;
  base::AtExitManager at_exit;

  base::CommandLine::Init(argc, argv);

  const auto* cmd = base::CommandLine::ForCurrentProcess();

  base::TaskScheduler::CreateAndStartWithDefaultParams("hello");
 
  if (cmd->HasSwitch("client")) {
    client.Init();
    client.Start();
  } else if (cmd->HasSwitch("server")) {
    server.Init();
    server.Start();
  }

  runloop.Run();

  if (cmd->HasSwitch("client")) {
    client.Exit();
  } else if (cmd->HasSwitch("server")) {
    server.Exit();
  }
}