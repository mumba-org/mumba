// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/workspace/window_manager_service.h"

#include "base/strings/string_split.h"
#include "core/host/workspace/workspace.h"
#include "core/host/ui/window_manager.h"
#include "core/host/host_controller.h"
#include "core/host/rpc/server/rpc_socket_client.h"
#include "core/host/rpc/server/proxy_rpc_handler.h"

namespace host {

namespace {
  const char kLaunchWindowFullname[] = "/mumba.WindowManager/LaunchWindow";
}

class LaunchWindowHandler : public WindowManagerServiceUnaryCallHandler {
public:
  
  LaunchWindowHandler(): fullname_(kLaunchWindowFullname) {
    Init();
  }

  ~LaunchWindowHandler() override {}

  const std::string& fullname() const override {
    return fullname_;
  }

  base::StringPiece ns() const override {
    auto offset = service_name_.find_first_of(".");
    return service_name_.substr(offset);
  }
  
  base::StringPiece service_name() const override {
    return service_name_;
  }
  
  base::StringPiece method_name() const override {
    return method_name_;
  }

  void HandleCall(const std::string& url) override {
    WindowManager::WindowParams params;

    Workspace* workspace = HostController::Instance()->current_workspace();
    WindowManager* window_manager = workspace->window_manager();

    size_t domain_name_offset = url.find_first_of("/");

    std::string domain_name = url.substr(0, domain_name_offset);
    DLOG(INFO) << "resolve shell to launch window to '" << domain_name << "'";

    Domain* shell = workspace->GetDomain(domain_name);
    if (!shell) {
      DLOG(ERROR) << "shell '" << domain_name << "' not found. cancelling window launch";
      return;
    }

    params.target_url = url;
    params.target_shell = shell;
    
    HostThread::PostTask(HostThread::UI,
      FROM_HERE,
      base::Bind(&WindowManager::LaunchWindow, 
        base::Unretained(window_manager),
        params));
  }

private:
  
  void Init() {
     std::vector<base::StringPiece> pieces = base::SplitStringPiece(
      fullname_,
      "/",
      base::KEEP_WHITESPACE,
      base::SPLIT_WANT_NONEMPTY);

     service_name_ = pieces[0];
     method_name_ = pieces[1];
  }

  // TODO: Use just one string for everything and a StringPiece for parts
  std::string fullname_;
  base::StringPiece service_name_;
  base::StringPiece method_name_;
};

WindowManagerServiceHandler::WindowManagerServiceHandler(Delegate* delegate):
 delegate_(delegate) {

}

WindowManagerServiceHandler::~WindowManagerServiceHandler() {
  // dont forget to clean up, if somehow there are call that were
  // not cleanly ended
  for (auto it = calls_.begin(); it != calls_.end(); ++it) {
    delete it->second;
  }
  calls_.clear();
}

void WindowManagerServiceHandler::OnCallArrived(int call_id, const std::string& method_fullname) {
  DLOG(INFO) << "WindowManagerServiceHandler::OnCallArrived. method: " << method_fullname;
  if (method_fullname == kLaunchWindowFullname) {
    DLOG(INFO) << "WindowManagerServiceHandler::OnCallArrived: creating handler for LaunchUIHost";
    // TODO: dont need to use Heap allocation, if we know ahead of time. fix
    LaunchWindowHandler* handler = new LaunchWindowHandler();
    calls_.emplace(std::make_pair(call_id, handler));
    delegate_->OnCallArrived(call_id, handler->method_type(), true);
    return;
  }
  delegate_->OnCallArrived(call_id, -1, false);
}

void WindowManagerServiceHandler::OnCallDataAvailable(int call_id, const std::vector<char>& data) {
  DLOG(INFO) << "WindowManagerServiceHandler::OnCallDataAvailable";
  auto it = calls_.find(call_id);
  if (it != calls_.end()) {
    DLOG(INFO) << "WindowManagerServiceHandler::OnCallDataAvailable: handling " << it->second->method_name();
    WindowManagerServiceUnaryCallHandler* handler = it->second;
    handler->HandleCall("twitter/home");
    delegate_->OnCallDataAvailable(call_id, handler->method_type(), true);
    return;
  }
  delegate_->OnCallDataAvailable(call_id, -1, false);
}

void WindowManagerServiceHandler::OnCallEnded(int call_id) {
  DLOG(INFO) << "WindowManagerServiceHandler::OnCallEnded";
  auto it = calls_.find(call_id);
  if (it != calls_.end()) {
    DLOG(INFO) << "WindowManagerServiceHandler::OnCallEnded: cleaning up " << it->second->method_name(); 
    delegate_->OnCallEnded(call_id, it->second->method_type(), true);
    return;
  }
  delegate_->OnCallEnded(call_id, -1, false);
}

WindowManagerService::WindowManagerService(): 
  rpc_service_(nullptr),
  host_host_service_handler_(new WindowManagerServiceHandler(this)),
  accepted_client_(nullptr) {

}

WindowManagerService::~WindowManagerService() {
  rpc_service_ = nullptr;
}

bool WindowManagerService::Init(
  Workspace* workspace,
  const std::string& host, 
  int port, 
  void* state,
  void (*on_read_cb)(grpc_exec_ctx* exec_ctx, void* arg, grpc_error* err),
  base::Callback<void(int, net::SocketDescriptor)> on_service_started) {
  
  rpc_service_ = workspace->CreateService(
    "mumba",
    "WindowManager",
    host,
    port, 
    net::RpcTransportType::kHTTP,
    base::ThreadTaskRunnerHandle::Get(),
    std::make_unique<ProxyRpcHandler<WindowManagerServiceHandler>>(host_host_service_handler_.get()));

  if (!rpc_service_) {
    LOG(ERROR) << "Rpc server: Unable to create service 'mumba.WindowManager'";
    return false;
  }

  net::RpcServiceOptions& service_options = rpc_service_->options();
  service_options.state = state;
  service_options.read_callback = on_read_cb;

  int result = rpc_service_->Start(std::move(on_service_started));

  return result == 0;
}

bool WindowManagerService::Accept(
    const net::IPEndPoint& remote_address,
    std::unique_ptr<net::StreamSocket> socket,
    grpc_exec_ctx* exec_ctx, 
    server_state* state,
    grpc_endpoint* tcp,
    grpc_pollset* accepting_pollset,
    grpc_tcp_server_acceptor* acceptor) {

  std::unique_ptr<RpcSocketClient> client(new RpcSocketClient(id_gen_.GetNext() + 1));

  // not very good as more than one connection might arrive before
  // we can clean it up.. passing as state to get it later is the only option
  // better if we use a int identifier
  accepted_client_ = client.get();
  
  if (!client->InitAccepted(
      rpc_service_,
      remote_address, 
      std::move(socket),
      exec_ctx,
      state,
      tcp,
      accepting_pollset,
      acceptor)) {
    
    return false;
  }
    
  rpc_service_->RegisterSocket(client->socket());

  clients_.push_back(std::move(client));

  return true;
}

void WindowManagerService::OnCallArrived(int call_id, int method_type, bool result) {
  DCHECK(accepted_client_);
  if (result) {
    call_to_client_map_.emplace(std::make_pair(call_id, accepted_client_));
    accepted_client_->socket()->ReceiveMessage(call_id, method_type);
  }
  accepted_client_ = nullptr;
}

void WindowManagerService::OnCallDataAvailable(int call_id, int method_type, bool result) {
  std::vector<char> data = { 'G', 'I', 'B', 'B', 'E', 'R', 'I', 'S', 'H'};

  auto it = call_to_client_map_.find(call_id);
  if (result && it != call_to_client_map_.end()) {
    RpcSocketClient* client = it->second;
    client->socket()->SendMessage(call_id, data, method_type);
  }
}

void WindowManagerService::OnCallEnded(int call_id, int method_type, bool result) {
  DLOG(INFO) << "WindowManagerService::OnCallEnded: we are doing nothing";
}

}