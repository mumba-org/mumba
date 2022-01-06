// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_KIT_CPP_LAUNCHER_RPC_CLIENT_H_
#define MUMBA_KIT_CPP_LAUNCHER_RPC_CLIENT_H_

#include <string>
#include "base/macros.h"
#include "base/command_line.h"
#include "rpc/grpc.h"

class RPCCall {
public:
  virtual ~RPCCall() {}
  virtual const std::string& method_name() const = 0;
  virtual const std::string& host() const = 0;
  virtual int port() = 0;
  virtual void Call(const base::CommandLine::StringVector& args, const std::string& encoded_data, int milliseconds) = 0;
};

class RPCUnaryCall : public RPCCall {
public:
  RPCUnaryCall(const std::string& host, int port, const std::string& method_name);
  ~RPCUnaryCall();

  const std::string& method_name() const override {
    return method_name_;
  }
  
  const std::string& host() const override {
    return host_;
  }
  
  int port() override {
    return port_;
  }

  char* output_data() {
    if (output_data_ == nullptr && output_buffer_) {
      ReadOutputBuffer();
    }
    return output_data_;
  }

  size_t output_data_size() const {
    return output_data_size_;
  }

  void Call(const base::CommandLine::StringVector& args, const std::string& encoded_data, int milliseconds = 5000) override;

private:

  void ReadOutputBuffer();

  std::string host_;
  int port_;
  std::string method_name_;
  grpc_completion_queue* completion_queue_ = nullptr; 
  grpc_byte_buffer* output_buffer_ = nullptr;
  char* output_data_ = nullptr;
  size_t output_data_size_ = 0;
  bool error_;

  DISALLOW_COPY_AND_ASSIGN(RPCUnaryCall);
};

class RPCClient {
public:
  RPCClient(const std::string& host, int port);
  ~RPCClient();   

  std::unique_ptr<RPCUnaryCall> CreateRPCUnaryCall(const std::string& method_name);

private:
  std::string host_;
  int port_;

  DISALLOW_COPY_AND_ASSIGN(RPCClient);   
};

#endif