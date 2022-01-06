// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_RPC_PAYMENT_HANDLER_H_
#define MUMBA_HOST_RPC_PAYMENT_HANDLER_H_

#include <memory>
#include <string>
#include <vector>
#include "base/macros.h"
#include "base/callback.h"
#include "base/files/file_path.h"
#include "base/sequenced_task_runner.h"
#include "rpc/grpc.h"
#include "net/base/completion_callback.h"
#include "core/host/rpc/services/mumba_services.h"

namespace host {

class PaymentClearHandler : public MumbaServicesUnaryCallHandler {
public:  
  static const char kFullname[];

  PaymentClearHandler();
  ~PaymentClearHandler();

  const std::string& fullname() const override {
    return fullname_;
  }

  base::StringPiece ns() const override;
  
  base::StringPiece service_name() const override {
    return service_name_;
  }
  
  base::StringPiece method_name() const override {
    return method_name_;
  }

  const std::string& output() const override;

  void HandleCall(std::vector<char> data, base::Callback<void(int)> cb) override;
  
private:
  
  void Init();
  
  // TODO: Use just one string for everything and a StringPiece for parts
  std::string fullname_;
  base::StringPiece service_name_;
  base::StringPiece method_name_;
  
};

class PaymentSetHandler : public MumbaServicesUnaryCallHandler {
public:  
  static const char kFullname[];

  PaymentSetHandler();
  ~PaymentSetHandler();

  const std::string& fullname() const override {
    return fullname_;
  }

  base::StringPiece ns() const override;
  
  base::StringPiece service_name() const override {
    return service_name_;
  }
  
  base::StringPiece method_name() const override {
    return method_name_;
  }

  const std::string& output() const override;

  void HandleCall(std::vector<char> data, base::Callback<void(int)> cb) override;
  
private:
  
  void Init();
  
  // TODO: Use just one string for everything and a StringPiece for parts
  std::string fullname_;
  base::StringPiece service_name_;
  base::StringPiece method_name_;
  
};

class PaymentListHandler : public MumbaServicesUnaryCallHandler {
public:  
  static const char kFullname[];

  PaymentListHandler();
  ~PaymentListHandler();

  const std::string& fullname() const override {
    return fullname_;
  }

  base::StringPiece ns() const override;
  
  base::StringPiece service_name() const override {
    return service_name_;
  }
  
  base::StringPiece method_name() const override {
    return method_name_;
  }

  const std::string& output() const override;

  void HandleCall(std::vector<char> data, base::Callback<void(int)> cb) override;
  
private:
  
  void Init();
  
  // TODO: Use just one string for everything and a StringPiece for parts
  std::string fullname_;
  base::StringPiece service_name_;
  base::StringPiece method_name_;
  
};

class PaymentKeysHandler : public MumbaServicesUnaryCallHandler {
public:  
  static const char kFullname[];

  PaymentKeysHandler();
  ~PaymentKeysHandler();

  const std::string& fullname() const override {
    return fullname_;
  }

  base::StringPiece ns() const override;
  
  base::StringPiece service_name() const override {
    return service_name_;
  }
  
  base::StringPiece method_name() const override {
    return method_name_;
  }

  const std::string& output() const override;

  void HandleCall(std::vector<char> data, base::Callback<void(int)> cb) override;
  
private:
  
  void Init();
  
  // TODO: Use just one string for everything and a StringPiece for parts
  std::string fullname_;
  base::StringPiece service_name_;
  base::StringPiece method_name_;
  
};

class PaymentGetHandler : public MumbaServicesUnaryCallHandler {
public:  
  static const char kFullname[];

  PaymentGetHandler();
  ~PaymentGetHandler();

  const std::string& fullname() const override {
    return fullname_;
  }

  base::StringPiece ns() const override;
  
  base::StringPiece service_name() const override {
    return service_name_;
  }
  
  base::StringPiece method_name() const override {
    return method_name_;
  }

  const std::string& output() const override;

  void HandleCall(std::vector<char> data, base::Callback<void(int)> cb) override;
  
private:
  
  void Init();
  
  // TODO: Use just one string for everything and a StringPiece for parts
  std::string fullname_;
  base::StringPiece service_name_;
  base::StringPiece method_name_;
  
};

class PaymentDeleteHandler : public MumbaServicesUnaryCallHandler {
public:  
  static const char kFullname[];

  PaymentDeleteHandler();
  ~PaymentDeleteHandler();

  const std::string& fullname() const override {
    return fullname_;
  }

  base::StringPiece ns() const override;
  
  base::StringPiece service_name() const override {
    return service_name_;
  }
  
  base::StringPiece method_name() const override {
    return method_name_;
  }

  const std::string& output() const override;

  void HandleCall(std::vector<char> data, base::Callback<void(int)> cb) override;
  
private:
  
  void Init();
  
  // TODO: Use just one string for everything and a StringPiece for parts
  std::string fullname_;
  base::StringPiece service_name_;
  base::StringPiece method_name_;
  
};

}

#endif