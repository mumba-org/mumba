// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_RPC_SERVICE_START_HANDLER_H_
#define MUMBA_HOST_RPC_SERVICE_START_HANDLER_H_

#include <memory>
#include <string>
#include <vector>
#include "base/macros.h"
#include "base/callback.h"
#include "base/sequenced_task_runner.h"
#include "rpc/grpc.h"
#include "net/base/completion_callback.h"
#include "core/host/rpc/services/mumba_services.h"

namespace host {

class ServiceStartHandler : public MumbaServicesUnaryCallHandler {
public:
  
  static const char kFullname[];

  ServiceStartHandler();
  ~ServiceStartHandler() override;

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

  const std::string& output() const  override {
    return output_;
  }

  void HandleCall(std::vector<char> data, base::Callback<void(int)> cb) override;

private:
  
  void Init();
  void ProcessServiceStartOnUI(const std::string& service_name, base::Callback<void(int)> cb);
  void OnApplicationInstanceLaunched(base::Callback<void(int)> cb, int r);

  // TODO: Use just one string for everything and a StringPiece for parts
  std::string fullname_;
  base::StringPiece service_name_;
  base::StringPiece method_name_;
  std::string output_;
};

}

#endif