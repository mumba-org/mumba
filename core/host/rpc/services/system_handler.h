// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_RPC_SYSTEM_HANDLER_H_
#define MUMBA_HOST_RPC_SYSTEM_HANDLER_H_

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

class SystemCpuInfoHandler : public MumbaServicesUnaryCallHandler {
public:  
  static const char kFullname[];

  SystemCpuInfoHandler();
  ~SystemCpuInfoHandler();

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

class SystemGpuInfoHandler : public MumbaServicesUnaryCallHandler {
public:  
  static const char kFullname[];

  SystemGpuInfoHandler();
  ~SystemGpuInfoHandler();

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

class SystemMemoryInfoHandler : public MumbaServicesUnaryCallHandler {
public:  
  static const char kFullname[];

  SystemMemoryInfoHandler();
  ~SystemMemoryInfoHandler();

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

class SystemShutdownHandler : public MumbaServicesUnaryCallHandler {
public:
  static const char kFullname[];

  SystemShutdownHandler();
  ~SystemShutdownHandler() override;

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

  const std::string& output() const override {
    return output_;
  }

  void HandleCall(std::vector<char> data, base::Callback<void(int)> cb) override;
  void ShutdownOnUI(base::Callback<void(int)> cb);

private:
  
  void Init();

  std::string fullname_;
  base::StringPiece service_name_;
  base::StringPiece method_name_;
  std::string output_;

  DISALLOW_COPY_AND_ASSIGN(SystemShutdownHandler);
};

class SystemStatusHandler : public MumbaServicesUnaryCallHandler {
public:  
  static const char kFullname[];

  SystemStatusHandler();
  ~SystemStatusHandler();

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

class SystemStorageHandler : public MumbaServicesUnaryCallHandler {
public:  
  static const char kFullname[];

  SystemStorageHandler();
  ~SystemStorageHandler();

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

class SystemUpdateHandler : public MumbaServicesUnaryCallHandler {
public:  
  static const char kFullname[];

  SystemUpdateHandler();
  ~SystemUpdateHandler();

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

class SystemVersionHandler : public MumbaServicesUnaryCallHandler {
public:  
  static const char kFullname[];

  SystemVersionHandler();
  ~SystemVersionHandler();

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