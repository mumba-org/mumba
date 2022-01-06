// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_RPC_DROP_HANDLER_H_
#define MUMBA_HOST_RPC_DROP_HANDLER_H_

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

class BundleBuildHandler : public MumbaServicesUnaryCallHandler {
public:  
  static const char kFullname[];

  BundleBuildHandler();
  ~BundleBuildHandler();

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

class BundleInfoHandler : public MumbaServicesUnaryCallHandler {
public:  
  static const char kFullname[];

  BundleInfoHandler();
  ~BundleInfoHandler();

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

class BundleInstallHandler : public MumbaServicesUnaryCallHandler {
public:  
  static const char kFullname[];

  BundleInstallHandler();//const scoped_refptr<base::SequencedTaskRunner>& service_worker);
  ~BundleInstallHandler();

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

class BundleSignHandler : public MumbaServicesUnaryCallHandler {
public:  
  static const char kFullname[];

  BundleSignHandler();
  ~BundleSignHandler();

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

class BundleUninstallHandler : public MumbaServicesUnaryCallHandler {
public:  
  static const char kFullname[];

  BundleUninstallHandler();
  ~BundleUninstallHandler();

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

class BundleUpdateHandler : public MumbaServicesUnaryCallHandler {
public:  
  static const char kFullname[];

  BundleUpdateHandler();
  ~BundleUpdateHandler();

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