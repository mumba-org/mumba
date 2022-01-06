// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_RPC_INDEXED_DB_HANDLER_H_
#define MUMBA_HOST_RPC_INDEXED_DB_HANDLER_H_

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

class IndexedDbClearObjectStoreHandler : public MumbaServicesUnaryCallHandler {
public:  
  static const char kFullname[];

  IndexedDbClearObjectStoreHandler();
  ~IndexedDbClearObjectStoreHandler();

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

class IndexedDbCountHandler : public MumbaServicesUnaryCallHandler {
public:  
  static const char kFullname[];

  IndexedDbCountHandler();
  ~IndexedDbCountHandler();

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

class IndexedDbDeleteDbHandler : public MumbaServicesUnaryCallHandler {
public:  
  static const char kFullname[];

  IndexedDbDeleteDbHandler();
  ~IndexedDbDeleteDbHandler();

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

class IndexedDbGetAllHandler : public MumbaServicesUnaryCallHandler {
public:  
  static const char kFullname[];

  IndexedDbGetAllHandler();
  ~IndexedDbGetAllHandler();

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

class IndexedDbGetHandler : public MumbaServicesUnaryCallHandler {
public:  
  static const char kFullname[];

  IndexedDbGetHandler();
  ~IndexedDbGetHandler();

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

class IndexedDbGetKeyHandler : public MumbaServicesUnaryCallHandler {
public:  
  static const char kFullname[];

  IndexedDbGetKeyHandler();
  ~IndexedDbGetKeyHandler();

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

class IndexedDbRequestDataHandler : public MumbaServicesUnaryCallHandler {
public:  
  static const char kFullname[];

  IndexedDbRequestDataHandler();
  ~IndexedDbRequestDataHandler();

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