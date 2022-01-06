// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_RPC_DOM_HANDLER_H_
#define MUMBA_HOST_RPC_DOM_HANDLER_H_

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

class DomFocusHandler : public MumbaServicesUnaryCallHandler {
public:  
  static const char kFullname[];

  DomFocusHandler();
  ~DomFocusHandler();

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

class DomGetAttributesHandler : public MumbaServicesUnaryCallHandler {
public:  
  static const char kFullname[];

  DomGetAttributesHandler();
  ~DomGetAttributesHandler();

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

class DomGetOuterHtmlHandler : public MumbaServicesUnaryCallHandler {
public:  
  static const char kFullname[];

  DomGetOuterHtmlHandler();
  ~DomGetOuterHtmlHandler();

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

class DomGetSearchResultHandler : public MumbaServicesUnaryCallHandler {
public:  
  static const char kFullname[];

  DomGetSearchResultHandler();
  ~DomGetSearchResultHandler();

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

class DomMoveToHandler : public MumbaServicesUnaryCallHandler {
public:  
  static const char kFullname[];

  DomMoveToHandler();
  ~DomMoveToHandler();

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

class DomPerformSearchHandler : public MumbaServicesUnaryCallHandler {
public:  
  static const char kFullname[];

  DomPerformSearchHandler();
  ~DomPerformSearchHandler();

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

class DomQuerySelectorHandler : public MumbaServicesUnaryCallHandler {
public:  
  static const char kFullname[];

  DomQuerySelectorHandler();
  ~DomQuerySelectorHandler();

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

class DomSetAttributeHandler : public MumbaServicesUnaryCallHandler {
public:  
  static const char kFullname[];

  DomSetAttributeHandler();
  ~DomSetAttributeHandler();

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

class DomSetNodeNameHandler : public MumbaServicesUnaryCallHandler {
public:  
  static const char kFullname[];

  DomSetNodeNameHandler();
  ~DomSetNodeNameHandler();

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

class DomSetNodeValueHandler : public MumbaServicesUnaryCallHandler {
public:  
  static const char kFullname[];

  DomSetNodeValueHandler();
  ~DomSetNodeValueHandler();

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

class DomSetOuterHtmlHandler : public MumbaServicesUnaryCallHandler {
public:  
  static const char kFullname[];

  DomSetOuterHtmlHandler();
  ~DomSetOuterHtmlHandler();

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