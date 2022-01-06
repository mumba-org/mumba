// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_NAMESPACE_CONNECTION_H_
#define MUMBA_DOMAIN_NAMESPACE_CONNECTION_H_

#include <memory>

#include "base/macros.h"

namespace domain {
class Stream;

// TODO: stream management here
class Connection {
public:
  virtual ~Connection();
protected:
  Connection();
private:
  DISALLOW_COPY_AND_ASSIGN(Connection);
};

// a local IPC connection
class IPCConnection: public Connection {
public:
  IPCConnection();
  ~IPCConnection() override;
private:

};

// a remote HTTP connection
class HTTPConnection: public Connection {
public:
  HTTPConnection();
  ~HTTPConnection() override;
private:
  
};

}

#endif