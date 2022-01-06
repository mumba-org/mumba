// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_NAMESPACE_SESSION_H_
#define MUMBA_DOMAIN_NAMESPACE_SESSION_H_

#include <memory>
#include "base/macros.h"
#include "url/gurl.h"

namespace domain {
class Connection;

// A namespace session is a client connected to one or more routes
class Session {
public:
  struct Subscription {
    GURL channel_url;
  };

  Session(std::unique_ptr<Connection> connection);
  ~Session();

  int id() const {
    return id_;
  }

  Connection* connection() const {
    return connection_.get();
  }

  const std::vector<Subscription *>& subscriptions() const {
    return subscriptions_;
  }

  void AddSubscription(const std::string& name);
  void RemoveSubscription(const std::string& name);

private:
  
  int id_;

  std::unique_ptr<Connection> connection_;

  std::vector<Subscription *> subscriptions_;

  DISALLOW_COPY_AND_ASSIGN(Session);
};

}

#endif