// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_RPC_CLIENT_RPC_HOST_H_
#define NET_RPC_CLIENT_RPC_HOST_H_

#include <unordered_map>
#include <string>
#include <memory>

#include "base/macros.h"
//#include "base/threading/sequenced_worker_pool.h"
#include "core/shared/common/url.h"
#include "net/rpc/rpc.h"

namespace host {
class RpcClient;

typedef std::unordered_map<std::string, net::RpcDescriptor*> RpcNodes;
typedef RpcNodes::const_iterator RpcNodesConstIterator;
typedef RpcNodes::iterator RpcNodesIterator;

class NET_EXPORT RpcNodeIterator {
public:
  RpcNodeIterator(RpcNodesConstIterator begin, RpcNodesConstIterator end);

  bool HasNext() const;
  net::RpcDescriptor* Next();

private:
  RpcNodesConstIterator begin_;
  RpcNodesConstIterator end_;

  RpcNodesConstIterator& current_;
};

class NET_EXPORT RpcHost {
public:
  RpcHost();
  ~RpcHost();

  std::unique_ptr<RpcNodeIterator> iterator() const {
    return std::unique_ptr<RpcNodeIterator>(new RpcNodeIterator(begin(), end()));
  }

  net::RpcDescriptor* GetNode(const std::string& name) const;
  net::RpcDescriptor* GetNode(const base::UUID& uuid) const;
  void AddNode(net::RpcDescriptor* node);
  void AddNode(std::unique_ptr<net::RpcDescriptor> node);
  void AddNodes(std::vector<net::RpcDescriptor> descriptors);
  void RemoveNode(net::RpcDescriptor* node);
  void RemoveNode(const std::string& key);

  RpcClient* NewClient();

private:

  RpcNodesConstIterator begin() const { return nodes_.begin(); }
  RpcNodesIterator begin() { return nodes_.begin(); }

  RpcNodesConstIterator end() const { return nodes_.end(); }
  RpcNodesIterator end() { return nodes_.end(); }

  RpcNodes nodes_;

  std::unordered_map<base::UUID, std::string> uuid_index_;

  std::vector<RpcClient*> clients_;

  std::vector<net::RpcDescriptor> owned_nodes_;

  //scoped_refptr<base::SequencedWorkerPool> worker_pool_;

  DISALLOW_COPY_AND_ASSIGN(RpcHost);
};

}

#endif