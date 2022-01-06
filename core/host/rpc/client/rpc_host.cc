// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/client/rpc_host.h"

#include "base/stl_util.h"
#include "base/strings/string_util.h"
#include "core/host/rpc/client/rpc_client.h"

namespace host {

// namespace {

// //const size_t kNumWorkerThreads = 4;

// std::string FormID(const URL& url) {
//   std::string path = url.spec();//url.path();
//   size_t pos = path.find('/');
//   return pos == std::string::npos ? path : path.substr(pos+1);//std::string(url.scheme() + "://" + url.host());
// }

// }  

RpcHost::RpcHost() {}//: 
 // worker_pool_(new base::SequencedWorkerPool(kNumWorkerThreads, "RpcClientWorker")) {

RpcHost::~RpcHost() {
  //worker_pool_->Shutdown();
  for (auto it = clients_.begin(); it != clients_.end(); ++it) {
    delete *it;
  }
  clients_.clear();

  for (auto it = nodes_.begin(); it != nodes_.end(); ++it) {
    delete it->second;
  }
  nodes_.clear();
}

net::RpcDescriptor* RpcHost::GetNode(const std::string& name) const {
  auto it = nodes_.find(name);
  if (it != nodes_.end()) {
    return it->second;
  }
  return nullptr;
}

net::RpcDescriptor* RpcHost::GetNode(const base::UUID& uuid) const {
  auto it = uuid_index_.find(uuid);
  if (it != uuid_index_.end()) {
    return nodes_.find(it->second)->second;
  }
  return nullptr;
}

void RpcHost::AddNode(net::RpcDescriptor* node) {
  std::string key = base::ToLowerASCII(node->name);//FormID(node->url);
  uuid_index_.emplace(std::make_pair(node->uuid, key));
  nodes_.emplace(std::make_pair(key, node));
}

void RpcHost::AddNode(std::unique_ptr<net::RpcDescriptor> node) {
  std::string key = base::ToLowerASCII(node->name);//FormID(node->url); 
  uuid_index_.emplace(std::make_pair(node->uuid, key));
  nodes_.emplace(std::make_pair(key, node.release()));
}

void RpcHost::AddNodes(std::vector<net::RpcDescriptor> descriptors) {
  // TODO: we should actually append
  owned_nodes_ = std::move(descriptors);
  for (auto it = owned_nodes_.begin(); it != owned_nodes_.end(); ++it) {
    std::string key = base::ToLowerASCII(it->name);//FormID(it->url);
    uuid_index_.emplace(std::make_pair(it->uuid, key));
    nodes_.emplace(std::make_pair(key, &(*it)));
  }
}

void RpcHost::RemoveNode(net::RpcDescriptor* node) {
  std::string key =node->name;//FormID(node->url);
  auto it = nodes_.find(key);
  if (it != nodes_.end()) {
    net::RpcDescriptor* node = it->second;
    auto index_it = uuid_index_.find(it->second->uuid);
    uuid_index_.erase(index_it);
    nodes_.erase(it);
    delete node;
  }
}

void RpcHost::RemoveNode(const std::string& key) {
  auto it = nodes_.find(key);
  if (it != nodes_.end()) {
    net::RpcDescriptor* node = it->second;
    auto index_it = uuid_index_.find(it->second->uuid);
    uuid_index_.erase(index_it);
    nodes_.erase(it);
    delete node;
  }
}

RpcClient* RpcHost::NewClient() {
  RpcClient* client = new RpcClient(this);//RpcClient(this, worker_pool_);
  clients_.push_back(client);
  return client;
}

RpcNodeIterator::RpcNodeIterator(RpcNodesConstIterator begin, RpcNodesConstIterator end): 
  begin_(std::move(begin)), 
  end_(std::move(end)),
  current_(begin_) {

}

bool RpcNodeIterator::HasNext() const {
  return current_ != end_;
}

net::RpcDescriptor* RpcNodeIterator::Next() {
  net::RpcDescriptor* node = current_->second;
  current_++;
  return node;
}

}