// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_RPC_RPC_TREE_H_
#define NET_RPC_RPC_TREE_H_

#include <unordered_map>
#include <string>

#include "base/macros.h"
#include <memory>

namespace net {
class RpcNode;
// All the routes are organized in a tree
// no matter if they are from distinct shells

// The idea is to organize the roots according to its shell name or uuid
// so finding a giving route would be a matter of starting from its root
// which references its 'owning' parent shell

class RpcTree {
public:
  struct Inode {
    RpcNode* node;
    Inode* next;

    Inode(): 
      node(nullptr), 
      next(nullptr) {}
  };
  
  class Iterator {
  public:
    Iterator(const std::string& ns, Inode* root);
    const std::string& ns() const { return ns_; }
    bool HasNext() const;
    RpcNode* Next();
  
  private:
    std::string ns_;
    Inode* root_;
    Inode* current_;
  };
  
  RpcTree();
  ~RpcTree();

  std::unique_ptr<Iterator> Find(const std::string& ns) const;
  void Add(RpcNode* node);
  void Remove(RpcNode* node);

private:
  std::unordered_map<std::string, Inode*> inodes_;

  DISALLOW_COPY_AND_ASSIGN(RpcTree);
};

}

#endif