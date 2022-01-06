// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/rpc/server/rpc_tree.h"

#include "base/stl_util.h"
#include "net/rpc/server/rpc_node.h"

namespace net {

RpcTree::Iterator::Iterator(const std::string& ns, RpcTree::Inode* root): ns_(ns), 
  root_(root), 
  current_(root) {

}

bool RpcTree::Iterator::HasNext() const {
 return root_ == current_ ? true : (current_ && current_->next != nullptr);
}

RpcNode* RpcTree::Iterator::Next() {
  RpcNode* node = current_->node;
  current_ = current_->next;
  return node;
}

RpcTree::RpcTree() {}

RpcTree::~RpcTree() {
  for (auto it = inodes_.begin(); it != inodes_.end(); it++) {
    Inode* inode = it->second;
    while (inode != nullptr) {
      Inode* to_delete = inode;
      inode = inode->next;
      // owned by Service
      //delete to_delete->node;
      delete to_delete;
    }
  }
  inodes_.clear();
}

std::unique_ptr<RpcTree::Iterator> RpcTree::Find(const std::string& ns) const {
  auto it = inodes_.find(ns);
  if (it == inodes_.end()) {
    std::unique_ptr<RpcTree::Iterator>();
  }

  return std::unique_ptr<RpcTree::Iterator>(new RpcTree::Iterator(ns, it->second));
}

void RpcTree::Add(RpcNode* node) {
  auto it = inodes_.find(node->ns());
  if (it != inodes_.end()) {
    Inode* cur = it->second;
    Inode* last = cur;
    while (cur != nullptr) {
      cur = cur->next;
      if (cur)
        last = cur;
    }
    Inode* inode = new Inode{};
    inode->node = node;
    inode->next = nullptr;
    last->next = inode;
  } else {
    Inode* inode = new Inode{};
    inode->node = node;
    inode->next = nullptr;
    inodes_.emplace(std::make_pair(node->ns(), inode));
  }
}

void RpcTree::Remove(RpcNode* node) {
  auto it = inodes_.find(node->ns());
  if (it != inodes_.end()) {
    Inode* cur = it->second;
    Inode* parent = cur;
    while (cur != nullptr) {
      if (cur->node == node) {
        // owned by Service
        //delete cur->node;
        if (parent && parent != cur) {
          // link the next of the inode to be deleted
          // to parent's next
          parent->next = cur->next;
        }
        delete cur;
        break;
      }
      parent = cur;
      cur = cur->next;
    }
  }
}

}