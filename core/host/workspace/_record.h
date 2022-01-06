// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_WORKSPACE_RECORD_H_
#define MUMBA_HOST_WORKSPACE_RECORD_H_

#include <unordered_map>
#include <deque>
#include <memory>
#include <string>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "net/base/io_buffer.h"
#include "base/uuid.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/string_piece.h"
#include "core/host/serializable.h"

namespace host {
class DatabaseContext;

class RecordTable;
class RecordInode {
public:
  using Entries = std::unordered_map<base::UUID, std::unique_ptr<RecordInode>>;

  static std::unique_ptr<RecordInode> Deserialize(const base::StringPiece& data);
 
  RecordInode(RecordInode* parent, base::UUID id, const std::string& name);
  ~RecordInode();
 
  RecordInode* parent() const {
    return parent_;
  }

  const base::UUID& id() const {
    return id_;
  }

  const std::string& name() const {
    return name_;
  }

  const std::string& fullname() {
    if (fullname_.empty()) {
      ResolveFullname();
    }
    return fullname_;
  }

  const base::UUID& parent_id() {
    if (parent_id_.IsNull() && parent_) {
      parent_id_ = parent_->id_;
    }
    return parent_id_;
  }

  bool is_root() const {
    // only root has a null parent
    return parent_ == nullptr;
  }

  bool managed() const {
    return managed_;
  }

  void set_managed(bool managed) {
    managed_ = managed;
  }

  size_t entries_count() const {
    return entries_.size();
  } 

  const Entries& entries() const {
    return entries_;
  }

  void AddEntry(const base::UUID& id, std::unique_ptr<RecordInode> entry);
  void RemoveEntry(const base::UUID& id);

  scoped_refptr<net::IOBufferWithSize> Serialize();

private:
  friend class RecordTable;
  
  RecordInode();
  
  size_t GetEncodedLenght();
  void ResolveFullname();
  
  RecordInode* parent_;
  base::UUID id_;
  base::UUID parent_id_;
  std::string fullname_;
  std::string name_;
  Entries entries_;
  bool managed_;
};

class RecordTable {
public:
  RecordTable();
  ~RecordTable();
  
  RecordInode* root() const {
    return root_.get();
  }

  void set_root(std::unique_ptr<RecordInode> root) {
    root_ = std::move(root);
  }

  void Init(scoped_refptr<DatabaseContext> db_context, bool first_time);

private:

  void AddRecordIntoDB(RecordInode* inode, bool recursive);
  void RemoveRecordFromDB(RecordInode* inode);

  void OnRecordInsert(bool result);
  void OnRecordRemove(bool result);

  void ScheduleAddRecordIntoDB(RecordInode* inode);
  void AddRecordIntoDBInternal(RecordInode* inode);

  void Create();
  void Load();
  void LoadRecordsFromDB();

  scoped_refptr<DatabaseContext> db_context_;
  std::unique_ptr<RecordInode> root_;
  std::deque<RecordInode*> add_queue_;
  mutable bool insert_busy_;
};

}

#endif