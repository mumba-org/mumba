// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/workspace/record.h"

#include "core/host/workspace/database.h"
#include "base/task_scheduler/post_task.h"
#include "base/bind.h"
#include "base/callback.h"
#include "db/db.h"
#include "db/sqlite3.h"
#include "db/sqliteInt.h"

namespace host {

namespace {
  
  std::vector<std::string> inode_names = {
    { "container" },
    { "shell" },
    { "service" },
    { "proto" },
    { "device" }
  };

}

std::unique_ptr<RecordInode> RecordInode::Deserialize(const base::StringPiece& data) {
  std::unique_ptr<RecordInode> inode(new RecordInode());
  uint8_t const* d = reinterpret_cast<uint8_t const*>(data.data());

  uint64_t fullname_len, name_len;

  inode->id_ = base::UUID(d);
  d += 16; // size of uuid in bytes

  inode->parent_id_ = base::UUID(d);
  d += 16; // parent uuid in bytes
  
  d += csqliteGetVarint(d, (u64*)&name_len);
  inode->name_ = std::string(reinterpret_cast<char const*>(d), name_len);
  d += name_len;

  d += csqliteGetVarint(d, (u64*)&fullname_len);
  inode->fullname_ = std::string(reinterpret_cast<char const*>(d), fullname_len);
    
  return inode;
}

RecordInode::RecordInode(RecordInode* parent, base::UUID id, const std::string& name): 
  parent_(parent),
  id_(std::move(id)),
  name_(name),
  managed_(false) {

}

RecordInode::RecordInode(): 
  parent_(nullptr),
  managed_(false) {

}

RecordInode::~RecordInode() {

}

void RecordInode::AddEntry(const base::UUID& id, std::unique_ptr<RecordInode> entry) {
  entries_.emplace(std::make_pair(id, std::move(entry)));
}

void RecordInode::RemoveEntry(const base::UUID& id) {
  auto it = entries_.find(id);
  if (it != entries_.end()) {
    entries_.erase(it);
  }
}

scoped_refptr<net::IOBufferWithSize> RecordInode::Serialize() {
  scoped_refptr<net::IOBufferWithSize> buffer;
  
  size_t len = GetEncodedLenght();
 
  buffer = new net::IOBufferWithSize(len);
  uint8_t* buf = reinterpret_cast<uint8_t *>(buffer->data());
  memset(buf, 0, len);
  
  // id
  memcpy(buf, id_.data, 16);
  buf += 16;//csqlitePutVarint(buf, id_);

  // parent id
  memcpy(buf, parent_id().data, 16);
  buf += 16;

  // name
  buf += csqlitePutVarint(buf, name_.size());
  memcpy(buf, name_.data(), name_.size());
  buf += name_.size();

  // fullname
  const std::string& _fullname = fullname();
  buf += csqlitePutVarint(buf, _fullname.size());
  memcpy(buf, _fullname.data(), _fullname.size());
  buf += _fullname.size();

  // TODO: codify all the entries uid's
  
  return buffer;
}

size_t RecordInode::GetEncodedLenght() {
  const std::string& _fullname = fullname();
  
  size_t len = 
    16 + // uuid
    16 + // parent_uuid
    csqliteVarintLen(name().size()) + 
    name().size() +
    csqliteVarintLen(_fullname.size()) + 
    _fullname.size();

  return len;
}

void RecordInode::ResolveFullname() {
  std::vector<std::string> names;
  RecordInode* p = parent_;
  names.push_back(name_);
  
  while (p != nullptr) {
    names.push_back(p->name_);
    p = p->parent_;
  }

  for (auto it = names.rbegin(); it != names.rend(); ++it) {
    fullname_.append(*it);
    fullname_.append(".");
  }
  
  fullname_.pop_back();
}


RecordTable::RecordTable(): insert_busy_(false) {

}

RecordTable::~RecordTable() {
  db_context_ = nullptr;
}

void RecordTable::Init(scoped_refptr<DatabaseContext> db_context, bool first_time) {
  db_context_ = db_context;
  if (first_time) {
    Create();
  } else {
    Load();
  }
}

void RecordTable::AddRecordIntoDB(RecordInode* inode, bool recursive) {
  if (recursive) {
    ScheduleAddRecordIntoDB(inode);
    // just one level for now
    for (auto it = inode->entries_.begin(); it != inode->entries_.end(); it++) {
      ScheduleAddRecordIntoDB(it->second.get());
    }
  } else {
    ScheduleAddRecordIntoDB(inode);
  }
}

void RecordTable::AddRecordIntoDBInternal(RecordInode* inode) {
  insert_busy_ = true;
  scoped_refptr<net::IOBufferWithSize> data = inode->Serialize();
  db_context_->Insert("record", inode->fullname(), data, 
    base::Bind(&RecordTable::OnRecordInsert, base::Unretained(this)));
}

void RecordTable::ScheduleAddRecordIntoDB(RecordInode* inode) {
  if (insert_busy_) {
    add_queue_.push_back(inode);
  } else if (add_queue_.size() > 0) {
    RecordInode* to_send = add_queue_.front();
    AddRecordIntoDBInternal(to_send);
    add_queue_.pop_front();
    add_queue_.push_back(inode);
  } else {
    AddRecordIntoDBInternal(inode);
  }
}

void RecordTable::RemoveRecordFromDB(RecordInode* inode) {
  db_context_->Remove("record", inode->fullname(), 
    base::Bind(&RecordTable::OnRecordRemove, base::Unretained(this)));
}

void RecordTable::OnRecordInsert(bool result) {
  DLOG(INFO) << "record insertion on db: "  << (result ? "ok" : "failed");
  insert_busy_ = false;
  if (add_queue_.size()) {
    RecordInode* to_send = add_queue_.front();
    add_queue_.pop_front();
    ScheduleAddRecordIntoDB(to_send);
  }
}

void RecordTable::OnRecordRemove(bool result) {
  DLOG(INFO) << "record deletion on db: "  << (result ? "ok" : "failed");
}

void RecordTable::Create() {
  root_.reset(new RecordInode(nullptr, base::UUID::generate(), "self"));
  for (size_t i = 0; i < inode_names.size(); i++) {
    std::unique_ptr<RecordInode> child = std::make_unique<RecordInode>(root_.get(), base::UUID::generate(), inode_names[i]);
    root_->AddEntry(child->id(), std::move(child));
  }
  AddRecordIntoDB(root_.get(), true);
}

void RecordTable::Load() {
  db_context_->io_task_runner()->PostTask(
    FROM_HERE,
    base::Bind(
      &RecordTable::LoadRecordsFromDB,
        base::Unretained(this)));
}

void RecordTable::LoadRecordsFromDB() {
  size_t count = 0;
  auto it = db_context_->GetIterator("record");
  it->First();
  while (it->HasNext()) {
    base::StringPiece payload = it->GetValue();
    if (payload.size()) {
      std::unique_ptr<RecordInode> r = RecordInode::Deserialize(payload.as_string());
      if (r) {
        r->set_managed(true);
        printf("record - uuid: %s name: %s fullname: %s\n", r->id().to_string().c_str(), r->name().c_str(), r->fullname().c_str());
        if (r->name() == "self") {
          root_ = std::move(r);
        } else {
          DCHECK(root_);
          root_->AddEntry(r->id(), std::move(r));
        }
         
      } else {
        LOG(ERROR) << "failed to deserialize record inode";
      }
    } else {
      LOG(ERROR) << "failed to deserialize record inode: it->GetValue() returned nothing";
    }
    it->Next();
    count++;
  }
  it.reset();
  printf("record inodes recovered from db: %zu records\n", count);
}

}