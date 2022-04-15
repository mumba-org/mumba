// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/channel/channel_model.h"

#include "base/task_scheduler/post_task.h"
#include "core/host/channel/channel.h"
#include "core/host/workspace/workspace.h"
#include "core/host/share/share_database.h"
#include "storage/db/db.h"
#include "storage/torrent.h"

namespace host {

ChannelModel::ChannelModel(scoped_refptr<ShareDatabase> db, DatabasePolicy policy): 
  policy_(policy),
  db_(db) {
  
}

ChannelModel::~ChannelModel() {
  channels_.clear();
  db_ = nullptr;
}

void ChannelModel::Load(base::Callback<void(int, int)> cb) {
  LoadChannelsFromDB(std::move(cb));
}

void ChannelModel::Close() {
 //db_->Close();
}

void ChannelModel::InsertChannel(const base::UUID& id, std::unique_ptr<Channel> channel, bool persist, base::Callback<void(int)> cb) {
  InsertChannelInternal(id, std::move(channel), persist, std::move(cb));
}

void ChannelModel::RemoveChannel(const base::UUID& id, base::Callback<void(int)> cb) {
  Channel* channel = GetChannelById(id);
  if (channel) {
    RemoveChannelInternal(channel, std::move(cb));
  } else {
    if (!cb.is_null()) {
      std::move(cb).Run(net::ERR_FAILED);
    }
  }
}

void ChannelModel::RemoveChannel(const std::string& scheme, const std::string& name, base::Callback<void(int)> cb) {
  Channel* channel = GetChannel(scheme, name);
  if (channel) {
    RemoveChannelInternal(channel, std::move(cb));
  } else {
    if (!cb.is_null()) {
      std::move(cb).Run(net::ERR_FAILED);
    }
  }
}

void ChannelModel::RemoveChannel(Channel* channel, base::Callback<void(int)> cb) {
  RemoveChannelInternal(channel, std::move(cb));
}

void ChannelModel::InsertChannelInternal(const base::UUID& id, std::unique_ptr<Channel> channel, bool persist, base::Callback<void(int)> cb) {
  if (!ChannelExists(channel.get())) {
    if (InsertChannelToDB(id, channel.get())) {
      AddToCache(id, std::move(channel));
      if (!cb.is_null())
        std::move(cb).Run(net::OK);
      return;
    }
    if (!cb.is_null())
      std::move(cb).Run(net::ERR_FAILED);
  } else {
    LOG(ERROR) << "Failed to add channel " << id.to_string() << " to DB. Already exists";
    if (!cb.is_null()) {
      std::move(cb).Run(net::ERR_FAILED);
    }
  }
}

void ChannelModel::RemoveChannelInternal(Channel* channel, base::Callback<void(int)> cb) {
  if (RemoveChannelFromDB(channel)) {
    RemoveFromCache(channel);
    if (!cb.is_null())
      std::move(cb).Run(net::OK);
    return;
  }
  if (!cb.is_null())
    std::move(cb).Run(net::ERR_FAILED);
}

bool ChannelModel::InsertChannelToDB(const base::UUID& id, Channel* channel) {
  //bool result = false;
  scoped_refptr<net::IOBufferWithSize> data = channel->Serialize();
  if (data) {
    MaybeOpen();
    storage::Transaction* trans = db_->Begin(true);
    bool ok = db_->Put(trans, Channel::kClassName, channel->name(), base::StringPiece(data->data(), data->size()));
    ok ? trans->Commit() : trans->Rollback();
    MaybeClose();
    return ok;
  }
  return false;
}

bool ChannelModel::RemoveChannelFromDB(Channel* channel) {
  MaybeOpen();
  storage::Transaction* trans = db_->Begin(true);
  bool ok = db_->Delete(trans, Channel::kClassName, channel->name());//, base::Bind(&ChannelModel::OnRemoveReply, base::Unretained(this)));
  ok ? trans->Commit() : trans->Rollback();
  MaybeClose();
  return ok;
}

void ChannelModel::LoadChannelsFromDB(base::Callback<void(int, int)> cb) {
  size_t count = 0;
  MaybeOpen();
  storage::Transaction* trans = db_->Begin(false);
  storage::Cursor* it = trans->CreateCursor(Channel::kClassName);
  if (!it) {
    DLOG(ERROR) << "ChannelModel::LoadChannelsFromDB: creating cursor for 'channel' failed.";
    std::move(cb).Run(net::ERR_FAILED, count);
    return;
  }
  it->First();
  while (it->IsValid()) {
    bool valid = false;
    storage::KeyValuePair kv = storage::DbDecodeKV(it->GetData(), &valid);
    if (valid) {
      // even if this is small.. having to heap allocate here is not cool
      scoped_refptr<net::StringIOBuffer> buffer = new net::StringIOBuffer(kv.second.as_string());
      std::unique_ptr<Channel> p = Channel::Deserialize(buffer.get(), kv.second.size());
      if (p) {
        p->set_managed(true);
        channels_.push_back(std::move(p));
      } else {
        LOG(ERROR) << "failed to deserialize channel";
      }
    } else {
      LOG(ERROR) << "failed to deserialize channel: it->GetValue() returned nothing";
    }
    it->Next();
    count++;
  }
  trans->Commit();
  MaybeClose();
  std::move(cb).Run(net::OK, count);
}

Channel* ChannelModel::GetChannel(const std::string& scheme, const std::string& name) {
  for (auto it = channels_.begin(); it != channels_.end(); ++it) {
    if ((*it)->scheme() == scheme && (*it)->name() == name) {
      return it->get();
    }
  }
  return nullptr; 
}

Channel* ChannelModel::GetChannelByName(const std::string& name) {
  for (auto it = channels_.begin(); it != channels_.end(); ++it) {
    if ((*it)->name() == name) {
      return it->get();
    }
  }
  return nullptr; 
}

Channel* ChannelModel::GetChannelById(const base::UUID& id) {
  for (auto it = channels_.begin(); it != channels_.end(); ++it) {
    if ((*it)->id() == id) {
      return it->get();
    }
  }
  return nullptr;
}

size_t ChannelModel::Count() const {
  return channels_.size();
}

bool ChannelModel::ChannelExists(Channel* channel) const {
  for (auto it = channels_.begin(); it != channels_.end(); ++it) {
    if ((*it)->scheme() == channel->scheme() && (*it)->name() == channel->name()) {
      return true;
    }
  }
  return false; 
}

bool ChannelModel::ChannelExists(const std::string& scheme, const std::string& name) const {
  for (auto it = channels_.begin(); it != channels_.end(); ++it) {
    if ((*it)->scheme() == scheme && (*it)->name() == name) {
      return true;
    }
  }
  return false; 
}

bool ChannelModel::ChannelExists(const std::string& name) const {
  for (auto it = channels_.begin(); it != channels_.end(); ++it) {
    if ((*it)->name() == name) {
      return true;
    }
  }
  return false; 
}

bool ChannelModel::ChannelExists(const base::UUID& id) const {
  for (auto it = channels_.begin(); it != channels_.end(); ++it) {
    if ((*it)->id() == id) {
      return true;
    }
  }
  return false; 
}

void ChannelModel::AddToCache(const base::UUID& id, std::unique_ptr<Channel> channel) {
  channel->set_managed(true);
  channels_.push_back(std::move(channel));
}

void ChannelModel::RemoveFromCache(const base::UUID& id) {
  for (auto it = channels_.begin(); it != channels_.end(); ++it) {
    if ((*it)->id() == id) {
      channels_.erase(it);
      return;
    }
  }
}

void ChannelModel::RemoveFromCache(Channel* channel) {
  for (auto it = channels_.begin(); it != channels_.end(); ++it) {
    if (it->get() == channel) {
      channels_.erase(it);
      return;
    }
  }
}

void ChannelModel::MaybeOpen() {
  if (policy_ != DatabasePolicy::OpenClose) {
    return;
  }
  if (!db_->is_open()) {
    //DLOG(INFO) << "ChannelModel::MaybeOpen: db is not open, reopening...";
    db_->Open(true);
  }
}

void ChannelModel::MaybeClose() {
  if (policy_ != DatabasePolicy::OpenClose) {
    return;
  }
  if (db_->is_open()) {
    db_->Close();
  }
}

void ChannelModel::OnDatabasePolicyChanged(DatabasePolicy new_policy) {
  policy_ = new_policy;
}

}
