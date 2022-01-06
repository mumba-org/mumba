// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_CHANNEL_CHANNEL_MODEL_H_
#define MUMBA_HOST_CHANNEL_CHANNEL_MODEL_H_

#include <memory>

#include "base/macros.h"
#include "base/callback.h"
#include "base/memory/ref_counted.h"
#include "base/uuid.h"
#include "net/base/io_buffer.h"
#include "core/host/database_policy.h"

namespace host {
class Channel;
class ShareDatabase;

class ChannelModel : public DatabasePolicyObserver {
public:
  ChannelModel(scoped_refptr<ShareDatabase> db, DatabasePolicy policy);
  ~ChannelModel();

  const std::vector<std::unique_ptr<Channel>>& channels() const {
    return channels_;
  }

  std::vector<std::unique_ptr<Channel>>& channels() {
    return channels_;
  }

  void Load(base::Callback<void(int, int)> cb);
  size_t Count() const;
  bool ChannelExists(Channel* channel) const;
  bool ChannelExists(const std::string& scheme, const std::string& name) const;
  bool ChannelExists(const base::UUID& id) const;
  Channel* GetChannel(const std::string& scheme, const std::string& name);
  Channel* GetChannelById(const base::UUID& id);
  void InsertChannel(const base::UUID& id, std::unique_ptr<Channel> channel, bool persist, base::Callback<void(int)> cb = base::Callback<void(int)>());
  void RemoveChannel(Channel* channel, base::Callback<void(int)> cb = base::Callback<void(int)>());
  void RemoveChannel(const base::UUID& id, base::Callback<void(int)> cb = base::Callback<void(int)>());
  void RemoveChannel(const std::string& scheme, const std::string& name, base::Callback<void(int)> cb = base::Callback<void(int)>());
 
  void Close();

private:
  
  void InsertChannelInternal(const base::UUID& id, std::unique_ptr<Channel> channel, bool persist, base::Callback<void(int)> cb);
  void RemoveChannelInternal(Channel* channel, base::Callback<void(int)> cb);

  bool InsertChannelToDB(const base::UUID& id, Channel* channel);
  bool RemoveChannelFromDB(Channel* channel);

  void AddToCache(const base::UUID& id, std::unique_ptr<Channel> channel);
  void RemoveFromCache(const base::UUID& id);
  void RemoveFromCache(Channel* channel);

  void LoadChannelsFromDB(base::Callback<void(int, int)> cb);

  void OnInsertReply(bool result);
  void OnRemoveReply(bool result);
  void MaybeOpen();
  void MaybeClose();

  void OnDatabasePolicyChanged(DatabasePolicy new_policy) override;

  DatabasePolicy policy_;
  scoped_refptr<ShareDatabase> db_;
  
  std::vector<std::unique_ptr<Channel>> channels_;

private:

 DISALLOW_COPY_AND_ASSIGN(ChannelModel);
};

}

#endif