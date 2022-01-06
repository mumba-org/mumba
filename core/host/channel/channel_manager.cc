// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/channel/channel_manager.h"

#include "base/path_service.h"
#include "base/base_paths.h"
#include "base/files/file_util.h"
#include "base/task_scheduler/post_task.h"
#include "core/shared/common/paths.h"
#include "core/host/host_thread.h"
#include "core/host/channel/channel.h"
#include "core/host/channel/channel_model.h"
#include "core/host/share/share_database.h"
#include "core/host/workspace/workspace.h"
#include "storage/torrent.h"

namespace host {

namespace {

void ReplyChannelCreated(common::mojom::ChannelRegistry::ConnectToChannelCallback callback, int result) {
  std::move(callback).Run(common::mojom::ChannelStatusCode::kCHANNEL_STATUS_OK);
}

void OnChannelInserted(common::mojom::ChannelRegistry::ConnectToChannelCallback callback, int result) {
  if (HostThread::CurrentlyOn(HostThread::IO)) {
    ReplyChannelCreated(std::move(callback), result);
  } else {
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE, 
      base::BindOnce(&ReplyChannelCreated, 
        base::Passed(std::move(callback)), 
        result));
  }
}

}

ChannelManager::ChannelManager(): 
  shutdown_event_(base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED),
  weak_factory_(this) {
  
}

ChannelManager::~ChannelManager() {

}

void ChannelManager::AddBinding(common::mojom::ChannelRegistryAssociatedRequest request) {
  channel_registry_binding_.AddBinding(this, std::move(request));
}

void ChannelManager::Init(scoped_refptr<ShareDatabase> db, DatabasePolicy policy) {
  channels_ = std::make_unique<ChannelModel>(db, policy);
  InitImpl();
}

void ChannelManager::Shutdown() {
  channels_.reset();
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ChannelManager::ShutdownImpl, 
      base::Unretained(this)));
  shutdown_event_.Wait();
}

void ChannelManager::InitImpl() {
  channels_->Load(base::Bind(&ChannelManager::OnLoad, base::Unretained(this)));
}

void ChannelManager::ShutdownImpl() {
  channel_registry_binding_.CloseAllBindings();
  shutdown_event_.Signal();
}

void ChannelManager::OnLoad(int r, int count) {
  NotifyChannelsLoad(r, count);
}

void ChannelManager::ConnectToChannel(
  const std::string& scheme,
  const std::string& name,
  common::mojom::ChannelClientAssociatedPtrInfo client,
  common::mojom::ChannelClientAssociatedRequest connection,
  ConnectToChannelCallback callback) {

  // HostThread::PostTask(
  //   HostThread::UI, 
  //   FROM_HERE, 
  //   base::BindOnce(&ChannelManager::ConnectToChannelImpl, 
  //     base::Unretained(this),
  //     scheme,
  //     name,
  //     base::Passed(std::move(client)), 
  //     base::Passed(std::move(connection)),
  //     base::Passed(std::move(callback))));
  ConnectToChannelImpl(
    scheme,
    name,
    std::move(client), 
    std::move(connection),
    std::move(callback));
}

void ChannelManager::ConnectToChannelImpl(
  const std::string& scheme,
  const std::string& name,
  common::mojom::ChannelClientAssociatedPtrInfo client,
  common::mojom::ChannelClientAssociatedRequest connection,
  ConnectToChannelCallback callback) {
  //DLOG(INFO) << "ChannelManager::ConnectToChannelImpl: " << scheme << ":" << name;
  base::UUID id = base::UUID::generate();
  std::unique_ptr<ChannelClient> channel_client = std::make_unique<ChannelClient>(this, id, scheme, name, std::move(client), std::move(connection));

  Channel* channel = channels_->GetChannel(scheme, name);
  if (!channel) {
    //DLOG(INFO) << "ChannelManager::ConnectToChannelImpl: new channel. creating";
    protocol::Channel channel_proto;
    channel_proto.set_uuid(id.to_string());
    channel_proto.set_scheme(scheme);
    channel_proto.set_name(name);

    std::unique_ptr<Channel> channel = std::make_unique<Channel>(std::move(channel_proto));
    channel->AddClient(std::move(channel_client));

    HostThread::PostTask(
      HostThread::UI, 
      FROM_HERE, 
      base::BindOnce(&ChannelManager::InsertChannelOnUI, 
        base::Unretained(this), 
        base::Passed(std::move(id)), 
        base::Passed(std::move(channel)),
        base::Passed(std::move(callback))));

    return;
  }
  //DLOG(INFO) << "ChannelManager::ConnectToChannelImpl: already exists. just adding";
  channel->AddClient(std::move(channel_client));
  OnChannelInserted(std::move(callback), net::OK);
}

void ChannelManager::InsertChannelOnUI(base::UUID id, std::unique_ptr<Channel> channel, ConnectToChannelCallback callback) {
  channels_->InsertChannel(
      id, 
      std::move(channel),
      true, 
      base::Bind(&OnChannelInserted, 
        base::Passed(std::move(callback))));
}

void ChannelManager::InsertChannel(std::unique_ptr<Channel> channel, bool persist) {
  Channel* reference = channel.get();
  channels_->InsertChannel(channel->id(), std::move(channel), persist);
  NotifyChannelAdded(reference);
}

void ChannelManager::RemoveChannel(Channel* channel) {
  NotifyChannelRemoved(channel);
  channels_->RemoveChannel(channel);
}

void ChannelManager::RemoveChannel(const base::UUID& uuid) {
  Channel* channel = channels_->GetChannelById(uuid);
  if (channel) {
    NotifyChannelRemoved(channel);
    channels_->RemoveChannel(channel);
  }
}

void ChannelManager::AddObserver(ChannelManagerObserver* observer) {
  observers_.push_back(observer);
}

void ChannelManager::RemoveObserver(ChannelManagerObserver* observer) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    if (observer == *it) {
      observers_.erase(it);
      return;
    }
  }
}

void ChannelManager::NotifyChannelAdded(Channel* channel) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    ChannelManagerObserver* observer = *it;
    observer->OnChannelAdded(channel);
  }
}

void ChannelManager::NotifyChannelRemoved(Channel* channel) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    ChannelManagerObserver* observer = *it;
    observer->OnChannelRemoved(channel);
  }
}

void ChannelManager::NotifyChannelsLoad(int r, int count) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    ChannelManagerObserver* observer = *it;
    observer->OnChannelsLoad(r, count);
  }
}

void ChannelManager::RemoveChannel(const std::string& scheme, const std::string& name, RemoveChannelCallback callback) {

}

void ChannelManager::RemoveChannelByUUID(const std::string& uuid, RemoveChannelByUUIDCallback callback) {

}

void ChannelManager::ListChannels(ListChannelsCallback callback) {

}

void ChannelManager::LookupChannel(const std::string& scheme, const std::string& name, LookupChannelCallback callback) {

}

void ChannelManager::LookupChannelByUUID(const std::string& uuid, LookupChannelByUUIDCallback callback) {

}

void ChannelManager::HaveChannel(const std::string& scheme, const std::string& name, HaveChannelCallback callback) {
  bool have = channels_->ChannelExists(scheme, name);
  std::move(callback).Run(have);
}

void ChannelManager::HaveChannelByUUID(const std::string& uuid, HaveChannelByUUIDCallback callback) {
  bool ok = false;
  base::UUID id = base::UUID::from_string(uuid, &ok);
  if (!ok) {
    std::move(callback).Run(false);
    return;
  }
  bool have = channels_->ChannelExists(id);
  std::move(callback).Run(have);
}

void ChannelManager::GetChannelCount(GetChannelCountCallback callback) {
  int count = channels_->Count();
  std::move(callback).Run(count);
}

void ChannelManager::AddRemoteObserver(
  const std::string& scheme,
  const std::string& name,
  common::mojom::ChannelObserverAssociatedPtrInfo observer) {

}

void ChannelManager::RemoveRemoteObserver(const std::string& scheme, const std::string& name) {

}

void ChannelManager::ReceivedMessageOnChannel(ChannelClient* client, common::CloneableMessage message) {
  const std::vector<std::unique_ptr<Channel>>& chans = channels_->channels();
  for (auto it = chans.begin(); it != chans.end(); ++it) {
    Channel* channel = it->get();
    if (channel->scheme() == client->scheme()) {
      for (size_t i = 0; i < channel->client_count(); ++i) {
        channel->GetClient(i)->MessageToClient(message);
      }
    }
  }
}

}