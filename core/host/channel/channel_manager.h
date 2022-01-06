// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_CHANNEL_CHANNEL_MANAGER_H_
#define MUMBA_HOST_CHANNEL_CHANNEL_MANAGER_H_

#include <memory>

#include "base/macros.h"
#include "base/synchronization/lock.h"
#include "base/memory/ref_counted.h"
#include "base/files/file_path.h"
#include "base/atomic_sequence_num.h"
#include "base/memory/weak_ptr.h"
#include "base/single_thread_task_runner.h"
#include "base/uuid.h"
#include "core/host/database_policy.h"
#include "core/shared/common/mojom/channel.mojom.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding_set.h"
#include "third_party/protobuf/src/google/protobuf/descriptor.h"
#include "core/host/channel/channel_manager_observer.h"

namespace host {
class ChannelModel;
class Channel;
class ChannelClient;
class ShareDatabase;

class ChannelManager : public common::mojom::ChannelRegistry {
public:
  ChannelManager();
  ~ChannelManager();

  void AddBinding(common::mojom::ChannelRegistryAssociatedRequest request);

  ChannelModel* channels() const {
    return channels_.get();
  }

  void Init(scoped_refptr<ShareDatabase> db, DatabasePolicy policy);
  void Shutdown();

  void InsertChannel(std::unique_ptr<Channel> channel, bool persist = true);
  void RemoveChannel(Channel* channel);
  void RemoveChannel(const base::UUID& uuid);

  void AddObserver(ChannelManagerObserver* observer);
  void RemoveObserver(ChannelManagerObserver* observer);

  // mojom::ChannelRegistry
  void ConnectToChannel(
    const std::string& scheme,
    const std::string& name,
    common::mojom::ChannelClientAssociatedPtrInfo client,
    common::mojom::ChannelClientAssociatedRequest connection,
    ConnectToChannelCallback callback) override;
  void RemoveChannel(const std::string& scheme, const std::string& name, RemoveChannelCallback callback) override;
  void RemoveChannelByUUID(const std::string& uuid, RemoveChannelByUUIDCallback callback) override;
  void ListChannels(ListChannelsCallback callback) override;
  void LookupChannel(const std::string& scheme,const std::string& name, LookupChannelCallback callback) override;
  void LookupChannelByUUID(const std::string& uuid, LookupChannelByUUIDCallback callback) override;
  void HaveChannel(const std::string& scheme,const std::string& name, HaveChannelCallback callback) override;
  void HaveChannelByUUID(const std::string& uuid, HaveChannelByUUIDCallback callback) override;
  void GetChannelCount(GetChannelCountCallback callback) override;
  void AddRemoteObserver(
    const std::string& scheme,
    const std::string& name,
    common::mojom::ChannelObserverAssociatedPtrInfo observer) override;
  void RemoveRemoteObserver(const std::string& scheme, const std::string& name) override;

  void ReceivedMessageOnChannel(ChannelClient* client, common::CloneableMessage message);

private:

  void InitImpl();
  void ShutdownImpl();

  void ConnectToChannelImpl(
    const std::string& scheme,
    const std::string& name,
    common::mojom::ChannelClientAssociatedPtrInfo client,
    common::mojom::ChannelClientAssociatedRequest connection,
    ConnectToChannelCallback callback);

  void InsertChannelOnUI(base::UUID id, std::unique_ptr<Channel> channel, ConnectToChannelCallback callback);

  void OnLoad(int r, int count);

  void NotifyChannelAdded(Channel* channel);
  void NotifyChannelRemoved(Channel* channel);
  void NotifyChannelsLoad(int r, int count);
  
  std::unique_ptr<ChannelModel> channels_;
  std::vector<ChannelManagerObserver*> observers_;
  mojo::AssociatedBindingSet<common::mojom::ChannelRegistry> channel_registry_binding_;
  base::WaitableEvent shutdown_event_;
  base::WeakPtrFactory<ChannelManager> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(ChannelManager);
};

}

#endif