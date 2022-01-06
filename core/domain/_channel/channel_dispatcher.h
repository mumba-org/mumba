// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_CHANNEL_DISPATCHER_H_
#define MUMBA_DOMAIN_CHANNEL_DISPATCHER_H_

#include "base/macros.h"

#include "core/shared/common/mojom/objects.mojom.h"
#include "core/shared/common/mojom/channel.mojom.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"

namespace domain {

class ChannelDispatcher : public common::mojom::ChannelDispatcher {
public:
  ChannelDispatcher();
  ~ChannelDispatcher() override;

  void Bind(common::mojom::ChannelDispatcherAssociatedRequest request);

  void GetChannelInfo(const std::string& url, GetChannelInfoCallback cb) override;
  void ListChannels(ListChannelsCallback cb) override;
  void AddChannel(const std::string& url, common::mojom::ChannelHandlePtr node, AddChannelCallback cb) override;
  void RemoveChannel(const std::string& url, RemoveChannelCallback cb) override;
  void SubscribeChannel(const std::string& url, SubscribeChannelCallback cb) override;
  void UnsubscribeChannel(const std::string& url, UnsubscribeChannelCallback cb) override;
  
private:
  class Handler;

  void ReplyGetChannelInfo(GetChannelInfoCallback callback, common::mojom::ChannelHandlePtr info);
  void ReplyListChannels(ListChannelsCallback callback, std::vector<common::mojom::ChannelHandlePtr> info);
  void ReplyAddChannel(AddChannelCallback callback, bool result);
  void ReplyRemoveChannel(RemoveChannelCallback callback, bool result);
  void ReplySubscribeChannel(SubscribeChannelCallback callback, bool result);
  void ReplyUnsubscribeChannel(UnsubscribeChannelCallback callback, bool result);

  mojo::AssociatedBinding<common::mojom::ChannelDispatcher> binding_;

  scoped_refptr<Handler> handler_;

  base::WeakPtrFactory<ChannelDispatcher> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(ChannelDispatcher);
};

}

#endif