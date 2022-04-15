// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_CHANNEL_CHANNEL_H_
#define MUMBA_HOST_CHANNEL_CHANNEL_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"
#include "base/containers/queue.h"
#include "base/strings/string_piece.h"
#include "base/synchronization/lock.h"
#include "base/containers/flat_map.h"
#include "core/host/serializable.h"
#include "core/common/proto/objects.pb.h"
#include "core/host/data/resource.h"
#include "core/host/channel/channel_client.h"
#include "core/shared/common/mojom/channel.mojom.h"

namespace host {
class ChannelClient;
class Channel : public Resource {
public:
  static char kClassName[];
  static std::unique_ptr<Channel> Deserialize(net::IOBuffer* buffer, int size);

  Channel(protocol::Channel channel_proto);
  ~Channel() override;

  const base::UUID& id() const override {
    return id_;
  }

  const std::string& scheme() const;

  const std::string& name() const override;

  bool is_managed() const override {
    return managed_;
  }

  void set_managed(bool managed) {
    managed_ = managed;
  }

  scoped_refptr<net::IOBufferWithSize> Serialize() const override;

  size_t client_count() const {
    return clients_.size();
  }

  void AddClient(std::unique_ptr<ChannelClient> client);
  ChannelClient* GetClient(size_t index) const;
  
private:

  base::UUID id_;
  protocol::Channel channel_proto_;
  
  bool managed_;

  std::vector<std::unique_ptr<ChannelClient>> clients_;
  
  DISALLOW_COPY_AND_ASSIGN(Channel);
};

}

#endif