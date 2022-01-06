// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_CHANNEL_CHANNEL_CLIENT_H_
#define MUMBA_HOST_CHANNEL_CHANNEL_CLIENT_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"
#include "core/shared/common/mojom/channel.mojom.h"
#include "mojo/public/cpp/bindings/binding_set.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "mojo/public/cpp/bindings/interface_ptr_set.h"
#include "mojo/public/cpp/bindings/strong_binding.h"

namespace host {
class ChannelManager;
class ChannelClient : public common::mojom::ChannelClient {
public:
  ChannelClient(ChannelManager* manager, 
                const base::UUID& id, 
                const std::string& scheme,
                const std::string& name,
                common::mojom::ChannelClientAssociatedPtrInfo client,
                common::mojom::ChannelClientAssociatedRequest connection);
  ~ChannelClient() override;

  const base::UUID& id() const {
    return id_;
  }

  const std::string& scheme() const {
    return scheme_;
  }
  
  const std::string& name() const {
    return name_;
  }

  void OnMessage(common::CloneableMessage message) override;

  void MessageToClient(const common::CloneableMessage& message) const;
    
private:
  ChannelManager* manager_;
  base::UUID id_;
  std::string scheme_;
  std::string name_;
  mojo::AssociatedBinding<common::mojom::ChannelClient> binding_;
  common::mojom::ChannelClientAssociatedPtr client_;

  DISALLOW_COPY_AND_ASSIGN(ChannelClient);
};

}

#endif