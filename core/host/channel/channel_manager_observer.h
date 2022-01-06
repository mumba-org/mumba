// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_CHANNEL_CHANNEL_MANAGER_OBSERVER_H_
#define MUMBA_HOST_CHANNEL_CHANNEL_MANAGER_OBSERVER_H_

namespace host {
class Channel;

class ChannelManagerObserver {
public:
  virtual ~ChannelManagerObserver(){}
  virtual void OnChannelsLoad(int r, int count) {}
  virtual void OnChannelAdded(Channel* channel) {}
  virtual void OnChannelRemoved(Channel* channel) {}
};

}

#endif