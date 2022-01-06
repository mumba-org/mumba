// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_SHARE_SHARE_CACHE_H_
#define MUMBA_HOST_SHARE_SHARE_CACHE_H_

#include <string>

#include "base/macros.h"
#include "base/uuid.h"
#include "core/common/proto/objects.pb.h"
#include "core/host/serializable.h"
#include "storage/torrent.h"
#include "storage/torrent_observer.h"
#include "core/host/share/share_observer.h"
#include "core/host/share/share_database.h"

namespace host {

/*
 * The idea behind share cache is very simple, it will wrap a Storage
 * and work as a unit of storage for files and databases
 *
 * To make this work we will need to change the manager and registry api
 * to support cache as a parameter to share
 *
 * So that for every share we define a cache.. or maybe even
 * the ipc interface might allow us to manipulate the caches
 * and manage the shares from it, instead of directly in the manager
 *
 * Of course using the cache as a parameter in the manager will always be possible
 *
 * The manager will have a model to have a index/heap version of all shares, 
 * but to manage the data on the storagewe will need to point the cache
 * 
 * In this way we will be able to managem them in a modular manner
 * where every share have a parent cache
 */

class ShareCache {
public:
  ShareCache();
  ~ShareCache();

private:

  DISALLOW_COPY_AND_ASSIGN(ShareCache);
};

}

#endif
