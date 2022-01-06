// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/cmd/commands.h"

#include "base/command_line.h"
#include "base/callback.h"
#include "base/bind.h"
#include "base/task_scheduler/post_task.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/strings/string_piece.h"
#include "base/memory/ref_counted.h"
#include "base/strings/string_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/run_loop.h"
#include "storage/storage_manager.h"
#include "storage/torrent_manager.h"
#include "net/base/net_errors.h"
#include "libtorrent/socket.hpp"
#include "libtorrent/hex.hpp"
#include "libtorrent/sha1_hash.hpp"
#include "libtorrent/udp_socket.hpp"
#include "libtorrent/socket_io.hpp"
#include "libtorrent/aux_/socket_type.hpp"
#include "libtorrent/aux_/session_udp_sockets.hpp"

namespace storage {

namespace {

const char kBOOTSTRAP_DHT_ADDRESS1[] = "82.221.103.244"; // router.utorrent.com
const char kBOOTSTRAP_DHT_ADDRESS2[] = "67.215.246.10"; // router.bittorrent.com
const int  kBOOTSTRAP_DHT_PORT1 = 6881;
const int  kBOOTSTRAP_DHT_PORT2 = 6881;

std::string sha1_hex = "ec185f258a41604dcc6d288de58e6cee874560c4"; // John Wick Chapter 3 - Parabellum

//void GetMovie(MakunaSession* manager) {
//  printf("getting %s...\n", sha1_hex.c_str());
//  manager->dht()->GetImmutableItemSha1Hex(sha1_hex);
//}

std::vector<libtorrent::tcp::endpoint> peer_list;
base::Lock peer_list_lock;

void OnGetPeers(std::vector<libtorrent::tcp::endpoint> peers) {
  printf("total peers for %s => %zu\n", sha1_hex.c_str(), peers.size());
  peer_list_lock.Acquire();
  for (auto it = peers.begin(); it != peers.end(); it++) {
    peer_list.push_back(*it);
  }
  peer_list_lock.Release();
}

void GetPeers(StorageManager* manager) {
  char hash_data[20] = {0};
  libtorrent::aux::from_hex({sha1_hex.data(), sha1_hex.size()}, hash_data);
  libtorrent::sha1_hash item = libtorrent::sha1_hash(hash_data);
  printf("getting peers for %s...\n", sha1_hex.c_str());
  manager->torrent_manager()->GetPeers(item, base::Bind(&OnGetPeers)); 
}

void ListPeers() {
  peer_list_lock.Acquire();
  for (auto it = peer_list.begin(); it != peer_list.end(); it++) {
    printf("%s %d\n", it->address().to_string().c_str(), it->port());
  }
  peer_list_lock.Release();
}

void OnSessionInit(StorageManager* manager, base::Closure quit, int result) {
  //manager->Update(base::Callback<void(int)>());
  //quit.Run(
  base::PostDelayedTask(
    FROM_HERE,
    base::Bind(&GetPeers, base::Unretained(manager)),
    base::TimeDelta::FromMilliseconds(1000 * 4));
}

} // namespace

const char kSession[] = "session";
const char kSession_HelpShort[] =
    "session: run a torrent session.";
const char kSession_Help[] =
    R"(
        just a marker
)";

int RunSession(const std::vector<std::string>& args) {
  base::RunLoop run_loop;
  base::FilePath current_dir;
  if (!base::GetCurrentDirectory(&current_dir)) {
    printf("error manager: failed to get the current directory\n");
    return 1;
  }
  std::unique_ptr<StorageManager> manager = std::make_unique<StorageManager>(current_dir); 

  net::IPAddress address1;
  if (!address1.AssignFromIPLiteral(kBOOTSTRAP_DHT_ADDRESS1)) {
    LOG(ERROR) << "bad bootstrap address " << kBOOTSTRAP_DHT_ADDRESS1;
    return 1;
  }

  net::IPAddress address2;
  if (!address2.AssignFromIPLiteral(kBOOTSTRAP_DHT_ADDRESS2)) {
    LOG(ERROR) << "bad bootstrap address " << kBOOTSTRAP_DHT_ADDRESS2;
    return 1;
  }
  
  manager->AddBootstrapNode(net::IPEndPoint(address1, kBOOTSTRAP_DHT_PORT1));
  manager->AddBootstrapNode(net::IPEndPoint(address2, kBOOTSTRAP_DHT_PORT2));
  manager->Init(base::Bind(&OnSessionInit, manager.get(), run_loop.QuitClosure()), false);

  base::PostDelayedTask(
    FROM_HERE,
    base::Bind(&ListPeers),
    base::TimeDelta::FromMilliseconds(1000 * 30));
  
  run_loop.Run();
  
  return 0;
}

}