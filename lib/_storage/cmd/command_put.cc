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
#include "libtorrent/kademlia/ed25519.hpp"
#include "libtorrent/aux_/session_udp_sockets.hpp"

namespace storage {
namespace {

std::tuple<libtorrent::dht::public_key, libtorrent::dht::secret_key> keys;

//void GetMutableItem(StorageManager* manager) {
//  printf("GetMutableItem: ok tentando pegar %s\n", base::HexEncode(std::get<0>(keys).bytes.data(), 32).c_str());
//  manager->dht()->GetMutableItem(std::get<0>(keys).bytes);
//}

void OnWriteDHTEntry(StorageManager* manager,
                     libtorrent::dht::item const& item, 
                     int num) {
  DLOG(INFO) << "OnWriteDHTEntry";
}

void OnPutMutableItem(StorageManager* manager, 
  libtorrent::entry& entry, 
  std::array<char, 64>& signature, 
  std::int64_t& seq, 
  std::string const& salt) {

  using libtorrent::dht::sign_mutable_item;

	entry = std::string("hello world");
	std::vector<char> buf;
	libtorrent::bencode(std::back_inserter(buf), entry);
	libtorrent::dht::signature sign;
	++seq;
	sign = sign_mutable_item(buf, salt, libtorrent::dht::sequence_number(seq)
		, libtorrent::dht::public_key(std::get<0>(keys).bytes.data())
		, libtorrent::dht::secret_key(std::get<1>(keys).bytes.data()));
	signature = sign.bytes;

  printf("OnPutMutableItem: ok setando mensagem na entry. 'hello world'.\n");

  //printf("OnPutMutableItem: setando entry para 'hello world'.\n '%s'\ndaqui a 1 segundo tentar pegar de novo..\n", entry.to_string().c_str());
  //base::PostDelayedTask(
  //  FROM_HERE,
  //  base::Bind(&GetMutableItem, base::Unretained(manager)),
  //  base::TimeDelta::FromMilliseconds(1000 * 1));
}

void OnDHTBootstrap(StorageManager* manager, base::Closure quit, int result) {
  std::printf("bootstrap done. %s\n", (result == 0 ? "ok": "failed"));
  if (result != 0) {
    quit.Run();
    return;
  }
  printf("put init: dht pronta, dando o comando put..\n");
    
  // generate public and private key
  std::array<char, 32> seed = libtorrent::dht::ed25519_create_seed();
  keys = libtorrent::dht::ed25519_create_keypair(seed);
  printf("chave gerada %s\n", base::HexEncode(std::get<0>(keys).bytes.data(), 32).c_str());
  manager->torrent_manager()->PutMutableItem(std::get<0>(keys).bytes, 
                                 base::Bind(&OnPutMutableItem, base::Unretained(manager)),
                                 base::Bind(&OnWriteDHTEntry, base::Unretained(manager)));
}

}

const char kPut[] = "put";
const char kPut_HelpShort[] =
    "put: put an item into the DHT.";
const char kPut_Help[] =
    R"(
        just a marker
)";

int RunPut(const std::vector<std::string>& args) {
  base::RunLoop run_loop;
  base::FilePath current_dir;
  if (!base::GetCurrentDirectory(&current_dir)) {
    printf("error manager: failed to get the current directory\n");
    return 1;
  }
  std::unique_ptr<StorageManager> manager = std::make_unique<StorageManager>(current_dir); 
  manager->Init(base::Bind(&OnDHTBootstrap, base::Unretained(manager.get()), run_loop.QuitClosure()), false);
  run_loop.Run();
  manager->Shutdown();
  
  return 0;
}



}