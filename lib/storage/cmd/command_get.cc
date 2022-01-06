// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/cmd/commands.h"

#include <cstdio> // for snprintf
#include <cinttypes> // for PRId64 et.al

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
#include "storage/storage.h"
#include "storage/torrent_manager.h"
#include "storage/proto/storage.pb.h"
#include "net/base/net_errors.h"
#include "libtorrent/socket.hpp"
#include "libtorrent/hex.hpp"
#include "libtorrent/sha1_hash.hpp"
#include "libtorrent/udp_socket.hpp"
#include "libtorrent/socket_io.hpp"
#include "libtorrent/aux_/socket_type.hpp"
#include "libtorrent/aux_/session_udp_sockets.hpp"
#include "libtorrent/entry.hpp"
#include "libtorrent/bencode.hpp"
#include "libtorrent/torrent_info.hpp"
#include "libtorrent/announce_entry.hpp"
#include "libtorrent/bdecode.hpp"
#include "libtorrent/magnet_uri.hpp"
#include "third_party/protobuf/src/google/protobuf/text_format.h"

namespace storage {

namespace {

// void OnGetImmutableItem(StorageManager* manager, base::Closure quit, libtorrent::sha1_hash target, libtorrent::dht::item const& i) {
//   lt::torrent_info t;
//   lt::error_code ec;
//   auto sha1_hex = base::HexEncode(target.data(), 20);

//   printf("get: entry =>\n %s\n", i.value().to_string().c_str());

//   if (i.value().type() == lt::entry::undefined_t) {
//     LOG(ERROR) << "get: error invalid entry payload for " << sha1_hex;
//     return;
//   }

//   storage_proto::Info info;
//   if (!info.ParseFromString(i.value().string())) {
//     LOG(ERROR) << "get: error while decoding entry: " << sha1_hex;
//     return;
//   }

//   if (!t.parse_protobuf(info, ec)) {
//     printf("get: error decoding protobuf to torrent info\n");
//     quit.Run();
//     return;
//   }

//   // print info about torrent
//   std::printf("\n\n----- torrent file info -----\n\n"
//     "nodes:\n");
//   for (auto const& i : t.nodes())
//     std::printf("%s: %d\n", i.first.c_str(), i.second);

//   puts("trackers:\n");
//   for (auto const& i : t.trackers())
//     std::printf("%2d: %s\n", i.tier, i.url.c_str());

//   //printf("root hash = %s\n", base::HexEncode(t.merkle_tree()[0].data(), t.merkle_tree()[0].size()).c_str());


//   std::stringstream ih;
//   ih << t.info_hash();
//   std::printf("number of pieces: %d\n"
//     "piece length: %d\n"
//     "info hash: %s\n"
//     "comment: %s\n"
//     "created by: %s\n"
//     "magnet link: %s\n"
//     "name: %s\n"
//     "number of files: %d\n"
//     "files:\n"
//     , t.num_pieces()
//     , t.piece_length()
//     , ih.str().c_str()
//     , t.comment().c_str()
//     , t.creator().c_str()
//     , make_magnet_uri(t).c_str()
//     , t.name().c_str()
//     , t.num_files());
//   lt::file_storage const& st = t.files();
//   for (auto const i : st.file_range())
//   {
//     auto const first = st.map_file(i, 0, 0).piece;
//     auto const last = st.map_file(i, std::max(std::int64_t(st.file_size(i)) - 1, std::int64_t(0)), 0).piece;
//     auto const flags = st.file_flags(i);
//     std::stringstream file_hash;
//     if (!st.hash(i).is_all_zeros())
//       file_hash << st.hash(i);
//     std::printf(" %8" PRIx64 " %11" PRId64 " %c%c%c%c [ %5d, %5d ] %7u %s %s %s%s\n"
//       , st.file_offset(i)
//       , st.file_size(i)
//       , ((flags & lt::file_storage::flag_pad_file)?'p':'-')
//       , ((flags & lt::file_storage::flag_executable)?'x':'-')
//       , ((flags & lt::file_storage::flag_hidden)?'h':'-')
//       , ((flags & lt::file_storage::flag_symlink)?'l':'-')
//       , static_cast<int>(first)
//       , static_cast<int>(last)
//       , std::uint32_t(st.mtime(i))
//       , file_hash.str().c_str()
//       , st.file_path(i).c_str()
//       , (flags & lt::file_storage::flag_symlink) ? "-> " : ""
//       , (flags & lt::file_storage::flag_symlink) ? st.symlink(i).c_str() : "");
//   }
//   std::printf("web seeds:\n");
//   for (auto const& ws : t.web_seeds())
//   {
//     std::printf("%s %s\n"
//       , ws.type == lt::web_seed_entry::url_seed ? "BEP19" : "BEP17"
//       , ws.url.c_str());
//   }
//   std::move(quit).Run();
// }

// void OnGetMutableItem(StorageManager* manager, base::Closure quit, const libtorrent::entry& entry, const std::array<char, 32>& pk, const std::array<char, 64>& sig, const std::int64_t& seq, std::string const& salt, bool authoritative) {
//   auto pk_hex = base::HexEncode(pk.data(), 32);
//   //std::string res = entry.find_key("disk")->string();
//   if (entry.type() == lt::entry::undefined_t) {
//     LOG(ERROR) << "get: error invalid entry payload for " << pk_hex;
//     std::move(quit).Run();
//     return;
//   }

//   storage_proto::Info info;
//   if (!info.ParseFromString(entry.string())) {
//     LOG(ERROR) << "get: error while decoding entry: " << pk_hex << "\n" << entry.to_string();
//     std::move(quit).Run();
//     return;
//   }

//   //std::string info_str;
//   //google::protobuf::TextFormat::PrintToString(info, &info_str);
//   //printf("%s\n", info_str.c_str());

//   //printf("now trying to get immutable %s ...\n", base::HexEncode(info.root_hash().data(), 20).c_str());

//   //manager->dht()->GetImmutableItem(libtorrent::sha1_hash(info.root_hash()), base::Bind(&OnGetImmutableItem, base::Unretained(session), std::move(quit)));
  
//   auto* disk = manager->GetStorage("twitter");

//   libtorrent::error_code ec;
//   libtorrent::add_torrent_params params;
//   params.ti = std::make_shared<libtorrent::torrent_info>();
//   params.userdata = disk->backend();
//   params.torrent_delegate = session;

//   //D//LOG(INFO) << "get: userdata(StorageBackend): " << params.userdata;

//   params.save_path = disk->path().AppendASCII(info.name()).value();

//   if (!params.ti->parse_protobuf(info, ec)) {
//     LOG(ERROR) << "get: error while creating torrent info from protobuf info";
//     std::move(quit).Run();
//     return;
//   }

//   auto torrent_handle = manager->dht()->session()->add_torrent(std::move(params), ec);
//   if (ec.value() != 0) {
//     LOG(ERROR) << "StorageManager::OnWriteDHTEntry: error while adding torrent info to session: " << ec.message();
//     std::move(quit).Run();
//     return;
//   }

// }

void OnGetPeers(StorageManager* manager, base::Closure quit, std::vector<libtorrent::tcp::endpoint> endpoints) {
  std::string peers;
  for (auto it = endpoints.begin(); it != endpoints.end(); ++it) {
    const libtorrent::tcp::endpoint& ep = *it;
    peers += ep.address().to_string() + ":" + base::IntToString(ep.port()) + "\n";
  }
  printf("OnGetPeers: count = %d\n%s", int(endpoints.size()), peers.c_str());
  std::move(quit).Run();
}

void OnBootstrap(StorageManager* manager, base::Closure quit, std::string key, int result) {
  printf("bootstrap done. %s\n", (result == 0 ? "ok": "failed"));
  if (result != 0) {
    std::move(quit).Run();
    return;
  }
  printf("now trying to get %s ...\n", key.c_str());
  std::vector<uint8_t> data;
  DCHECK(base::HexStringToBytes(key, &data));
  //std::array<char, 32> pub_key;
  //memcpy(pub_key.data(), reinterpret_cast<char *>(data.data()), 32);
  //manager->session()->GetMutableItem(pub_key, base::Bind(&OnGetMutableItem, base::Unretained(session), std::move(quit)));
  libtorrent::sha1_hash hash;
  memcpy(hash.data(), reinterpret_cast<char *>(data.data()), 20);
  //manager->session()->GetImmutableItem(libtorrent::sha1_hash(*data.begin()), base::Bind(&OnGetImmutableItem, base::Unretained(session), std::move(quit)));
  manager->torrent_manager()->GetPeers(hash, base::Bind(&OnGetPeers, base::Unretained(manager), std::move(quit)));
}

}


const char kGet[] = "get";
const char kGet_HelpShort[] =
    "get: get an item from the DHT.";
const char kGet_Help[] =
    R"(
        just a marker
)";

int RunGet(const std::vector<std::string>& args) {
  base::RunLoop run_loop;
  base::FilePath current_dir;

  if (args.size() < 1) {
    printf("error: missing the key arg\n");
    return 1;
  }
  
  if (!base::GetCurrentDirectory(&current_dir)) {
    printf("error session: failed to get the current directory\n");
    return 1;
  }
  std::unique_ptr<StorageManager> manager = std::make_unique<StorageManager>(current_dir); 
  manager->Init(base::Bind(&OnBootstrap, base::Unretained(manager.get()), run_loop.QuitClosure(), args[0]), false);

  //manager->CreateStorage("skype");
 
  run_loop.Run();

  manager->Shutdown();
  manager.reset();
  
  return 0;
}

}