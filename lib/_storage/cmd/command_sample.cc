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
#include "net/base/mime_util.h"
#include "storage/proto/storage.pb.h"
#include "libtorrent/socket.hpp"
#include "libtorrent/hex.hpp"
#include "libtorrent/sha1_hash.hpp"
#include "libtorrent/udp_socket.hpp"
#include "libtorrent/socket_io.hpp"
#include "libtorrent/aux_/socket_type.hpp"
#include "libtorrent/kademlia/ed25519.hpp"
#include "libtorrent/aux_/session_udp_sockets.hpp"
#include "third_party/boringssl/src/include/openssl/mem.h"
#include "third_party/boringssl/src/include/openssl/sha.h"
#include "components/base32/base32.h"

namespace storage {

namespace {

std::tuple<libtorrent::dht::public_key, libtorrent::dht::secret_key> keys;


std::string GenerateStorageSample() {
  std::string encoded_data;
  std::string content_type;
  char zero_hash[SHA_DIGEST_LENGTH] = {0};
    
  storage_proto::EntryHeaderBlock header;
  header.set_entry_count(1);
  header.set_next(zero_hash);
  
  // for now, just one entry
  storage_proto::Info* entry_header = header.add_entries();

  base::Time creation_time = base::Time::Now();
  std::string name = "bowie";
  std::string description("The Bowie Collection");

  //std::string entry_id = base32::Base32Encode(name, base32::Base32EncodePolicy::OMIT_PADDING);

  entry_header->set_path(name);
  entry_header->set_root_hash("123143235346");
  entry_header->set_piece_length(65586);
  entry_header->set_piece_count(256);
  entry_header->set_length(16864);
  entry_header->set_hash_header_length(0);
  entry_header->set_hash_content_length(0);
  //entry_header->set_file_count(1);
  entry_header->set_comment(description);
  entry_header->set_creation_date(creation_time.ToInternalValue());
  entry_header->set_mtime(creation_time.ToInternalValue());
  
  // a blob sample
  // add it
  auto* blob = entry_header->add_inodes();

  //std::string blob_id = base32::Base32Encode("david_bowie", base32::Base32EncodePolicy::OMIT_PADDING);
  
  net::GetMimeTypeFromFile(base::FilePath("david_bowie.mp3"), &content_type);

  //blob->set_id(blob_id);
  blob->set_parent(name);
  blob->set_name("david_bowie.mp3");
  blob->set_path("david_bowie.mp3");
  blob->set_length(16384);
  blob->set_offset(1);
  blob->set_root_hash("1234434536456467");
  blob->set_piece_count(256);
  blob->set_piece_start(1);
  blob->set_piece_end(256);
  blob->set_content_type(content_type);
  blob->set_creation_date(0);
  blob->set_mtime(0);

  header.SerializeToString(&encoded_data);

  return encoded_data;
}

std::string GenerateSha1Hash(const std::string& data) {
  SHA_CTX sha1_ctx;
  char hash[SHA_DIGEST_LENGTH] = {0};
  SHA1_Init(&sha1_ctx);
  SHA1_Update(&sha1_ctx, reinterpret_cast<const unsigned char*>(data.data()), data.size());
  SHA1_Final(reinterpret_cast<uint8_t*>(&hash[0]), &sha1_ctx);
  OPENSSL_cleanse(&sha1_ctx, sizeof(sha1_ctx));
  return std::string(hash, SHA_DIGEST_LENGTH);
}

//void GetMutableItem(StorageManager* manager) {
//  printf("GetMutableItem: ok tentando pegar %s\n", base::HexEncode(std::get<0>(keys).bytes.data(), 32).c_str());
//  manager->dht()->GetMutableItem(std::get<0>(keys).bytes);
//}
void OnWriteDHTEntry(StorageManager* manager,
                     libtorrent::dht::item const& item, 
                     int num) {
  DLOG(INFO) << "OnWriteDHTEntry";
}

void OnPutMutableItem(
  StorageManager* manager,
  std::string disk_sample,
  libtorrent::entry& entry, 
  std::array<char, 64>& signature, 
  std::int64_t& seq, 
  std::string const& salt) {

  using libtorrent::dht::sign_mutable_item;

  std::string hash = GenerateSha1Hash(disk_sample);

	entry["disk"] = base::HexEncode(hash.data(), hash.size());

  printf("resulting hash: %s\n", base::HexEncode(hash.data(), hash.size()).c_str());

	std::vector<char> buf;
	libtorrent::bencode(std::back_inserter(buf), entry);
	libtorrent::dht::signature sign;
	++seq;
	sign = sign_mutable_item(buf, salt, libtorrent::dht::sequence_number(seq)
		, libtorrent::dht::public_key(std::get<0>(keys).bytes.data())
		, libtorrent::dht::secret_key(std::get<1>(keys).bytes.data()));
	signature = sign.bytes;
 
  printf("OnPutMutableItem: ok setando mensagem na entry. Bowie collection.\n");

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
  std::string disk_sample = GenerateStorageSample();  
  // generate public and private key
  std::array<char, 32> seed = libtorrent::dht::ed25519_create_seed();
  keys = libtorrent::dht::ed25519_create_keypair(seed);
  printf("chave gerada %s\n---\n%s\n---\n", base::HexEncode(std::get<0>(keys).bytes.data(), 32).c_str(), base::HexEncode(std::get<1>(keys).bytes.data(), 64).c_str());
  manager->torrent_manager()->PutMutableItem(
    std::get<0>(keys).bytes, 
    base::Bind(&OnPutMutableItem, 
               base::Unretained(manager),
               base::Passed(std::move(disk_sample))),
    base::Bind(&OnWriteDHTEntry, base::Unretained(manager)));
}

}

const char kSample[] = "sample";
const char kSample_HelpShort[] =
    "Sample: sample of a disk on DHT, for test.";
const char kSample_Help[] =
    R"(
        just a marker
)";

int RunSample(const std::vector<std::string>& args) {
  base::RunLoop run_loop;
  base::FilePath current_dir;
  if (!base::GetCurrentDirectory(&current_dir)) {
    printf("error sample: failed to get the current directory\n");
    return 1;
  }
  std::unique_ptr<StorageManager> manager = std::make_unique<StorageManager>(current_dir); 
  manager->Init(base::Bind(&OnDHTBootstrap, base::Unretained(manager.get()), run_loop.QuitClosure()), false);
  run_loop.Run();
  manager->Shutdown();
  
  return 0;
}



}