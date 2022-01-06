#include <cstdio> // for snprintf
#include <cinttypes> // for PRId64 et.al.

#include "base/strings/string_number_conversions.h"

#include "libtorrent/entry.hpp"
#include "libtorrent/bencode.hpp"
#include "libtorrent/torrent_info.hpp"
#include "libtorrent/announce_entry.hpp"
#include "libtorrent/bdecode.hpp"
#include "libtorrent/magnet_uri.hpp"

#include <fstream>
#include <iostream>

#include "storage/cmd/commands.h"

#include "base/command_line.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/files/file_enumerator.h"
#include "base/command_line.h"
#include "base/at_exit.h"
#include "base/run_loop.h"
#include "base/message_loop/message_loop.h"
#include "base/task_scheduler/task_scheduler.h"
#include "storage/storage_file.h"
#include "storage/proto/storage.pb.h"
#include "storage/storage.h"
#include "storage/storage_manager.h"
#include "storage/storage_utils.h"
#include "storage/db/db.h"
#include "storage/backend/addr.h"
#include "storage/backend/storage_format.h"
#include "storage/backend/block_files.h"

namespace storage {

namespace {

void OnGetBlobInfo(const std::string& key, base::Closure quit, storage_proto::Info info, int64_t result) {
  if (result == 0) {
    lt::torrent_info t;
    lt::error_code ec;
    if (!t.parse_protobuf(info, ec)) {
      printf("torrent: error decoding protobuf to torrent info\n");
      quit.Run();
      return;
    }

    // print info about torrent
    std::printf("\n\n----- torrent file info -----\n\n"
      "nodes:\n");
    for (auto const& i : t.nodes())
      std::printf("%s: %d\n", i.first.c_str(), i.second);

    puts("trackers:\n");
    for (auto const& i : t.trackers())
      std::printf("%2d: %s\n", i.tier, i.url.c_str());

    //printf("root hash = %s\n", base::HexEncode(t.merkle_tree()[0].data(), t.merkle_tree()[0].size()).c_str());


    std::stringstream ih;
    ih << t.info_hash();
    std::printf("number of pieces: %d\n"
      "piece length: %d\n"
      "info hash: %s\n"
      "comment: %s\n"
      "created by: %s\n"
      "magnet link: %s\n"
      "name: %s\n"
      "number of files: %d\n"
      "files:\n"
      , t.num_pieces()
      , t.piece_length()
      , ih.str().c_str()
      , t.comment().c_str()
      , t.creator().c_str()
      , make_magnet_uri(t).c_str()
      , t.name().c_str()
      , t.num_files());
    lt::file_storage const& st = t.files();
    for (auto const i : st.file_range())
    {
      auto const first = st.map_file(i, 0, 0).piece;
      auto const last = st.map_file(i, std::max(std::int64_t(st.file_size(i)) - 1, std::int64_t(0)), 0).piece;
      auto const flags = st.file_flags(i);
      std::stringstream file_hash;
      if (!st.hash(i).is_all_zeros())
        file_hash << st.hash(i);
      std::printf(" %8" PRIx64 " %11" PRId64 " %c%c%c%c [ %5d, %5d ] %7u %s %s %s%s\n"
        , st.file_offset(i)
        , st.file_size(i)
        , ((flags & lt::file_storage::flag_pad_file)?'p':'-')
        , ((flags & lt::file_storage::flag_executable)?'x':'-')
        , ((flags & lt::file_storage::flag_hidden)?'h':'-')
        , ((flags & lt::file_storage::flag_symlink)?'l':'-')
        , static_cast<int>(first)
        , static_cast<int>(last)
        , std::uint32_t(st.mtime(i))
        , file_hash.str().c_str()
        , st.file_path(i).c_str()
        , (flags & lt::file_storage::flag_symlink) ? "-> " : ""
        , (flags & lt::file_storage::flag_symlink) ? st.symlink(i).c_str() : "");
    }
    std::printf("web seeds:\n");
    for (auto const& ws : t.web_seeds())
    {
      std::printf("%s %s\n"
        , ws.type == lt::web_seed_entry::url_seed ? "BEP19" : "BEP17"
        , ws.url.c_str());
    }

  } else {
    printf("torrent: error getting blob info for '%s' : %ld\n", key.c_str(), result);
  }
  quit.Run();
}

}

const char kTorrent[] = "torrent";
const char kTorrent_HelpShort[] =
    "torrent: dump a torrent info from a entry.";
const char kTorrent_Help[] =
    R"(
        just a marker
)";

int RunTorrent(const std::vector<std::string>& args) {
  base::RunLoop run_loop;
  base::FilePath src_dir;
  std::string key;

  if (args.size() >= 2) {
    key = args[0];
    src_dir = base::FilePath(args[1]);
  } else if (args.size() == 1) {
    key = args[0];
    base::GetCurrentDirectory(&src_dir);
  } else {
    printf("error torrent: not enough arguments. requires 'key' of entry\n");
    return 1;
  }

  bool ok = false;
  base::UUID id = base::UUID::from_string(key, &ok);
  if (!ok) {
    printf("error db: failed to open db. '%s' not valid UUID\n", key.c_str());
    return 1;
  }
  
  std::unique_ptr<StorageManager> manager = std::make_unique<StorageManager>(src_dir);
  manager->Init(base::Callback<void(int)>());
  //Storage* disk = manager->GetStorage("twitter");
  //if (!disk) {
  //  printf("error torrent: failed to open disk '%s'\n", src_dir.value().c_str());
  //  return 1;
  //}
  manager->GetEntryInfo(
        "twitter",
        id, 
        base::Bind(&OnGetBlobInfo,
          key,
          base::Passed(run_loop.QuitClosure())));

  run_loop.Run();
  
  manager->Shutdown();
  
  return 0;
}

}