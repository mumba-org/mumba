// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/cmd/commands.h"

#include "base/uuid.h"
#include "base/command_line.h"
#include "base/command_line.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/files/file_enumerator.h"
#include "base/strings/string_number_conversions.h"
#include "base/command_line.h"
#include "base/at_exit.h"
#include "base/run_loop.h"
#include "base/message_loop/message_loop.h"
#include "base/task_scheduler/task_scheduler.h"
#include "base/task_scheduler/post_task.h"
#include "storage/storage_file.h"
#include "storage/proto/storage.pb.h"
#include "storage/storage.h"
#include "storage/storage_manager.h"
#include "storage/storage_utils.h"
#include "storage/db/db.h"
//#include "storage/catalog.h"
#include "storage/torrent.h"
#include "storage/db/db.h"
#include "storage/db/sqliteInt.h"
//#include "storage/data_catalog.h"
#include "storage/backend/addr.h"
#include "storage/backend/storage_format.h"
#include "components/base32/base32.h"
#include "third_party/protobuf/src/google/protobuf/text_format.h"

namespace storage {

namespace {

enum Opcode {
  kNONE = 0,
  kCREATE = 1,
  kOPEN = 2,
  kGET = 3,
  kPUT = 4,
  kLIST = 5,
  kDELETE = 6,
  kCREATEKEYSPACE = 7,
  kDELETEKEYSPACE = 8,
  kLISTKEYSPACE = 9
};

void CreateKeyspaceOnMain(scoped_refptr<Torrent> t, const std::string& keyspace) {
  bool ok = t->db().CreateKeyspace(keyspace);
  if (ok) {
    printf("create keyspace ok.\n");
  } else {
    printf("create keyspace failed.\n");
  }
}

void DropKeyspaceOnMain(scoped_refptr<Torrent> t, const std::string& keyspace) {
  bool ok = t->db().DropKeyspace(keyspace);
  if (ok) {
    printf("delete keyspace for ok.\n");
  } else {
    printf("delete keyspace failed.\n");
  }
}

void OnDatabaseCreated(base::Closure quit, const std::string& db_name, int64_t result) {
  if (result == 0) {
    printf("db created ok.\n");
    //Catalog* catalog = disk->GetCatalog(db_name);
    //printf("closing catalog.\n");
    //catalog->Close();
    //printf("catalog closed.\n");
  } else {
    printf("failed create db. code %ld\n", result);
  }
  base::PostDelayedTask(FROM_HERE, quit, base::TimeDelta::FromMilliseconds(2000));
  //std::move(quit).Run();
}

void OnDatabaseOpen(base::Closure quit, StorageManager* manager, scoped_refptr<base::SingleThreadTaskRunner> task_runner, const std::string& disk_name, const std::string& db_name, Opcode op, std::string keyspace, std::string key, std::string value, int64_t result) {
  if (result == 0) {
    //printf("db opened ok.\n");
    scoped_refptr<Torrent> t = manager->GetTorrent(disk_name, db_name);
    if (op == kPUT) {
      Transaction* tr = t->db().Begin(true);
      bool ok = t->db().Put(tr, keyspace, key, value);
      if (ok) {
        printf("db: %s\ninsert for '%s:%s' ok.\n", db_name.c_str(), keyspace.c_str(), key.c_str());
      } else {
        printf("db: %s\ninsert for '%s:%s' failed.\n", db_name.c_str(), keyspace.c_str(), key.c_str());
      }
      ok ? tr->Commit() : tr->Rollback();
    } else if (op == kDELETE) {
      Transaction* tr = t->db().Begin(true);
      bool ok = t->db().Delete(tr, keyspace, key);
      if (ok) {
        printf("db: %s\ndelete for '%s:%s' ok.\n", db_name.c_str(), keyspace.c_str(), key.c_str());
      } else {
        printf("db: %s\ndelete for '%s:%s' failed.\n", db_name.c_str(), keyspace.c_str(), key.c_str());
      }
      ok ? tr->Commit() : tr->Rollback();
    } else if (op == kCREATEKEYSPACE) {
      task_runner->PostTask(FROM_HERE, base::BindOnce(&CreateKeyspaceOnMain, t, keyspace));
    } else if (op == kDELETEKEYSPACE) {
      task_runner->PostTask(FROM_HERE, base::BindOnce(&DropKeyspaceOnMain, t, keyspace));
    } else if (op == kLISTKEYSPACE) {
      std::vector<std::string> keyspaces;
      t->db().GetKeyspaceList(&keyspaces, true /* include_hidden*/);
      for (auto const& keyspace : keyspaces) {
        printf("%s\n", keyspace.c_str());
      }
      printf("total: %ld\n", keyspaces.size());
    } else if (op == kGET) {
      std::string val;
      bool result = false;
      Transaction* trans = t->db().Begin(false);
      if (trans) {
        base::StringPiece data;
        Cursor* cursor = trans->CreateCursor(keyspace);
        if (cursor->GetValue(key, &data)) {
          result = true;
          // copy here as the sqlite page will vanish after commit
          // and the StringPiece will point to nowhere
          val = data.as_string();
        }
        trans->Commit();
      }
      if (result) {
        printf("db: %s:%s\n%s => \"%s\"\n", db_name.c_str(), keyspace.c_str(), key.c_str(), val.c_str());
      } else {
        printf("db: %s\nget for '%s:%s' failed.\n", db_name.c_str(), keyspace.c_str(), key.c_str());
      }
    } else if (op == kLIST) {
      Transaction* tr = t->db().Begin(false);
      auto iterator = tr->CreateCursor(keyspace);
      if (!iterator) {
        printf("db: %s\nlist failed for %s.\n", db_name.c_str(), keyspace.c_str());
      } else {
        iterator->First();
        if (t->is_root()) {
          while (iterator->IsValid()) {
            storage_proto::Info info;
            base::StringPiece payload = iterator->GetData();
            bool valid = false;
            KeyValuePair kv = DbDecodeKV(payload, &valid);
            if (info.ParseFromArray(kv.second.data(), kv.second.size())) {
              std::string hash_str = base::HexEncode(info.root_hash().data(), info.root_hash().size());
              printf("#uuid: %s path: %s hash: %s size: %ld inodes: %d total pieces: %ld/%ld\n",
                kv.first.as_string().c_str(),
                info.path().c_str(),
                hash_str.c_str(),
                info.length(),
                info.inodes().size(),
                info.piece_count(),
                info.piece_length());
            } else {
              printf("error decoding protobuf payload\n'%s' : '%s'", kv.first.as_string().c_str(), kv.second.as_string().c_str());
            }
            iterator->Next();
          }
        } else {
          int64_t total = iterator->Count();
          printf("db: '%s' table: '%s'\n", db_name.c_str(), keyspace.c_str());
          while (iterator->IsValid()) {
            bool valid = false;
            KeyValuePair kv = DbDecodeKV(iterator->GetData(), &valid);
            if (valid) {
              std::string k = kv.first.as_string();
              std::string v = kv.second.as_string();
              if (keyspace == ".meta") {
                uint8_t const* buf = reinterpret_cast<uint8_t const*>(kv.second.begin());
                uint64_t n;
                csqliteGetVarint(buf, reinterpret_cast<u64*>(&n));
                printf("%s => %lu\n", k.c_str(), n);
              } else {
                printf("%s => \"%s\"\n", k.c_str(), v.c_str());
              }
            } else {
              printf("error decoding key-value payload\n");
            }
            iterator->Next();
          }
          printf("total: %ld\n", total);
        }
        tr->Commit();
      }
    }
  } else {
    printf("failed open db. code %ld\n", result);
  }
  
  //std::move(quit).Run();
  base::PostDelayedTask(FROM_HERE, quit, base::TimeDelta::FromMilliseconds(2000));
}

//void OnStorageInit(storage::Storage* disk, base::Closure quit, int64_t result) {
//  if (result == 0) {
//    printf("disk open ok. now creating db 'hello' ...");
//    std::string key = "hello";//base32::Base32Encode("hello", base32::Base32EncodePolicy::OMIT_PADDING);
//    disk->CreateDatabase(
//      key,
//      base::Bind(&OnDatabase::Created, base::Passed(std::move(quit))));
//  }
//}

}

const char kDatabase[] = "database";
const char kDatabase_HelpShort[] =
    "database: db tests.";
const char kDatabase_Help[] =
    R"(
        just a marker
)";

int RunDatabase(const std::vector<std::string>& args) {
  base::RunLoop run_loop;
  Opcode op = kNONE;
  std::string key = "donnie";
  std::string db_name;
  std::string keyspace;
  std::string value = "darko";
  bool error = false;

  base::FilePath current_dir("/home/fabiok/Storage");
  //base::FilePath current_dir;
  //if (!base::GetCurrentDirectory(&current_dir)) {
  //  printf("error db: failed to get the current directory\n");
  //  return 1;
  //}

  scoped_refptr<base::SingleThreadTaskRunner> task_runner = base::ThreadTaskRunnerHandle::Get();
  
  std::unique_ptr<StorageManager> manager = std::make_unique<StorageManager>(current_dir);
  manager->Init(base::Callback<void(int)>(), false);//true /* batch_mode */);
  //Storage* disk = manager->GetStorage("twitter");
  //if (!disk) {
  //  printf("error db: failed to open disk on '%s'\n", current_dir.value().c_str());
  //  return 1;
  //}

  if (args.size() > 0) {
    if (args[0] == "create" ) {
      if (args.size() < 2) {
        printf("error create db: not enough arguments. database create [db-name]\n");
        error = true;
        goto exit;
      } else {
        op = kCREATE;
        db_name = args[1];
        keyspace = ".global";
      }
    } else if (args[0] == "get" ) {
      if (args.size() < 3) {
        printf("error get db: not enough arguments. database get [db-name] [keyspace] [key]\n");
        error = true;
        goto exit;
      } else {
        op = kGET;
        db_name = args[1];
        if (args.size() == 4) { 
          keyspace = args[2];
          key = args[3];
        } else if (args.size() == 3) {
          keyspace = ".global";
          key = args[2];
        }
      }
    } else if (args[0] == "put" ) {
      if (args.size() < 4) {
        printf("error put db: not enough arguments. database put [db-name] [keyspace] [key] [value]\n");
        error = true;
        goto exit;
      } else {
        op = kPUT;
        db_name = args[1];
        if (args.size() == 5) { 
          keyspace = args[2];
          key = args[3];
          value = args[4];
        } else if (args.size() == 4) {
          keyspace = ".global";
          key = args[2];
          value = args[3];
        }
        
      }
    } else if (args[0] == "list" ) {
      if (args.size() < 2) {
        printf("error list db: not enough arguments. database list [db-name] [keyspace]\n");
        error = true;
        goto exit;
      } else {
        op = kLIST;
        db_name = args[1];
        if (args.size() == 3) { 
          keyspace = args[2];
        } else if (args.size() == 2) {
          keyspace = ".global";
        }
      }
    }
    else if (args[0] == "keyspace-create" ) {
      if (args.size() < 3) {
        printf("error keyspace create: not enough arguments. database keyspace-create [db-name] [keyspace]\n");
        error = true;
        goto exit;
      } else {
        op = kCREATEKEYSPACE;
        db_name = args[1];
        keyspace = args[2];
      }
    }
    else if (args[0] == "keyspace-delete" ) {
      if (args.size() < 3) {
        printf("error keyspace delete: not enough arguments. database keyspace-delete [db-name] [keyspace]\n");
        error = true;
        goto exit;
      } else {
        op = kDELETEKEYSPACE;
        db_name = args[1];
        keyspace = args[2];
      }
    }
    else if (args[0] == "keyspace-list" ) {
      if (args.size() < 2) {
        printf("error keyspace list: not enough arguments. database keyspace-list [db-name]\n");
        error = true;
        goto exit;
      } else {
        op = kLISTKEYSPACE;
        db_name = args[1];
      }
    }
    else if (args[0] == "open" ) {
      if (args.size() < 2) {
        printf("error open db: not enough arguments. database open [db-name]\n");
        error = true;
        goto exit;
      } else {
        op = kOPEN;
        db_name = args[1];
      }
    } else if (args[0] == "delete" ) {
      if (args.size() < 3) {
        printf("error list db: not enough arguments. database delete [db-name] [keyspace] [key]\n");
        error = true;
        goto exit;
      } else {
        op = kDELETE;
        db_name = args[1];
        if (args.size() == 4) { 
          keyspace = args[2];
          key = args[3];
        } else if (args.size() == 3) {
          keyspace = ".global";
          key = args[2];
        }        
      }
    }
  }
 
  if (op == kCREATE) {
    std::vector<std::string> keyspaces;
    keyspaces.push_back(keyspace);
    manager->CreateTorrent(
      "twitter",
      storage_proto::INFO_KVDB,
      db_name,
      std::move(keyspaces),
      base::Bind(&OnDatabaseCreated, base::Passed(run_loop.QuitClosure()), db_name));
  } else {
    manager->OpenDatabase(
        "twitter",
        db_name,
        base::Bind(&OnDatabaseOpen, base::Passed(run_loop.QuitClosure()), base::Unretained(manager.get()), task_runner, "twitter", db_name, op, base::Passed(std::move(keyspace)), base::Passed(std::move(key)), base::Passed(std::move(value))));
  }
  
  run_loop.Run();

exit:
  //printf("out of loop. calling stop\n");
  manager->Shutdown();
  
  return 0;
}

}