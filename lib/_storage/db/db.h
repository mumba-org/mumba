// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_STORAGE_DB_DB_
#define MUMBA_STORAGE_DB_DB_

#include <memory>
#include <unordered_map>

#include "base/macros.h"
#include "base/uuid.h"
#include "base/files/file_path.h"
#include "base/strings/string_piece.h"
#include "base/memory/ref_counted.h"
#include "storage/db/memory.h"
#include "storage/proto/storage.pb.h"
#include "storage/storage_export.h"

typedef struct Btree Btree;
typedef struct BtCursor BtCursor;
typedef struct csqlite csqlite;
typedef struct KeyInfo KeyInfo;

namespace storage {

const int kMAX_TABLES = 1024;
// index of the main table
//const int kMAIN_TABLE = 0;

class Database;
class Arena;
class Torrent;

using KeyValuePair = std::pair<base::StringPiece, base::StringPiece>;

enum class Seek {
  EQ = 0,
  LT = 1,
  LE = 2,
  GT = 3,
  GE = 4,
};

enum class Order {
  ANY = 0,
  ASC = 1,
  DESC = 3
};

class STORAGE_EXPORT Transaction {
public:
  Transaction(Database* db, bool write);
  ~Transaction();

  bool write() const {
    return write_;
  }

  void Commit();
  void Rollback();

private:
  
  Database* db_;

  bool write_;

  DISALLOW_COPY_AND_ASSIGN(Transaction);
};

class STORAGE_EXPORT Cursor {
public:
  Cursor(Database* db,
         Transaction* transaction,
         const std::string& keyspace, 
         int table,
         Order order = Order::ASC);
  
  ~Cursor();

  Transaction* transaction() const {
    return transaction_;
  }

  Order order() const {
    return order_;
  }

  Arena* arena() const {
    return arena_.get();
  }

  const std::string& keyspace() const {
    return keyspace_;
  }

  bool IsValid() const;
  void SetValid(bool valid);
  bool IsEof() const;

  void First();
  void Last();
  void Previous();
  void Next();

  int64_t Count() const;

  int SeekTo(base::StringPiece key, Seek seek, bool* match, bool ignore_fragment_mode = false);
  //bool Update(base::StringPiece value);
  bool Get(base::StringPiece key, KeyValuePair* kv);
  bool GetValue(base::StringPiece key, base::StringPiece* data);
  bool HasValue(base::StringPiece key, bool* result);
  base::StringPiece GetPrefix(base::StringPiece key, int maxLength);
  base::StringPiece GetData();
  base::StringPiece GetDataPrefix(int max_encoded_size);
  bool Insert(const KeyValuePair& kv);
  bool InsertFragment(const KeyValuePair& kv, uint32_t index, int seek_result);
  bool Delete();

  int64_t IntKey() const;
  size_t DataSize() const;

private:

  Database* db_;
  Transaction* transaction_;
  BtCursor* handle_;
  KeyInfo* keyInfo_;

  HeapBufferAllocator allocator_;
  std::unique_ptr<Arena> arena_;
  bool valid_;
  int nfield_;
  std::string keyspace_;
  //bool match_equals_;
  Order order_;

  DISALLOW_COPY_AND_ASSIGN(Cursor);
};

class STORAGE_EXPORT Database {
public:
  static Database* Open(scoped_refptr<Torrent> torrent);
  static Database* Create(scoped_refptr<Torrent> torrent, const std::vector<std::string>& keyspaces);

  Database(
    const base::UUID& id,
    csqlite* sqlite, 
    Btree* btree,
    int table_count);
  
  ~Database();

  bool Init();
  bool CreateTables(const std::vector<std::string>& keyspaces);

  bool readonly() const {
    return readonly_;
  }

  bool is_closed() const {
    return closed_;
  }

  const base::UUID& id() const {
    return id_;
  }

  int table_count() const {
    return table_count_;
  }

  uint32_t largest_root_page() const {
    return largest_root_page_;
  }

  void Close();

  std::unique_ptr<Cursor> CreateCursor(Transaction* tr, const std::string& keyspace);
  std::unique_ptr<Transaction> BeginTransaction(bool write);

  bool Get(Transaction* tr, const std::string& keyspace, base::StringPiece key, std::string* value);
  bool Put(Transaction* tr, const std::string& keyspace, base::StringPiece key, base::StringPiece value);
  bool Delete(Transaction* tr, const std::string& keyspace, base::StringPiece key);
  
  bool EraseAll(Transaction* tr);
  bool Check();

  int Count(Transaction* tr, const std::string& keyspace);

  bool Checkpoint(int* result_code);

private:
  friend class Transaction;
  friend class Cursor;
  
  bool ExecuteStatement(const std::string& stmt);

  bool GetIndex(const std::string& keyspace, int* index);
  
  csqlite* sqlite_;
  Btree* btree_;
  base::UUID id_;
  int table_count_;
  bool readonly_;
  bool fragment_values_;
  int tables_[kMAX_TABLES];
  std::unordered_map<std::string, int> keyspaces_;
  uint32_t largest_root_page_;
  bool closed_;
 
  DISALLOW_COPY_AND_ASSIGN(Database);
};

void STORAGE_EXPORT DbInit();
void STORAGE_EXPORT DbShutdown();

//std::unique_ptr<Database> Database::Open(const base::FilePath& path, size_t tables, bool readonly);
//std::unique_ptr<Database> Database::Create(const base::FilePath& path, size_t tables);

KeyValuePair STORAGE_EXPORT DbDecodeKV(base::StringPiece encoded, bool* valid);

}

#endif