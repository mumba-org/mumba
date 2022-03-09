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
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-compare"
#pragma clang diagnostic ignored "-Wignored-qualifiers"
#include "third_party/zetasql/parser/parse_tree.h"
#include "third_party/zetasql/parser/ast_node_kind.h"
#include "third_party/zetasql/parser/parser.h"
#include "third_party/zetasql/public/parse_resume_location.h"
#include "third_party/zetasql/base/status.h"
#pragma clang diagnostic pop

typedef struct Btree Btree;
typedef struct BtCursor BtCursor;
typedef struct csqlite csqlite;
typedef struct csqlite_stmt csqlite_stmt;
typedef struct KeyInfo KeyInfo;

namespace storage {

const int kMAX_TABLES = 1024;
// index of the main table
//const int kMAIN_TABLE = 0;

class Database;
class Arena;
class Torrent;
class Cursor;

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
  class Delegate {
  public:
    virtual ~Delegate() {}
    virtual void OnTransactionCommit(Transaction* transaction) = 0;
    virtual void OnTransactionRollback(Transaction* transaction) = 0;
  };
  Transaction(Database* db, bool write);
  ~Transaction();

  Cursor* CreateCursor(const std::string& keyspace, Order order = Order::ASC);

  bool is_write() const {
    return is_write_;
  }

  bool is_pending() const {
    return is_pending_;
  }

  bool Commit();
  bool Rollback();

  void DatabaseIsClosing() {
    notification_enabled_ = false;    
  }

private:
  friend class Database;

  Cursor* CreateCursor(int table_value, Order order = Order::ASC);
  //Cursor* CreateCursor(const std::string& keyspace, int table_offset, int table_value);
  Cursor* CreateCursor(const std::string& keyspace, int table_value, Order order = Order::ASC);
  
  Database* db_;

  std::vector<std::unique_ptr<Cursor>> cursors_;

  bool is_write_;

  bool is_pending_;

  bool notification_enabled_;

  DISALLOW_COPY_AND_ASSIGN(Transaction);
};

class STORAGE_EXPORT Cursor {
public:
  // Cursor(Database* db,
  //        Transaction* transaction,
  //        const std::string& keyspace, 
  //        int table_offset,
  //        int table_value,
  //        Order order = Order::ASC);

  Cursor(Database* db,
         Transaction* transaction,
         const std::string& keyspace, 
         int table_value,
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

  bool First();
  bool Last();
  bool Previous();
  bool Next();

  int64_t Count() const;

  int SeekTo(base::StringPiece key, Seek seek, bool* match, bool ignore_fragment_mode = false);
  //bool Update(base::StringPiece value);
  bool Get(base::StringPiece key, KeyValuePair* kv);
  bool GetValue(base::StringPiece key, base::StringPiece* data);
  bool HasValue(base::StringPiece key, bool* result);
  base::StringPiece GetPrefix(base::StringPiece key, int maxLength);
  base::StringPiece GetData();
  bool GetKV(KeyValuePair* kv);
  KeyValuePair GetKV();
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

class STORAGE_EXPORT Database : public Transaction::Delegate {
public:
  static Database* Open(scoped_refptr<Torrent> torrent, bool key_value);
  static Database* Create(scoped_refptr<Torrent> torrent, const std::vector<std::string>& keyspaces, bool key_value);
  static Database* Create(scoped_refptr<Torrent> torrent, const std::vector<std::string>& create_statements, const std::vector<std::string>& insert_statements, bool key_value);
  static std::unique_ptr<Database> CreateMemory(const std::vector<std::string>& keyspaces, bool key_value);

  Database(
    const base::UUID& id,
    csqlite* sqlite, 
    Btree* btree);
  
  ~Database() override;

  bool Init(bool key_value);
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
    return keyspaces_.size();
  }

  uint32_t largest_root_page() const {
    return largest_root_page_;
  }

  void Close();
  
  Transaction* Begin(bool write);
  Transaction* BeginRead();
  Transaction* BeginWrite();

  bool Get(Transaction* tr, const std::string& keyspace, base::StringPiece key, std::string* value);
  bool Put(Transaction* tr, const std::string& keyspace, base::StringPiece key, base::StringPiece value);
  bool Delete(Transaction* tr, const std::string& keyspace, base::StringPiece key);
  
  bool EraseAll(Transaction* tr);
  bool Check();

  int Count(Transaction* tr, const std::string& keyspace);
  //bool GetKeyspaceOffset(const std::string& keyspace, int* offset);
  //bool GetKeyspaceOffsetAndValue(const std::string& keyspace, int* offset, int* value);
  bool GetKeyspaceValue(const std::string& keyspace, int* value);
  bool Checkpoint(int* result_code);
  bool CreateKeyspace(const std::string& keyspace);
  bool DropKeyspace(const std::string& keyspace);
  void GetKeyspaceList(std::vector<std::string>* out, bool include_hidden = false);

  bool ExecuteStatement(const std::string& stmt);
  // FIXME: wrap this up in a ResultSet
  csqlite_stmt* ExecuteQuery(const std::string& query, int* rc);

private:
  friend class Transaction;
  friend class Cursor;

  // TransactionDelegate
  void OnTransactionCommit(Transaction* transaction);
  void OnTransactionRollback(Transaction* transaction);

  bool CreateKeyspaces(const std::vector<std::string>& keyspaces);
  //bool CreateMetaTable();
  bool LoadMetaTable();
  bool LoadKeyspaces();

  base::Lock db_lock_;
  base::Lock btree_lock_;
  base::Lock transaction_lock_;
  base::Lock write_lock_;
  base::Lock keyspaces_lock_;
  csqlite* sqlite_;
  Btree* btree_;
  base::UUID id_;
  bool readonly_;
  bool fragment_values_;
  std::unordered_map<std::string, int> keyspaces_;
  std::vector<std::unique_ptr<Transaction>> transactions_;
  uint32_t largest_root_page_;
  bool closed_;
  mutable bool inside_checkpoint_;
    
 
  DISALLOW_COPY_AND_ASSIGN(Database);
};

void STORAGE_EXPORT DbInit();
void STORAGE_EXPORT DbShutdown();

//std::unique_ptr<Database> Database::Open(const base::FilePath& path, size_t tables, bool readonly);
//std::unique_ptr<Database> Database::Create(const base::FilePath& path, size_t tables);

KeyValuePair STORAGE_EXPORT DbDecodeKV(base::StringPiece encoded, bool* valid);

}

#endif