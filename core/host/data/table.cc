// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/data/table.h"

struct sqlite_vcursor {
  csqlite_vtab_cursor base;
  host::SQLiteVCursor* state;
};

struct sqlite_vtab {
  csqlite_vtab base;
  host::SQLiteVTable* state;
};

static int xConnect(csqlite* db, 
                    void *pAux,
                    int argc, const char *const*argv,
                    csqlite_vtab **ppVTab, 
                    char** pzErr) {
  //DCHECK(csqliteMallocInit() == SQLITE_OK);                       
  csqliteMemSetDefault();
  host::SQLiteVTable* state = reinterpret_cast<host::SQLiteVTable*>(pAux);
  int rc = SQLITE_OK;
  DLOG(INFO) << "xConnect: csqlite_declare_vtab => '" << state->table()->create_table_sql() << "'";
  rc = csqlite_declare_vtab(db, state->table()->create_table_sql().c_str());
  if (rc != SQLITE_OK){
    return rc;
  }

  sqlite_vtab* handle = (sqlite_vtab *)csqlite_malloc64(sizeof(sqlite_vtab));
  state->set_handle(handle);
  handle->state = state;
  *ppVTab = &handle->base;
  
  return rc;
}

static int xCreate(csqlite* db, 
                   void *pAux,
                   int argc, const char *const*argv,
                   csqlite_vtab **ppVTab, 
                   char** pzErr) {
  //DLOG(INFO) << "xCreate";
  return xConnect(db, pAux, argc, argv, ppVTab, pzErr);
}



static int xBestIndex(csqlite_vtab *pVTab, csqlite_index_info* index) {
  DLOG(INFO) << "xBestIndex";
  sqlite_vtab* vt = reinterpret_cast<sqlite_vtab*>(pVTab);
  host::SQLiteVTable* state = vt->state;
  return state->BestIndex(pVTab, index);
}

static int xDisconnect(csqlite_vtab *pVTab) {
  DLOG(INFO) << "xDisconnect";
  sqlite_vtab* vt = reinterpret_cast<sqlite_vtab*>(pVTab);
  host::SQLiteVTable* state = vt->state;
  return state->Disconnect(pVTab);
}

static int xDestroy(csqlite_vtab *pVTab) {
  DLOG(INFO) << "xDestroy";
  csqlite_free(reinterpret_cast<sqlite_vtab*>(pVTab));
  return SQLITE_OK;
}

static int xOpen(csqlite_vtab *pVTab, csqlite_vtab_cursor **ppCursor) {
  DLOG(INFO) << "xOpen";
  sqlite_vtab* vt = reinterpret_cast<sqlite_vtab*>(pVTab);
  host::SQLiteVTable* state = vt->state;
  return state->Open(pVTab, ppCursor);
}

static int xClose(csqlite_vtab_cursor* cursor) {
  DLOG(INFO) << "xClose";
  sqlite_vcursor* ncursor = reinterpret_cast<sqlite_vcursor*>(cursor);
  host::SQLiteVCursor* state = ncursor->state;
  state->Close(cursor);
  csqlite_free(ncursor);
  return SQLITE_OK;
}

static int xFilter(csqlite_vtab_cursor* cursor, int idxNum, const char *idxStr,
                   int argc, csqlite_value **argv) {
  DLOG(INFO) << "xFilter";
  sqlite_vcursor* ncursor = reinterpret_cast<sqlite_vcursor*>(cursor);
  host::SQLiteVCursor* state = ncursor->state;
  return state->Filter(cursor, idxNum, idxStr, argc, argv);
}

static int xNext(csqlite_vtab_cursor* cursor) {
  DLOG(INFO) << "xNext";
  sqlite_vcursor* ncursor = reinterpret_cast<sqlite_vcursor*>(cursor);
  host::SQLiteVCursor* state = ncursor->state;
  return state->Next(cursor);
}

static int xEof(csqlite_vtab_cursor* cursor) {
  DLOG(INFO) << "xEof";
  sqlite_vcursor* ncursor = reinterpret_cast<sqlite_vcursor*>(cursor);
  host::SQLiteVCursor* state = ncursor->state;
  return state->Eof(cursor);
}

static int xColumn(csqlite_vtab_cursor* cursor, csqlite_context* context, int i) {
  DLOG(INFO) << "xColumn";
  sqlite_vcursor* ncursor = reinterpret_cast<sqlite_vcursor*>(cursor);
  host::SQLiteVCursor* state = ncursor->state;
  return state->Column(cursor, context, i);
}

static int xRowid(csqlite_vtab_cursor* cursor, csqlite_int64 *pRowid) {
  DLOG(INFO) << "xRowid";
  sqlite_vcursor* ncursor = reinterpret_cast<sqlite_vcursor*>(cursor);
  host::SQLiteVCursor* state = ncursor->state;
  return state->Rowid(cursor, pRowid);
}

static int xUpdate(csqlite_vtab* pVTab, int x, csqlite_value** v, csqlite_int64* i) {
  DLOG(INFO) << "xUpdate";
  sqlite_vtab* vt = reinterpret_cast<sqlite_vtab*>(pVTab);
  host::SQLiteVTable* state = vt->state;
  return state->Update(pVTab, x, v, i);
}

static int xBegin(csqlite_vtab *pVTab) {
  DLOG(INFO) << "xBegin";
  sqlite_vtab* vt = reinterpret_cast<sqlite_vtab*>(pVTab);
  host::SQLiteVTable* state = vt->state;
  return state->Begin(pVTab);
}

static int xSync(csqlite_vtab *pVTab) {
  DLOG(INFO) << "xSync";
  sqlite_vtab* vt = reinterpret_cast<sqlite_vtab*>(pVTab);
  host::SQLiteVTable* state = vt->state;
  return state->Sync(pVTab);
}

static int xCommit(csqlite_vtab *pVTab) {
  DLOG(INFO) << "xCommit";
  sqlite_vtab* vt = reinterpret_cast<sqlite_vtab*>(pVTab);
  host::SQLiteVTable* state = vt->state;
  return state->Commit(pVTab);
}

static int xRollback(csqlite_vtab *pVTab) {
  DLOG(INFO) << "xRollback";
  sqlite_vtab* vt = reinterpret_cast<sqlite_vtab*>(pVTab);
  host::SQLiteVTable* state = vt->state;
  return state->Rollback(pVTab);
}

static int xFindFunction(csqlite_vtab *pVTab, int nArg, const char *zName,
                        void (**pxFunc)(csqlite_context*,int,csqlite_value**),
                        void **ppArg) {
  DLOG(INFO) << "xFindFunction";
  sqlite_vtab* vt = reinterpret_cast<sqlite_vtab*>(pVTab);
  host::SQLiteVTable* state = vt->state;
  
  return state->FindFunction(pVTab, nArg, zName, pxFunc, ppArg);
}

static int xRename(csqlite_vtab *pVTab, const char *zNew) {
  DLOG(INFO) << "xRename";
  sqlite_vtab* vt = reinterpret_cast<sqlite_vtab*>(pVTab);
  host::SQLiteVTable* state = vt->state;
  return state->Rename(pVTab, zNew);
}

static int xSavepoint(csqlite_vtab *pVTab, int i) {
  DLOG(INFO) << "xSavepoint";
  sqlite_vtab* vt = reinterpret_cast<sqlite_vtab*>(pVTab);
  host::SQLiteVTable* state = vt->state;
  return state->Savepoint(pVTab, i);
}

static int xRelease(csqlite_vtab *pVTab, int i) {
  DLOG(INFO) << "xRelease";
  sqlite_vtab* vt = reinterpret_cast<sqlite_vtab*>(pVTab);
  host::SQLiteVTable* state = vt->state;
  return state->Release(pVTab, i);
}

static int xRollbackTo(csqlite_vtab *pVTab, int i) {
  DLOG(INFO) << "xRollbackTo";
  sqlite_vtab* vt = reinterpret_cast<sqlite_vtab*>(pVTab);
  host::SQLiteVTable* state = vt->state;
  return state->RollbackTo(pVTab, i);
}

namespace host {

std::unique_ptr<SQLiteVCursor> SQLiteVCursor::Open(SQLiteVTable* vtable, std::unique_ptr<Cursor> cursor) {
  return {};
}

SQLiteVCursor::SQLiteVCursor(SQLiteVTable* vtable, sqlite_vcursor* handle, std::unique_ptr<Cursor> cursor): 
  vtable_(vtable),
  handle_(handle),
  cursor_(std::move(cursor)) {

}

int SQLiteVCursor::Close(csqlite_vtab_cursor*) {
  return cursor_->Close();
}

int SQLiteVCursor::Filter(csqlite_vtab_cursor*, int idx_num, const char *idx_str, int argc, csqlite_value **argv) {
  return cursor_->Filter(idx_num, idx_str, argc, argv);
}

int SQLiteVCursor::Next(csqlite_vtab_cursor*) {
  return cursor_->Next();
}

int SQLiteVCursor::Eof(csqlite_vtab_cursor*) {
  return cursor_->Eof();
}

int SQLiteVCursor::Column(csqlite_vtab_cursor*, csqlite_context* ctx, int i) {
  return cursor_->Column(ctx, i);
}

int SQLiteVCursor::Rowid(csqlite_vtab_cursor*, csqlite_int64 *row_id) {
  return cursor_->Rowid(row_id);
}

// struct csqlite_module {
//   int iVersion;
//   int (*xCreate)(csqlite*, void *pAux,
//                int argc, const char *const*argv,
//                csqlite_vtab **ppVTab, char**);
//   int (*xConnect)(csqlite*, void *pAux,
//                int argc, const char *const*argv,
//                csqlite_vtab **ppVTab, char**);
//   int (*xBestIndex)(csqlite_vtab *pVTab, csqlite_index_info*);
//   int (*xDisconnect)(csqlite_vtab *pVTab);
//   int (*xDestroy)(csqlite_vtab *pVTab);
//   int (*xOpen)(csqlite_vtab *pVTab, csqlite_vtab_cursor **ppCursor);
//   int (*xClose)(csqlite_vtab_cursor*);
//   int (*xFilter)(csqlite_vtab_cursor*, int idxNum, const char *idxStr,
//                 int argc, csqlite_value **argv);
//   int (*xNext)(csqlite_vtab_cursor*);
//   int (*xEof)(csqlite_vtab_cursor*);
//   int (*xColumn)(csqlite_vtab_cursor*, csqlite_context*, int);
//   int (*xRowid)(csqlite_vtab_cursor*, csqlite_int64 *pRowid);
//   int (*xUpdate)(csqlite_vtab *, int, csqlite_value **, csqlite_int64 *);
//   int (*xBegin)(csqlite_vtab *pVTab);
//   int (*xSync)(csqlite_vtab *pVTab);
//   int (*xCommit)(csqlite_vtab *pVTab);
//   int (*xRollback)(csqlite_vtab *pVTab);
//   int (*xFindFunction)(csqlite_vtab *pVTab, int nArg, const char *zName,
//                        void (**pxFunc)(csqlite_context*,int,csqlite_value**),
//                        void **ppArg);
//   int (*xRename)(csqlite_vtab *pVTab, const char *zNew);
//   /* The methods above are in version 1 of the sqlite_module object. Those 
//   ** below are for version 2 and greater. */
//   int (*xSavepoint)(csqlite_vtab *pVTab, int);
//   int (*xRelease)(csqlite_vtab *pVTab, int);
//   int (*xRollbackTo)(csqlite_vtab *pVTab, int);
// };

// static 
std::unique_ptr<SQLiteVTable> SQLiteVTable::Create(storage::Database* db, std::unique_ptr<Table> vtable) {
  const std::string& name = vtable->name();
  DLOG(INFO) << "creating virtual table '" << name << "' for db " << db;
  int version = vtable->version();
  std::unique_ptr<SQLiteVTable> handle = std::make_unique<SQLiteVTable>(db, std::move(vtable));
  handle->callbacks_.iVersion = version;
  handle->callbacks_.xCreate = xCreate;
  handle->callbacks_.xConnect = xConnect;
  handle->callbacks_.xBestIndex = xBestIndex;
  handle->callbacks_.xDisconnect = xDisconnect;
  handle->callbacks_.xDestroy = xDestroy;
  handle->callbacks_.xOpen = xOpen;
  handle->callbacks_.xClose = xClose;
  handle->callbacks_.xFilter = xFilter;
  handle->callbacks_.xNext = xNext;
  handle->callbacks_.xEof = xEof;
  handle->callbacks_.xColumn = xColumn;
  handle->callbacks_.xRowid = xRowid;
  handle->callbacks_.xUpdate = xUpdate;
  handle->callbacks_.xBegin = xBegin;
  handle->callbacks_.xSync = xSync;
  handle->callbacks_.xCommit = xCommit;
  handle->callbacks_.xRollback = xRollback;
  handle->callbacks_.xFindFunction = xFindFunction;
  handle->callbacks_.xRename = xRename;
  handle->callbacks_.xSavepoint = xSavepoint;
  handle->callbacks_.xRelease = xRelease;
  handle->callbacks_.xRollbackTo = xRollbackTo;
  if (!db->CreateVirtualTable(name, handle.get(), &handle->callbacks_)) {
    return nullptr;
  }
  return handle;
}

SQLiteVTable::SQLiteVTable(storage::Database* db, std::unique_ptr<Table> vtable): db_(db), user_table_(std::move(vtable)) {

}

int SQLiteVTable::BestIndex(csqlite_vtab *tab, csqlite_index_info* index_info) {
  return user_table_->BestIndex(index_info);
}

int SQLiteVTable::Disconnect(csqlite_vtab *tab) {
  sqlite_vtab* vt = reinterpret_cast<sqlite_vtab*>(tab);
  user_table_->Disconnect();
  csqlite_free(vt);
  return SQLITE_OK;
}

int SQLiteVTable::Destroy(csqlite_vtab *tab) {
  return user_table_->Destroy();
}

int SQLiteVTable::Open(csqlite_vtab *tab, csqlite_vtab_cursor **cursor) {
  sqlite_vcursor* pCur;
  size_t nByte = sizeof(*pCur);// + (sizeof(char*)+sizeof(int))*tab->nCol;
  pCur = (sqlite_vcursor*) csqlite_malloc64(nByte);
  if (pCur == 0) {
    return SQLITE_NOMEM;
  } 
  memset(pCur, 0, nByte);
  //pCur->azVal = (char**)&pCur[1];
  //pCur->aLen = (int*)&pCur->azVal[pTab->nCol];

  // from the csv virtual table sample
  // our internal user_table_->Open()
  // should be more like it

  // if (csv_reader_open(&pCur->rdr, pTab->zFilename, pTab->zData)){
  //   csv_xfer_error(pTab, &pCur->rdr);
  //   return SQLITE_ERROR;
  // }
  auto user_cursor = user_table_->Open();
  std::unique_ptr<SQLiteVCursor> vcursor = std::make_unique<SQLiteVCursor>(this, pCur, std::move(user_cursor));
  pCur->state = vcursor.get();
  *cursor = &pCur->base;
  cursors_.push_back(std::move(vcursor));
  return SQLITE_OK;
}

int SQLiteVTable::Update(csqlite_vtab *, int x, csqlite_value ** v, csqlite_int64 * i) {
  return user_table_->Update(x, v, i);
}

int SQLiteVTable::Begin(csqlite_vtab *tab) {
  return user_table_->Begin();
}

int SQLiteVTable::Sync(csqlite_vtab *tab) {
  return user_table_->Sync();
}

int SQLiteVTable::Commit(csqlite_vtab *tab) {
  return user_table_->Commit();
}

int SQLiteVTable::Rollback(csqlite_vtab *tab) {
  return user_table_->Rollback();
}

int SQLiteVTable::FindFunction(csqlite_vtab *tab, int argc, const char *name,
                               void (**func)(csqlite_context*,int,csqlite_value**),
                               void **args) {
  return 0;
}

int SQLiteVTable::Rename(csqlite_vtab *tab, const char *znew) {
  std::string field(znew);
  return user_table_->Rename(field);
}

int SQLiteVTable::Savepoint(csqlite_vtab *tab, int i) {
  return user_table_->Savepoint(i);
}

int SQLiteVTable::Release(csqlite_vtab *tab, int i) {
  return user_table_->Release(i);
}

int SQLiteVTable::RollbackTo(csqlite_vtab *tab, int i) {
  return user_table_->RollbackTo(i);
}

void SQLiteVTable::OnClose(SQLiteVCursor* cursor) {
  //std::erase(cursors_.begin(), cursors_.end(), cursor);
}

}