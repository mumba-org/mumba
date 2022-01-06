// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_NAMESPACE_GRAPH_GRAPH_DB_H_
#define MUMBA_DOMAIN_NAMESPACE_GRAPH_GRAPH_DB_H_

#include <memory>

#include "base/macros.h"
#include "base/single_thread_task_runner.h"
#include "base/files/file_path.h"
#include "core/shared/domain/storage/graph/graph_db_transaction.h"
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
#include "core/shared/domain/storage/graph/lemongraph.h"
#pragma clang diagnostic push

namespace domain {

class GraphDb {
public:
  static std::unique_ptr<GraphDb> Open(int id, const base::FilePath& path, bool in_memory);
  
  GraphDb(int id, const base::FilePath& path, bool in_memory);  
  ~GraphDb();

  int id() const {
    return id_;
  }

  bool is_open() const {
    return open_;
  }

  bool in_memory() const {
    return in_memory_;
  }

  base::SingleThreadTaskRunner* task_runner() const {
    return background_task_runner_.get();
  }

  void Initialize(const base::Callback<void(int)>& callback);
  void Shutdown();

  GraphDbTransaction Begin(bool write) const;

  void Count(const base::Callback<void(size_t)>& callback) const;

  void Sync(bool force);
  void Updated();
  void Remap();

  void Execute(const base::Callback<void(GraphDbTransaction*)>& batch, bool write) const;
  
private:

  int InitializeImpl();
  void ShutdownImpl();

  void SyncImpl(bool force);
  void UpdatedImpl();
  void RemapImpl();

  void ExecuteImpl(const base::Callback<void(GraphDbTransaction*)>& batch, bool write) const;

  void CountImpl(const base::Callback<void(size_t)>& callback) const;
  
  int id_;

  base::FilePath path_;

  bool in_memory_;

  graph_t graph_db_;

  scoped_refptr<base::SingleThreadTaskRunner> background_task_runner_;

  bool open_;

  DISALLOW_COPY_AND_ASSIGN(GraphDb);
};


}

#endif