// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_NAMESPACE_NAMESPACE_DATABASE_H_
#define MUMBA_DOMAIN_NAMESPACE_NAMESPACE_DATABASE_H_

#include <memory>

#include "base/macros.h"
#include "base/files/file_path.h"
#include "base/callback.h"

namespace domain {
class DatabaseBackend;

class Database {
public:
  enum State {
    kUndefined,
    kInitialized,
    kShutdown,
    kError
  };

  Database(int id, const base::FilePath& db_path, bool in_memory);
  ~Database();

  int id() const {
    return id_;
  }

  bool in_memory() const;

  State state() const { 
    return state_; 
  }

  void set_state(State state)  { 
    state_ = state; 
  }

  void Initialize(const base::Callback<void(int, int)>& result);
  void Shutdown();

private:

  int id_;

  State state_;

  std::unique_ptr<DatabaseBackend> backend_;

  DISALLOW_COPY_AND_ASSIGN(Database);
};

}

#endif