// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_NAMESPACE_FILESYSTEM_H_
#define MUMBA_DOMAIN_NAMESPACE_FILESYSTEM_H_

#include "base/macros.h"
#include "base/callback.h"
#include "base/files/file_path.h"
#include "base/uuid.h"

//#include "core/shared/domain/storage/filesystem_type.h"

namespace domain {
class FilesystemBackend;

class Filesystem {
public:

  enum State {
    kUndefined,
    kInitialized,
    kShutdown,
    kError
  };

  Filesystem(
   // FilesystemType type,
    int id,
    const base::UUID& namespace_id, 
    const base::FilePath& fs_path,
    bool in_memory);
  
  ~Filesystem();

  int id() const {
    return id_;
  }

  State state() const { 
    return state_; 
  }

  void set_state(State state)  { 
    state_ = state; 
  }

 // FilesystemType type() const;

  bool in_memory() const;

  int32_t GetFileCount() const;

  void Initialize(const base::Callback<void(int, int)>& result);

  void Shutdown();

private:

  std::unique_ptr<FilesystemBackend> backend_;

  int id_;

  State state_;

  DISALLOW_COPY_AND_ASSIGN(Filesystem);
};

}

#endif