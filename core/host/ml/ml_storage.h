// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_ML_ML_STORAGE_H_
#define MUMBA_HOST_ML_ML_STORAGE_H_

#include <string>
#include <unordered_map>

#include "base/macros.h"
#include "storage/torrent.h"

namespace host {

class MLStorage {
public:
  MLStorage();
  ~MLStorage();

  /* expected:
   * (manifest ?) 
   * +
   * model_file
   * +
   * parameter file
   */
  bool CreateFileset(const std::string& model_name, const base::FilePath& model_input_dir);
  GetModelFile(const std::string& model_name);

private:
  
  std::unordered_map<std::string, scoped_refptr<storage::Torrent>> torrents_;

  DISALLOW_COPY_AND_ASSIGN(MLStorage);
};

}

#endif
