// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_ML_MXNET_MODEL_FILE_H_
#define MUMBA_HOST_ML_MXNET_MODEL_FILE_H_

#include "base/macros.h"
#include "base/files/file_path.h"

namespace host {
class MXNetModel;
class MXNetModelManifest;

class MXNetModelFile {
public:
 static std::unique_ptr<MXNetModelFile> Load(const base::FilePath& model_file);
 
 MXNetModelFile();
 ~MXNetModelFile();

 MXNetModelManifest* manifest() const {
    return manifest_.get();
 }

 std::unique_ptr<MXNetModel> LoadModel();

private:

  bool LoadManifest(const base::FilePath& model_file);

  std::unique_ptr<MXNetModelManifest> manifest_;

  DISALLOW_COPY_AND_ASSIGN(MXNetModelFile);
};

}

#endif
