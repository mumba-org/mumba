// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ml/mxnet_model_file.h"

#include "core/host/ml/mxnet_model.h"
#include "core/host/ml/mxnet_model_manifest.h"

namespace host {

std::unique_ptr<MXNetModelFile> MXNetModelFile::Load(const base::FilePath& model_file) {
  auto file = std::make_unique<MXNetModelFile>();
  bool loaded = file->LoadManifest(model_file);
  if (!loaded) {
    return {};
  }
  return file;
}

MXNetModelFile::MXNetModelFile() {

}

MXNetModelFile::~MXNetModelFile() {

}

std::unique_ptr<MXNetModel> MXNetModelFile::LoadModel() {
  if (!manifest_->is_valid()) {
    return {};
  }
  return manifest_->OwnModel();
}

bool MXNetModelFile::LoadManifest(const base::FilePath& model_file) {
  auto manifest = std::make_unique<MXNetModelManifest>();
  bool ok = manifest->ParseFromFile(model_file);
  if (!ok) {
    return false;
  }
  manifest_ = std::move(manifest);
  return true;
}

}