// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ml/ml_controller.h"

#include "core/host/ml/ml_model_manager.h"
#include "core/host/ml/mxnet_model.h"
#include "base/files/file_util.h"
#include "base/task_scheduler/post_task.h"

namespace host {

MLController::MLController(MLModelManager* model_manager, MLServiceManager* service_manager): 
  model_manager_(model_manager),
  service_manager_(service_manager) {

}

MLController::~MLController() {
  model_manager_ = nullptr;
  service_manager_ = nullptr;
}

void MLController::CopyAndLoadModelFromFile(MLModelType model_type, const std::string& model_name, const base::FilePath& input_path) {
  base::PostTaskWithTraits(
      FROM_HERE,
      { base::WithBaseSyncPrimitives(), base::MayBlock() },
      base::BindOnce(
        &MLController::CopyAndLoadModelFromFileImpl, 
        base::Unretained(this), 
        model_type,
        model_name,
        input_path));
}

void MLController::CopyModelFile(const base::FilePath& input_path) {
  base::PostTaskWithTraits(
      FROM_HERE,
      { base::WithBaseSyncPrimitives(), base::MayBlock() },
      base::BindOnce(
        &MLController::CopyModelFileImpl, 
        base::Unretained(this), 
        input_path));
}

void MLController::InstallPredictor(const std::string& url, base::Callback<void(int)> cb) {
  
}

void MLController::CopyAndLoadModelFromFileImpl(MLModelType model_type, const std::string& model_name, const base::FilePath& input_path) {
  if (!base::PathExists(input_path)) {
    //DLOG(INFO) << "model on path " << input_path << " does not exists. cancelling load";
    return;
  }
  if (!base::PathExists(model_manager_->models_path())) {
    base::CreateDirectory(model_manager_->models_path());
  }
  bool copied = base::CopyFile(input_path, model_manager_->models_path());
  if (copied) {
    if (model_type == MLModelType::kML_MODEL_MXNET) {
      std::unique_ptr<MXNetModel> model = std::make_unique<MXNetModel>(model_name, model_manager_->models_path());
      model_manager_->AddModel(std::move(model));
    }
  }
}

void MLController::CopyModelFileImpl(const base::FilePath& input_path) {
  if (!base::PathExists(input_path)) {
    return;
  }
  if (!base::PathExists(model_manager_->models_path())) {
    base::CreateDirectory(model_manager_->models_path());
  }
  bool copied = base::CopyFile(input_path, model_manager_->models_path());
  DCHECK(copied);
}

}