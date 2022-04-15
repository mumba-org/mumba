// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ml/ml_model_manager.h"

#include "core/host/ml/mxnet_model.h"
#include "base/files/file_util.h"
#include "base/task_scheduler/post_task.h"

namespace host {

MLModelManager::MLModelManager(const base::FilePath& models_path): models_path_(models_path) {

}

MLModelManager::~MLModelManager() {
  
}

bool MLModelManager::HaveModel(const std::string& model_name) {
  base::AutoLock lock(model_lock_);
  return models_.find(model_name) != models_.end();
}

bool MLModelManager::HaveModel(const base::UUID& id) {
  base::AutoLock lock(model_lock_);
  for (auto it = models_.begin(); it != models_.end(); ++it) {
    if (it->second->id() == id) {
      return true;
    }  
  }
  return false;
}

void MLModelManager::AddModel(std::unique_ptr<MLModel> model) {
  base::AutoLock lock(model_lock_);
  const std::string& model_name = model->model_name(); 
  models_.emplace(std::make_pair(model_name, std::move(model)));
}

MLModel* MLModelManager::GetModel(const std::string& model_name) {
  base::AutoLock lock(model_lock_);
  auto it = models_.find(model_name);
  if (it != models_.end()) {
    return it->second.get();
  }
  return nullptr;
}

MLModel* MLModelManager::GetModel(const base::UUID& id) {
  base::AutoLock lock(model_lock_);
  for (auto it = models_.begin(); it != models_.end(); ++it) {
    if (it->second->id() == id) {
      return it->second.get();
    }  
  }
  return nullptr;
}

void MLModelManager::CopyAndLoadModelFromFile(MLModelType model_type, const std::string& model_name, const base::FilePath& input_path) {
  base::PostTaskWithTraits(
      FROM_HERE,
      { base::WithBaseSyncPrimitives(), base::MayBlock() },
      base::BindOnce(
        &MLModelManager::CopyAndLoadModelFromFileImpl, 
        base::Unretained(this), 
        model_type,
        model_name,
        input_path));
}

MLModel* MLModelManager::LoadModel(MLModelType model_type, const std::string& model_name) {
  base::AutoLock lock(model_lock_);
  MLModel* result = nullptr;
  if (model_type == MLModelType::kML_MODEL_MXNET) {
    std::unique_ptr<MXNetModel> model = std::make_unique<MXNetModel>(model_name, models_path_);
    result = model.get();
    models_.emplace(std::make_pair(model_name, std::move(model)));
  }
  DCHECK(result);
  return result;
}

void MLModelManager::CopyModelFile(const base::FilePath& input_path) {
  base::PostTaskWithTraits(
      FROM_HERE,
      { base::WithBaseSyncPrimitives(), base::MayBlock() },
      base::BindOnce(
        &MLModelManager::CopyModelFileImpl, 
        base::Unretained(this), 
        input_path));
}

void MLModelManager::CopyAndLoadModelFromFileImpl(MLModelType model_type, const std::string& model_name, const base::FilePath& input_path) {
  base::AutoLock lock(model_lock_);
  if (!base::PathExists(input_path)) {
    //DLOG(INFO) << "model on path " << input_path << " does not exists. cancelling load";
    return;
  }
  if (!base::PathExists(models_path_)) {
    base::CreateDirectory(models_path_);
  }
  bool copied = base::CopyFile(input_path, models_path_);
  if (copied) {
    if (model_type == MLModelType::kML_MODEL_MXNET) {
      std::unique_ptr<MXNetModel> model = std::make_unique<MXNetModel>(model_name, models_path_);
      models_.emplace(std::make_pair(model_name, std::move(model)));
    }
  }
}

void MLModelManager::CopyModelFileImpl(const base::FilePath& input_path) {
  if (!base::PathExists(input_path)) {
    return;
  }
  if (!base::PathExists(models_path_)) {
    base::CreateDirectory(models_path_);
  }
  bool copied = base::CopyFile(input_path, models_path_);
  DCHECK(copied);
}

const google::protobuf::Descriptor* MLModelManager::resource_descriptor() {
  //Schema* schema = workspace_->schema_registry()->GetSchemaByName("objects.proto");
  //DCHECK(schema);
  //return schema->GetMessageDescriptorNamed("MLModel");
  // FIXME
  return nullptr;
}

std::string MLModelManager::resource_classname() const {
  return "ml_model";
}

}