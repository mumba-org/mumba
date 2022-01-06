// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_ML_ML_CONTROLLER_H_
#define MUMBA_HOST_ML_ML_CONTROLLER_H_

#include <unordered_map>

#include "base/macros.h"
#include "base/files/file_path.h"
#include "base/synchronization/lock.h"
#include "core/host/ml/ml_model.h"

namespace host {
class MLModelManager;
class MLServiceManager;

/*
 * The ML Controller should automate all the operations
 * concerning ML's like models, predictors, datasets, etc...
 */

class MLController {
public:
 MLController(MLModelManager* model_manager, MLServiceManager* service_manager);
 ~MLController();

 void CopyModelFile(const base::FilePath& input_path);
 void CopyAndLoadModelFromFile(MLModelType model_type, const std::string& model_name, const base::FilePath& input_path);

 void InstallPredictor(const std::string& url, base::Callback<void(int)> cb);

private:

 void CopyAndLoadModelFromFileImpl(MLModelType model_type, const std::string& model_name, const base::FilePath& input_path);
 void CopyModelFileImpl(const base::FilePath& input_path);

 MLModelManager* model_manager_;
 MLServiceManager* service_manager_;

 DISALLOW_COPY_AND_ASSIGN(MLController);
};

}

#endif