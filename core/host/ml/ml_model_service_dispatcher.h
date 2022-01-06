// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_ML_ML_MODEL_SERVICE_DIPATCHER_H_
#define MUMBA_HOST_ML_ML_MODEL_SERVICE_DIPATCHER_H_

#include "base/macros.h"
#include "core/shared/common/mojom/ml.mojom.h"

namespace host {
class MLModelManager;

class MLModelServiceDispatcher : public ml::ModelService {
public:
 MLModelServiceDispatcher(MLModelManager* model_manager);
 ~MLModelServiceDispatcher() override;

 MLModelManager* model_manager() const {
   return model_manager_;
 }

 void Compile(ml::ModelCompileRequestPtr request, CompileCallback callback) override;
 void Load(ml::ModelLoadRequestPtr request, LoadCallback callback) override;
 void Unload(ml::ModelUnloadRequestPtr request, UnloadCallback callback) override;

private:
 
 MLModelManager* model_manager_;
 
 DISALLOW_COPY_AND_ASSIGN(MLModelServiceDispatcher);
};

}

#endif