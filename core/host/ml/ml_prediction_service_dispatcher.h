// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_ML_ML_PREDICTION_SERVICE_DISPATCHER_H_
#define MUMBA_HOST_ML_ML_PREDICTION_SERVICE_DISPATCHER_H_

#include "base/macros.h"
#include "core/shared/common/mojom/ml.mojom.h"

namespace host {
class MLModelManager;
class MLServiceManager;

class MLPredictionServiceDispatcher : public ml::PredictionService {
public:
 MLPredictionServiceDispatcher(MLModelManager* model_manager, MLServiceManager* service_manager);
 ~MLPredictionServiceDispatcher() override;

 MLModelManager* model_manager() const {
   return model_manager_;
 }

 MLServiceManager* service_manager() const {
   return service_manager_;
 }

 void Predict(const std::string& model_name, const std::string& model_version, ml::PredictRequestPtr request, PredictCallback callback) override;

private:
 
 MLModelManager* model_manager_;
 MLServiceManager* service_manager_;
 
 DISALLOW_COPY_AND_ASSIGN(MLPredictionServiceDispatcher);
};

}

#endif