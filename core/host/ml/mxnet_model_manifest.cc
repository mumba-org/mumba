// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ml/mxnet_model_manifest.h"

#include "base/strings/string_util.h"
#include "base/json/json_reader.h"
#include "base/files/file_util.h"
#include "core/host/ml/mxnet_model.h"

namespace host {

namespace {
const char kMANIFEST_FILE[] = "MANIFEST.json";
}

MXNetModelManifest::MXNetModelManifest(): 
  model_(new MXNetModel("_unnamed", path_)),
  specification_version_("1.0"),
  implementation_version_("1.0"),
  model_server_version_("1.0"),
  license_("Apache 2.0"),
  runtime_(RuntimeType::kPYTHON),
  is_valid_(false) {
}

MXNetModelManifest::~MXNetModelManifest() {

}

bool MXNetModelManifest::ParseFromFile(const base::FilePath& model_dir) {
  std::string manifest_content;
  base::FilePath manifest_file = model_dir.AppendASCII("MAR-INF").AppendASCII(kMANIFEST_FILE);

  if (!base::ReadFileToString(manifest_file, &manifest_content)) {
    return false;
  }

  std::unique_ptr<base::Value> root = base::JSONReader::Read(manifest_content);
  if (!root) {
    return false;
  }
  return ParseFromJson(root.get());
}

bool MXNetModelManifest::ParseFromJson(base::Value* root) {
  // {
  // "specificationVersion": "1.0",
  // "implementationVersion": "1.0",
  // "description": "noop v1.0",
  // "modelServerVersion": "1.0",
  // "license": "Apache 2.0",
  // "runtime": "python",
  // "model": {
  //   "modelName": "respheader",
  //   "description": "Tests for response headers",
  //   "modelVersion": "1.0",
  //   "handler": "service:handle"
  // },
  // "publisher": {
  //   "author": "MXNet SDK team",
  //   "email": "noreply@amazon.com"
  // }
  // }
  std::unique_ptr<MXNetModel> model_;
  RuntimeType runtime_;
  Engine engine_;
  Publisher publisher_;

  if (!root || root->type() != base::Value::Type::DICTIONARY) {
    return false;
  }
  
  base::Value* spec_version = root->FindKeyOfType("specificationVersion", base::Value::Type::STRING);
  if (!spec_version) {
    return false;
  }
  
  specification_version_ = spec_version->GetString();
  base::Value* impl_version = root->FindKeyOfType("implementationVersion", base::Value::Type::STRING);
  if (!impl_version) {
    return false;
  }
  implementation_version_ = impl_version->GetString();

  base::Value* descr = root->FindKeyOfType("description", base::Value::Type::STRING);
  if (!descr) {
    return false;
  }

  description_ = descr->GetString();
  
  base::Value* model_server_version = root->FindKeyOfType("modelServerVersion", base::Value::Type::STRING);
  if (!model_server_version) {
    return false;
  }

  model_server_version_ = model_server_version->GetString();

  base::Value* license = root->FindKeyOfType("license", base::Value::Type::STRING);
  if (!license) {
    return false;
  }

  license_ = license->GetString();
  
  base::Value* runtime = root->FindKeyOfType("runtime", base::Value::Type::STRING);
  if (!runtime) {
    return false;
  }

  if (runtime->GetString() == "python") {
    runtime_ = kPYTHON;
  } else if(runtime->GetString() == "python2") {
    runtime_ = kPYTHON2;
  } else if(runtime->GetString() == "python3") {
    runtime_ = kPYTHON3;
  }
  
  base::Value* model = root->FindKeyOfType("model", base::Value::Type::DICTIONARY);
  if (model) {
    base::Value* modelName = model->FindKeyOfType("modelName", base::Value::Type::STRING);
    base::Value* modelDescription = model->FindKeyOfType("description", base::Value::Type::STRING);
    base::Value* modelVersion = model->FindKeyOfType("modelVersion", base::Value::Type::STRING);
    base::Value* modelHandler = model->FindKeyOfType("handler", base::Value::Type::STRING);

    if (!modelName || !modelDescription || !modelVersion || !modelHandler) {
      return false;
    }

    model_->set_model_name(modelName->GetString());
    model_->set_description(modelDescription->GetString());
    model_->set_model_version(modelVersion->GetString());
    model_->set_handler(modelHandler->GetString()); 
  }
  
  base::Value* publisher = root->FindKeyOfType("publisher", base::Value::Type::DICTIONARY);
  if (publisher) {
    base::Value* publisherAuthor = model->FindKeyOfType("author", base::Value::Type::STRING);
    base::Value* publisherEmail = model->FindKeyOfType("email", base::Value::Type::STRING);

    if (!publisherAuthor || !publisherEmail) {
        return false;
    }

    publisher_.author = publisherAuthor->GetString();
    publisher_.email = publisherEmail->GetString(); 
  }

  is_valid_ = true;
  return true;
}

}