// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ml/mxnet_model.h"

#include <iostream>
#include <fstream>

#include "base/files/file_util.h"
#define MSHADOW_XINLINE MSHADOW_FORCE_INLINE
//#include "mxnet/ndarray.h"

namespace host {

MXNetModel::MXNetModel(const std::string& model_name, const base::FilePath& model_path):
 uuid_(base::UUID::generate()), 
 model_name_(model_name),
 model_path_(model_path),
 //global_ctx_(mxnet::cpp::Context::cpu()),
 highest_bucket_key_(-1),
 model_loaded_(false),
 params_loaded_(false) {

}

MXNetModel::~MXNetModel() {
  // for (auto bucket : this->executor_buckets_) {
  //   mxnet::cpp::Executor* executor = bucket.second;
  //   delete executor;
  // }
}

const std::string& MXNetModel::model_name() const {
  return model_name_;
}

void MXNetModel::Load(const std::vector<int>& bucket_keys) {
  // bucket_keys_ = bucket_keys;
  // base::FilePath model_file = model_path_.AppendASCII(model_name_ + ".json");
  // if (!base::PathExists(model_file)) {
  //   DLOG(INFO) << "Loading the model file '" << model_file << "' does not exist";
  //   return;
  // }
  // net_ = mxnet::cpp::Symbol::Load(model_file.value());
  // model_loaded_ = net_.GetHandle() != nullptr;
}

void MXNetModel::LoadParameters(const std::string& params_name) {
  // base::FilePath model_params_file = model_path_.AppendASCII(params_name);
  // if (!base::PathExists(model_params_file)) {
  //   DLOG(ERROR) << "Parameter file '" << model_params_file << "' does not exist";
  //   return;
  // }
  // DLOG(INFO) << "Loading the model parameters from " << model_params_file;
  // std::map<std::string, mxnet::cpp::NDArray> parameters;
  // mxnet::cpp::NDArray::Load(model_params_file.value(), 0, &parameters);
  // for (const auto &k : parameters) {
  //   if (k.first.substr(0, 4) == "aux:") {
  //     auto name = k.first.substr(4, k.first.size() - 4);
  //     aux_map_[name] = k.second.Copy(global_ctx_);
  //   }
  //   if (k.first.substr(0, 4) == "arg:") {
  //     auto name = k.first.substr(4, k.first.size() - 4);
  //     args_map_[name] = k.second.Copy(global_ctx_);
  //   }
  // }
  // /*WaitAll is need when we copy data between GPU and the main memory*/
  // mxnet::cpp::NDArray::WaitAll();
  // params_loaded_ = true;
}

void MXNetModel::Compile() {
   /*
   * Create the executors for each bucket key. The bucket key represents the shape of input data.
   * The executors will share the memory by using following technique:
   * 1. Infer the executor arrays and bind the first executor with the first bucket key.
   * 2. Then for creating the next bucket key, adjust the shape of input argument to match that key.
   * 3. Create the executor for the next bucket key by passing the inferred executor arrays and
   *    pointer to the executor created for the first key.
   */
  // std::vector<mxnet::cpp::NDArray> arg_arrays;
  // std::vector<mxnet::cpp::NDArray> grad_arrays;
  // std::vector<mxnet::cpp::OpReqType> grad_reqs;
  // std::vector<mxnet::cpp::NDArray> aux_arrays;

  // /*
  //  * Create master executor with highest bucket key for optimizing the shared memory between the
  //  * executors for the remaining bucket keys.
  //  */
  // highest_bucket_key_ = *(std::max_element(bucket_keys_.begin(), bucket_keys_.end()));
  // args_map_["data0"] = mxnet::cpp::NDArray(mxnet::cpp::Shape(highest_bucket_key_, 1), global_ctx_, false);
  // args_map_["data1"] = mxnet::cpp::NDArray(mxnet::cpp::Shape(1), global_ctx_, false);

  // net_.InferExecutorArrays(global_ctx_, &arg_arrays, &grad_arrays, &grad_reqs,
  //                         &aux_arrays, args_map_, std::map<std::string, mxnet::cpp::NDArray>(),
  //                         std::map<std::string, mxnet::cpp::OpReqType>(), aux_map_);
  // mxnet::cpp::Executor *master_executor = net_.Bind(global_ctx_, arg_arrays, grad_arrays, grad_reqs, aux_arrays,
  //   std::map<std::string, mxnet::cpp::Context>(), nullptr);
  // executor_buckets_[highest_bucket_key_] = master_executor;

  // for (int bucket : bucket_keys_) {
  //   if (executor_buckets_.find(bucket) == executor_buckets_.end()) {
  //     arg_arrays[0] = mxnet::cpp::NDArray(mxnet::cpp::Shape(bucket, 1), global_ctx_, false);
  //     mxnet::cpp::Executor *executor = net_.Bind(global_ctx_, arg_arrays, grad_arrays, grad_reqs, aux_arrays,
  //                                      std::map<std::string, mxnet::cpp::Context>(), master_executor);
  //     executor_buckets_[bucket] = executor;
  //   }
  // }
}

void MXNetModel::LoadDictionaryFile(const base::FilePath& input_dictionary) {
  // if (!base::PathExists(input_dictionary)) {
  //   DLOG(INFO) << "Dictionary file " << input_dictionary << " does not exist";
  //   return;
  // }
  // std::ifstream fi(input_dictionary.value().c_str());
  // if (!fi.is_open()) {
  //   DLOG(ERROR) << "Error opening dictionary file " << input_dictionary << std::endl;
  //   assert(false);
  // }

  // std::string line;
  // std::string word;
  // int index;
  // while (std::getline(fi, line)) {
  //   std::istringstream stringline(line);
  //   stringline >> word >> index;
  //   word_to_index_[word] = index;
  // }
  // fi.close();
}

}