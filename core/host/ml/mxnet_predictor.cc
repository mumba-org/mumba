// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ml/mxnet_predictor.h"

#include "core/host/ml/mxnet_model.h"
#include "core/host/ml/ml_model_manager.h"
//#include "mxnet/cpp-package/include/mxnet-cpp/ndarray.h"
#include "base/task_scheduler/post_task.h"

namespace host {
namespace {
  //const char input_line[] = "this movie sucks balls";
}

MXNetPredictor::MXNetPredictor(const std::string& service_name): 
  service_name_(service_name) {

}

MXNetPredictor::~MXNetPredictor() {
  
}

const std::string& MXNetPredictor::service_name() const {
  return service_name_;
}

MLModel* MXNetPredictor::model() const {
  return model_;
}

void MXNetPredictor::Init() {
  
}

void MXNetPredictor::LoadModel(MLModelManager* model_manager, const std::string& model_name, const std::vector<int>& bucket_keys) {
  // if (!model_) {
  //   if (!model_manager->HaveModel(model_name)) {
  //     model_ = static_cast<MXNetModel*>(model_manager->LoadModel(MLModelType::kML_MODEL_MXNET, model_name));
  //     DCHECK(model_);
  //     model_->Load(bucket_keys);
  //   } else {
  //     model_ = static_cast<MXNetModel*>(model_manager->GetModel(model_name));
  //     DCHECK(model_);
  //     if (!model_->is_loaded()) {
  //       model_->Load(bucket_keys);
  //     }
  //   }
  // }
  // DCHECK(model_->is_loaded());
}

void MXNetPredictor::LoadParameters(const std::string& params_name) {
  //model_->LoadParameters(params_name);
}

void MXNetPredictor::LoadDictionaryFile(const base::FilePath& input_dictionary) {
  //model_->LoadDictionaryFile(input_dictionary);
}

void MXNetPredictor::Inference(mxnet::cpp::NDArray* input, base::OnceCallback<void(mxnet::cpp::NDArray)> callback) {
  // model_->Compile();
  // /*
  //  * Initialize a vector of length equal to 'num_words' with index corresponding to <eos>.
  //  * Convert the input string to a vector of indices that represent
  //  * the words in the input string.
  //  */
  // std::vector<float> index_vector(GetIndexForWord("<eos>"));
  // int num_words = ConvertToIndexVector(std::string(input_line), &index_vector);
  // int bucket_key = GetClosestBucketKey(num_words);

  // /*
  //  * The index_vector has size equal to num_words. The vector needs to be padded if
  //  * the bucket_key is greater than num_words. The vector needs to be trimmed if
  //  * the bucket_key is smaller than num_words.
  //  */
  // index_vector.resize(bucket_key, GetIndexForWord("<eos>"));

  // mxnet::cpp::Executor* executor = model_->executor_buckets_[bucket_key];
  // executor->arg_dict()["data0"].SyncCopyFromCPU(index_vector.data(), index_vector.size());
  // executor->arg_dict()["data1"] = num_words;

  // // Run the forward pass.
  // executor->Forward(false);

  // /*
  //  * The output is available in executor->outputs. It is a vector of
  //  * NDArray. We need to find the index in that vector that
  //  * corresponds to the output symbol "sentimentnet0_hybridsequential0_dense0_fwd_output".
  //  */
  // const std::string output_symbol_name = "sentimentnet0_hybridsequential0_dense0_fwd_output";
  // int output_index = GetIndexForOutputSymbolName(output_symbol_name);
  // std::vector<mxnet::cpp::NDArray> outputs = executor->outputs;
  // auto arrayout = executor->outputs[output_index].Copy(model_->global_ctx_);
  // std::move(callback).Run(std::move(arrayout));
}

/*
 * The function returns the index associated with the word in the dictionary.
 * If the word is not present, the index representing "<unk>" is returned.
 * If the "<unk>" is not present then 0 is returned.
 */
float MXNetPredictor::GetIndexForWord(const std::string& word) {
  // if (model_->word_to_index_.find(word) == model_->word_to_index_.end()) {
  //   if (model_->word_to_index_.find("<unk>") == model_->word_to_index_.end())
  //     return 0;
  //   else
  //     return static_cast<float>(model_->word_to_index_["<unk>"]);
  // }
  // return static_cast<float>(model_->word_to_index_[word]);
  return 0;
}

/*
 * The function populates the input vector with indices from the dictionary that
 * correspond to the words in the input string.
 * The function returns the number of words in the input line.
 */
int MXNetPredictor::ConvertToIndexVector(const std::string& input, std::vector<float> *input_vector) {
  // std::istringstream input_string(input);
  // input_vector->clear();
  // const char delimiter = ' ';
  // std::string token;
  // size_t words = 0;
  // while (std::getline(input_string, token, delimiter) && (words <= input_vector->size())) {
  //   input_vector->push_back(GetIndexForWord(token));
  //   words++;
  // }
  // return words;
  return 0;
}


/*
 * The function returns the index at which the given symbol name will appear
 * in the output vector of NDArrays obtained after running the forward pass on the executor.
 */
int MXNetPredictor::GetIndexForOutputSymbolName(const std::string& output_symbol_name) {
  // int index = 0;
  // for (const std::string& op : model_->net_.ListOutputs()) {
  //   if (op == output_symbol_name) {
  //     return index;
  //   } else {
  //     index++;
  //   }
  // }
  // //throw std::runtime_error("The output symbol name can not be found");
  // return index;
  return 0;
}


/*
 * The function finds the closest bucket for the given num_words in the input line.
 * If the exact bucket key exists, function returns that bucket key.
 * If the matching bucket key does not exist, function looks for the next bucket key
 * that is greater than given num_words.
 * If the next larger bucket does not exist, function returns the largest bucket key.
 */
int MXNetPredictor::GetClosestBucketKey(int num_words) {
  // int closest_bucket_key = model_->highest_bucket_key_;

  // if (model_->executor_buckets_.lower_bound(num_words) != model_->executor_buckets_.end()) {
  //   closest_bucket_key = model_->executor_buckets_.lower_bound(num_words)->first;
  // }
  // return closest_bucket_key;
  return 0;
}

}