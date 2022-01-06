// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/execution/execution_engine.h"

#include "base/task_scheduler/post_task.h"
//#include "db/sqlite3.h"
//#include "gin/public/isolate_holder.h"
//#include "gin/public/v8_platform.h"
//#include "gin/array_buffer.h"
//#include "gin/v8_initializer.h"
#include "core/shared/domain/storage/namespace.h"
//#include "core/domain/execution/execution_context.h"
#include "core/domain/execution/execution_module.h"
//#include "core/domain/execution/library.h"
//#include "core/domain/execution/native/native_function.h"
//#include "core/domain/execution/native/native_library.h"
#include "core/domain/execution/engine_client.h"
//#include "disk/disk.h"
//#include "disk/bundle_manifest.h"
//#include "disk/executable.h"
//#include "disk/executable_flags.h"
#include "data/array.h"
#include "data/builder.h"
#include "data/record_batch.h"
#include "data/table.h"
#include "data/table_builder.h"
#include "data/type.h"
#include "core/common/query/query_encoder.h"

namespace domain {

namespace {

disk::Architecture GetCurrentArchitecture() {
#if defined(OS_LINUX)  
  return disk::Architecture::kLINUX_ELF_X86_64;
#endif
}

}


ExecutionEngine::ExecutionEngine():
  //background_task_runner_(
  //    base::CreateSingleThreadTaskRunnerWithTraits(
  //      { base::MayBlock(), 
  //        base::TaskPriority::BACKGROUND })),
  initialized_(false),
  weak_factory_(this)  {
  
}

ExecutionEngine::~ExecutionEngine() {

}

void ExecutionEngine::Initialize() {
 // base::
  //background_task_runner_->PostTask(
  base::PostTask(
    FROM_HERE,
    base::BindOnce(
      &ExecutionEngine::InitializeImpl,
      base::Unretained(this)));
}

void ExecutionEngine::Shutdown() {

  // for (auto it = contexts_.begin(); it != contexts_.end(); ++it) {
  //   (*it)->Shutdown();
  //   delete *it;
  // }

  for (auto it = modules_.begin(); it != modules_.end(); ++it) {
    (*it)->Unload();
    delete *it;
  }

  //contexts_.clear();
  
  modules_.clear();

 // isolate_holder_.reset();
}

// ExecutionContext* ExecutionEngine::CreateContext() {
//   //DCHECK(isolate_holder_->isolate());
//   ExecutionContext* context = new 
//     ExecutionContext(
//       weak_factory_.GetWeakPtr(), 
//       isolate_holder_->isolate());

//   contexts_.push_back(context);
  
//   return context;
// }

void ExecutionEngine::InitializeImpl() {
//  printf("ExecutionEngine::InitializeImpl\n");

// #ifdef V8_USE_EXTERNAL_STARTUP_DATA
//   gin::V8Initializer::LoadV8Snapshot();
//   gin::V8Initializer::LoadV8Natives();
// #endif
//   //gin::V8Platform* platform = gin::V8Platform::Get();
//   //DLOG(INFO) << "platform: " << platform;
//   //v8::V8::InitializePlatform(platform);

//   gin::IsolateHolder::Initialize(
//     gin::IsolateHolder::kStrictMode,
//     gin::IsolateHolder::kStableV8Extras,
//     gin::ArrayBufferAllocator::SharedInstance());

//   isolate_holder_.reset(
//     new gin::IsolateHolder(background_task_runner_, 
//       gin::IsolateHolder::kUseLocker, 
//       //gin::IsolateHolder::kSingleThread,
//       gin::IsolateHolder::kAllowAtomicsWait));

//   //DLOG(INFO) << "isolate: " << isolate_holder_->isolate();
  
  // create a 'zero' context
  //ExecutionContext* context = CreateContext();
  //printf("ExecutionContext* context ? %d\n", context != nullptr);
  
  //context->CallHello();
  //CreateContext();
  //disk::Init();
  //sqlite3_initialize();
  initialized_ = true;
}

void ExecutionEngine::LoadModule(Namespace* ns, const std::string& name) {
  base::PostTaskWithTraits(
  //background_task_runner_->PostTask(//WithTraits(
    FROM_HERE,
    { base::MayBlock() },
    base::BindOnce(
      &ExecutionEngine::LoadModuleImpl,
      base::Unretained(this),
      base::Unretained(ns),
      name));
}

void ExecutionEngine::UnloadModule(const std::string& name) {
   base::PostTaskWithTraits(
   //background_task_runner_->PostTask(//WithTraits( 
    FROM_HERE,
    { base::MayBlock() },
    base::BindOnce(
      &ExecutionEngine::UnloadModuleImpl,
      base::Unretained(this),
      name));
}

//void ExecutionEngine::SendEventForTest() {

//}

bool ExecutionEngine::ExecuteQuery(
  int32_t id, 
  const std::string& address, 
  const std::string& encoded_query, 
  std::string* encoded_reply) {
 
  auto f0 = data::CreateField("id", data::int32());
  auto f1 = data::CreateField("name", data::utf8());
  
  std::vector<std::shared_ptr<data::Field>> fields = {f0, f1};
  std::shared_ptr<data::Schema> schema = std::make_shared<data::Schema>(fields);

  std::vector<int32_t> f0_values = {1001, 2002, 3003, 4004};
  std::vector<std::string> f1_values = {"joao quintana", "lucia corneta", "geronimo hamburger", "james johnson"};

  std::shared_ptr<data::Array> f0_array;
  std::shared_ptr<data::Array> f1_array;

  data::Int32Builder int_builder;
  data::StringBuilder str_builder;

  data::Status ok;
  
  for (auto& val : f0_values) {
    ok = int_builder.Append(val);
  }

  ok = int_builder.Finish(&f0_array);
  if (!ok.ok()) {
    return false;
  }

  for (auto& val : f1_values) {
    ok = str_builder.Append(val);
  }

  ok = str_builder.Finish(&f1_array);

  if (!ok.ok()) {
    return false;
  }

  std::vector<std::shared_ptr<data::Array>> data;
  data.push_back(f0_array);
  data.push_back(f1_array);

  std::shared_ptr<data::RecordBatch> result = data::RecordBatch::Make(schema, 4, std::move(data));

  if (!result) {
    return false;
  }

  common::QueryEncoder encoder;
  protocol::QueryReply query_reply;
 
  query_reply.set_reply_id(id);
  query_reply.set_status(protocol::QueryReply::STATUS_OK);

  scoped_refptr<net::IOBufferWithSize> encoded_data = encoder.EncodeBatchReply(&query_reply, result);
  if (!encoded_data) {
    return false;
  }
  
  encoded_reply->assign(reinterpret_cast<const char *>(encoded_data->data()), encoded_data->size());

  return true;
}

void ExecutionEngine::LoadModuleImpl(Namespace* ns, const std::string& name) {
  ExecutionModule* module = GetCachedModule(name);

  if (module) {
    return;
  }

  disk::Disk* disk = ns->disk();
  if (!disk) {
    LOG(ERROR) << "Loading module '" << name << "' error. disk is null";
    return;
  }

  disk::Architecture arch = GetCurrentArchitecture();
  
  if (!disk->SupportsArch(arch)) {
   LOG(ERROR) << "Loading module '" << name << "' error. Your architecture is not supported by the executable";
   // TODO: list the supported archs
   return; 
  }

  disk::DiskManifest* manifest = disk->manifest();

  if (!manifest) {
    LOG(ERROR) << "Loading module '" << name << "' error. no manifest for disk";
    return;
  }

  const std::vector<std::string>& executables = manifest->GetExecutables();
  if (executables.size() == 0) {
    LOG(ERROR) << "Loading module '" << name << "' error. no executables listed on manifest";
    return;
  }

  const std::string& engine_executable = executables[0];

  LOG(INFO) << "trying to load " << engine_executable << " from disk executable ...";

  disk::Executable* exec = disk->GetExecutable(base::FilePath(engine_executable));

  if (!exec) {
    LOG(ERROR) << "Loading module '" << name << "' error. Loading executable '" << engine_executable << "' on disk failed";
    return; 
  }

  module = new ExecutionModule(ns, name, exec);
  AddModule(module);
  module->Load();

  // NativeLibrary* lib = static_cast<NativeLibrary*>(Library::LoadLibraryFromName(ns, name, Library::kNative));
  
  // if (lib) {
  //   //DLOG(INFO) << "isolate: " << isolate_holder_->isolate();
  //   // TODO: check if v8 will have any problem with thread affinity
  //   //ExecutionContext* context = CreateContext();
  //   ExecutionModule* module = new ExecutionModule(ns, lib);//context, lib);
  //   AddModule(module);
  //   module->Load();
  // } else {
  //   //DLOG(INFO) << "library \"" << name << "\" not found";
  // }
}

void ExecutionEngine::UnloadModuleImpl(const std::string& name) {
  ExecutionModule* module = RemoveModule(name);
  if (module) {
    module->Unload();
    delete module;
  }
}

void ExecutionEngine::AddModule(ExecutionModule* module) {
  modules_.push_back(module);
}

ExecutionModule* ExecutionEngine::RemoveModule(const std::string& name) {
  bool found = false;
  ExecutionModule* reference = nullptr;
  
  auto it = modules_.begin();
  
  for (; it != modules_.end(); ++it) {
    if ((*it)->name() == name) {
      found = true;
      break;
    }
  }

  if (found) {
    reference = *it;
    modules_.erase(it);
  }

  return reference;
}

ExecutionModule* ExecutionEngine::GetCachedModule(const std::string& name) {
  for (auto it = modules_.begin(); it != modules_.end(); it++) {
    if ((*it)->name() == name) {
      return *it;
    }
  }
  return nullptr;
}

// void ExecutionEngine::SendEventForTestImpl() {
//   ExecutionModule* mod = GetCachedModule("hello");
//   if (mod) {
//     mod->SendEventForTest();
//   }
// }

}