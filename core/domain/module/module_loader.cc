// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/module/module_loader.h"

#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "base/sha1.h"
#include "base/strings/string_number_conversions.h"
#include "core/domain/module/executable.h"
#include "core/domain/module/native_module.h"
#include "core/domain/module/executable.h"
#include "core/domain/module/native_executable.h"
#include "core/domain/domain_context.h"
#include "core/shared/domain/storage/storage_context.h"
#include "core/shared/domain/storage/data_storage.h"
#include "core/shared/domain/storage/file_storage.h"
#include "core/shared/domain/module/module_client.h"
#include "storage/storage_utils.h"
#include "storage/storage_constants.h"

namespace domain {

namespace {

storage_proto::ExecutableArchitecture GetCurrentArchitecture() {
#if defined(OS_LINUX) && defined(ARCH_CPU_X86_64)
  return storage_proto::LINUX_X86_64;
#elif defined(OS_WIN) && defined(ARCH_CPU_X86_64)
  return storage_proto::WINDOWS_X86_64;
#endif
}

}

ModuleLoader::ModuleLoader(const base::FilePath& root_path):
  root_path_(root_path),
  background_task_runner_(
      base::CreateSingleThreadTaskRunnerWithTraits(
        { base::MayBlock(), 
          base::TaskPriority::BACKGROUND })),
  initialized_(false),
  clean_shutdown_(false),
  dispatcher_(nullptr),
  active_module_(nullptr),
  weak_factory_(this)  {
  
}

ModuleLoader::~ModuleLoader() {
  if (!clean_shutdown_) {
    for (auto it = modules_.begin(); it != modules_.end(); ++it) {
      (*it)->Unload();
    }
    modules_.clear();  
  }
}

void ModuleLoader::Load(const ModuleParams& params) {
  background_task_runner_->PostTask(
    FROM_HERE,
    base::BindOnce(
      &ModuleLoader::LoadModuleImpl,
      base::Unretained(this),
      params));
}

void ModuleLoader::Shutdown() {
  for (auto it = modules_.begin(); it != modules_.end(); ++it) {
    (*it)->Unload();
  }
  modules_.clear();

  active_module_ = nullptr;
  main_task_runner_ = nullptr;
  background_task_runner_ = nullptr; 
  clean_shutdown_ = true;
}

void ModuleLoader::Init(scoped_refptr<DomainContext> context, 
  P2PSocketDispatcher* dispatcher, 
  scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
  scoped_refptr<base::SingleThreadTaskRunner> io_task_runner) {
  dispatcher_ = dispatcher;
  main_task_runner_ = main_task_runner;
  io_task_runner_ = io_task_runner;
  context_ = context;
}

void ModuleLoader::LoadModules() {
  storage_context_ = context_->storage_manager()->CreateContext(
      base::Bind(&ModuleLoader::OnStorageContextCreated, 
               base::Unretained(this)));
}

void ModuleLoader::LoadModuleImpl(const ModuleParams& params) { 
  if (params.in_memory) {
    storage_context_->file().ReadFileOnce(
      context_->name(),
#if defined(OS_WIN)
      base::UTF16ToASCII(params.path.value()),
#else
      params.path.value(),
#endif
      0, // offset
      -1, // size 
      base::Bind(&ModuleLoader::OnModuleDataAvailable, base::Unretained(this), params));
  } else {
    LoadModuleFromFilesystem(params);
  }
}

void ModuleLoader::UnloadModuleImpl(const std::string& name) {
  std::unique_ptr<Module> module = RemoveModule(name);
  if (module) {
    module->Unload();
  }
  active_module_ = nullptr;
}

void ModuleLoader::AddModule(std::unique_ptr<Module> module) {
  modules_.push_back(std::move(module));
}

std::unique_ptr<Module> ModuleLoader::RemoveModule(const std::string& name) {
  bool found = false;
  std::unique_ptr<Module> reference;
  
  auto it = modules_.begin();
  
  for (; it != modules_.end(); ++it) {
    if ((*it)->name() == name) {
      found = true;
      break;
    }
  }

  if (found) {
    reference = std::move(*it);
    modules_.erase(it);
  }

  return reference;
}

Module* ModuleLoader::GetCachedModule(const std::string& name) const {
  for (auto it = modules_.begin(); it != modules_.end(); it++) {
    if ((*it)->name() == name) {
      return it->get();
    }
  }
  return nullptr;
}

void ModuleLoader::OnStorageContextCreated(scoped_refptr<StorageContext> context) {
  // TODO: better to parse the manifest and understand who is realy our target
  // eg. should we load a DLL, a bitcode?

  // we could parse and pass to the executor which engine to load
  // if native, or script, etc..

  // on idea is to create a struct with much more details
  // of how this should be run

  // by the way, the scripts or VM types, could be a two step process
  // where first it loads the native dll and than the execution context

  // we can try a LLVM here just for show.. the LLVM executor could be
  // guarded by compiler or runtime directives to not force the user
  // to have LLVM installed on its machine

  // eg. elf_linux_x86_64 => NativeExecution
  //     llvm_x86_64 => LLVMExecution
  //     python_bitcode => Python VM
  ModuleParams params;
  params.type = kMOD_TYPE_NATIVE_LIBRARY;
  std::string type = params.type == kMOD_TYPE_NATIVE_LIBRARY ? "service" : "app"; 
  params.name = params.type == kMOD_TYPE_NATIVE_LIBRARY ? context_->name() + "_" + type : context_->name();
  params.format = GetCurrentArchitecture();
  params.uuid = base::UUID::generate();
  params.in_memory = false;

  base::FilePath exe_path = storage::GetPathForArchitecture(params.name, params.format, params.type == kMOD_TYPE_NATIVE_LIBRARY ? storage_proto::LIBRARY : storage_proto::PROGRAM);
  params.root = root_path_;
#if defined(OS_WIN)
  //params.path = base::FilePath(base::ASCIIToUTF16(type)).Append(exe_path);
  params.path = base::FilePath(exe_path);
#else  
  //params.path = base::FilePath(type).Append(exe_path);
  params.path = base::FilePath(exe_path);
#endif

  Load(params);
}

void ModuleLoader::OnModuleDataAvailable(const ModuleParams& params, int status, mojo::ScopedSharedBufferHandle data, int size) {
  if (status == 0) { 
    LoadModuleFromMemory(params, std::move(data), size);    
  } else {
    LOG(ERROR) << "Loading module '" << params.name << "' error. failed opening application";
  }
}

void ModuleLoader::LoadModuleFromMemory(const ModuleParams& params, mojo::ScopedSharedBufferHandle data, int data_size) {
  Executable::InitParams executable_params;
  executable_params.in_memory = true;
  executable_params.data = std::move(data);
  executable_params.data_size = data_size;
  LoadModuleInternal(params, std::move(executable_params));
}

void ModuleLoader::LoadModuleFromFilesystem(const ModuleParams& params) {
  Executable::InitParams executable_params;
  executable_params.in_memory = false;
  executable_params.path = params.root.Append(params.path);
  LoadModuleInternal(params, std::move(executable_params));
}

void ModuleLoader::LoadModuleInternal(const ModuleParams& params, Executable::InitParams executable_params) {
  if (GetCachedModule(params.name)) {
    return;
  }  
  Module* module = CreateModule(params);
  if (!module) {
    LOG(ERROR) << "Loading module '" << params.name << "' error. module creation failed"; 
    return;
  }  
  if (!module->Load(std::move(executable_params))) {
    LOG(ERROR) << "Loading module '" << params.name << "' error. module initialization failed"; 
  }
  active_module_ = module;
  initialized_ = true;
}

Module* ModuleLoader::CreateModule(const ModuleParams& params) {
  Module* module = nullptr;
  // FIX to support the other kinds of modules
  if (params.type == kMOD_TYPE_NATIVE_LIBRARY) {
    std::unique_ptr<NativeModule> owned_module = std::make_unique<NativeModule>(context_, params.uuid, params.name, dispatcher_, main_task_runner_, io_task_runner_, background_task_runner_);
    module = owned_module.get();
    AddModule(std::move(owned_module));
  }
  return module;
}

}