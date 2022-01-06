// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_MODULE_MODULE_LOADER_H_
#define MUMBA_DOMAIN_MODULE_MODULE_LOADER_H_

#include <memory>
#include <queue>

#include "base/uuid.h"
#include "base/memory/weak_ptr.h"
#include "base/memory/ref_counted.h"
#include "base/files/file_path.h"
#include "base/single_thread_task_runner.h"
#include "mojo/public/cpp/system/buffer.h"
#include "core/domain/module/executable.h"
#include "core/shared/common/mojom/module.mojom.h"
#include "storage/proto/storage.pb.h"

namespace domain {
class Module;
class P2PSocketDispatcher;
class StorageContext;
class DomainContext;

enum ModuleType {
  kMOD_TYPE_NATIVE_LIBRARY = 0,
};

struct ModuleParams {
  ModuleType type;
  storage_proto::ExecutableArchitecture format;
  std::string name;
  base::UUID uuid;
  base::FilePath root;
  base::FilePath path;
  bool in_memory = false;
};

class ModuleLoader {
public:
  ModuleLoader(const base::FilePath& root_path);
  ~ModuleLoader();

  scoped_refptr<DomainContext> context() const {
    return context_;
  }

  Module* active_module() const {
    return active_module_;
  }

  void Init(scoped_refptr<DomainContext> context, 
    P2PSocketDispatcher* dispatcher, 
    scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> io_task_runner);

  void Load(const ModuleParams& params);
  void Shutdown();

  void LoadModules();

private:

  void LoadModuleImpl(const ModuleParams& params);
  void UnloadModuleImpl(const std::string& name);

  void AddModule(std::unique_ptr<Module> module);
  std::unique_ptr<Module> RemoveModule(const std::string& name);

  Module* GetCachedModule(const std::string& name) const;

  //void LoadImpl(const std::string& name);
  void OnStorageContextCreated(scoped_refptr<StorageContext> context);

  void OnModuleDataAvailable(const ModuleParams& params, int status, mojo::ScopedSharedBufferHandle data, int size);

  void LoadModuleFromMemory(const ModuleParams& params, mojo::ScopedSharedBufferHandle data, int data_size);
  void LoadModuleFromFilesystem(const ModuleParams& params);
  void LoadModuleInternal(const ModuleParams& params, Executable::InitParams executable_params);
  Module* CreateModule(const ModuleParams& params);

  base::FilePath root_path_;

  scoped_refptr<DomainContext> context_;

  scoped_refptr<StorageContext> storage_context_;

  scoped_refptr<base::SingleThreadTaskRunner> background_task_runner_;
   
  std::vector<std::unique_ptr<Module>> modules_;

  bool initialized_;
  bool clean_shutdown_;

  P2PSocketDispatcher* dispatcher_;

  scoped_refptr<base::SingleThreadTaskRunner> main_task_runner_;
  scoped_refptr<base::SingleThreadTaskRunner> io_task_runner_;

  std::unique_ptr<Executable> executable_;

  Module* active_module_;

  base::WeakPtrFactory<ModuleLoader> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(ModuleLoader);
};

}

#endif