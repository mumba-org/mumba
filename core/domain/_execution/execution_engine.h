// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_EXECUTION_EXECUTION_ENGINE_H_
#define MUMBA_DOMAIN_EXECUTION_EXECUTION_ENGINE_H_

#include <memory>
#include <queue>

//#include "lib/base/macros.h"
#include "base/memory/weak_ptr.h"
#include "base/files/file_path.h"
#include "base/single_thread_task_runner.h"

//#include <v8.h>


//namespace gin {
//class IsolateHolder;
//}

namespace domain {
class ExecutionModule;
//class ExecutionContext;
//class Library;
class Namespace;

class ExecutionEngine {
public:
  ExecutionEngine();
  ~ExecutionEngine();

  void Initialize();
  void Shutdown();

  //ExecutionContext* CreateContext();

  void LoadModule(Namespace* ns, const std::string& name);
  void UnloadModule(const std::string& name);

  //void SendEventForTest();

  bool ExecuteQuery(int32_t id, const std::string& address, const std::string& encoded_query, std::string* encoded_reply);

private:

  void LoadModuleImpl(Namespace* ns, const std::string& name);
  void UnloadModuleImpl(const std::string& name);

  //void SendEventForTestImpl();

  void AddModule(ExecutionModule* module);
  ExecutionModule* RemoveModule(const std::string& name);

  ExecutionModule* GetCachedModule(const std::string& name);

  void InitializeImpl();

   // This was needed for V8 isolate thread affinity
   // we dont need it anymore

  //scoped_refptr<base::SingleThreadTaskRunner> background_task_runner_;
   
  //std::unique_ptr<gin::IsolateHolder> isolate_holder_;

  //std::vector<ExecutionContext*> contexts_;

  std::vector<ExecutionModule*> modules_;

  bool initialized_;

  base::WeakPtrFactory<ExecutionEngine> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(ExecutionEngine);
};

}

#endif