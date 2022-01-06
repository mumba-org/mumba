// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_V8_ENGINE_H__
#define MUMBA_RUNTIME_MUMBA_SHIMS_V8_ENGINE_H__

#include <memory>

#include "base/macros.h"
#include "base/synchronization/waitable_event.h"
#include "base/memory/singleton.h"
#include "base/threading/thread.h"
#include "base/single_thread_task_runner.h"
#include "v8/include/v8.h"

namespace gin {
class IsolateHolder;
}

namespace mumba {
class V8Context;

// class ArrayBufferAllocator : public v8::ArrayBuffer::Allocator {
// public:
//  ArrayBufferAllocator();
//  ~ArrayBufferAllocator() override;
//  void* Allocate(size_t length) override;
//  void* AllocateUninitialized(size_t length) override;
//  void Free(void* data, size_t) override;
// };

class V8Engine {
public:

 static V8Engine* GetInstance();

 V8Engine();
 ~V8Engine();

 v8::Isolate* isolate() const;// { return isolate_; }

 bool Init();
 void Shutdown();

 scoped_refptr<base::SingleThreadTaskRunner> vm_task_runner() const {
    return vm_thread_.task_runner();
 }

 V8Context* CreateContext(v8::Local<v8::ObjectTemplate> global);
 V8Context* CreateContext();

private:

  void InitVM(base::WaitableEvent* wait_event);
  void ShutdownVM(base::WaitableEvent* wait_event);

  void CreateContextImpl(base::WaitableEvent* wait_event, V8Context** result);
  void CreateContextWithGlobal(v8::Local<v8::ObjectTemplate> global, base::WaitableEvent* wait_event, V8Context** result);
 //friend class base::Singleton<V8Engine>;
 //friend struct base::DefaultSingletonTraits<V8Engine>;

 //v8::Isolate* isolate_;

 std::unique_ptr<gin::IsolateHolder> isolate_holder_;

 //scoped_refptr<base::SingleThreadTaskRunner> background_task_runner_;
 base::Thread vm_thread_;
 
 //ArrayBufferAllocator* allocator_;
 
 // TODO: implement this later
 //scoped_ptr<PerIsolateData> isolate_data_;
 //std::unique_ptr<v8::Platform> platform_;

 DISALLOW_COPY_AND_ASSIGN(V8Engine);
};

}

#endif
