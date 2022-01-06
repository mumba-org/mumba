// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/execution/execution_module.h"

#include "base/task_scheduler/post_task.h"
//#include "core/domain/execution/library.h"
//#include "core/domain/execution/native/native_library.h"
//#include "core/domain/execution/native/native_function.h"
//#include "core/domain/execution/event_queue.h"
//#include "disk/executable.h"
#include "runtime/MumbaShims/EngineShims.h"

namespace domain {

ExecutionModule::ExecutionModule(Namespace* ns, const std::string& name, disk::Executable* exe):
 executable_(exe),
 name_(name),
 engine_context_(this, ns),
 client_(nullptr) {

}

ExecutionModule::~ExecutionModule() {

}

const std::string& ExecutionModule::name() const {
  return name_;
}

void ExecutionModule::Load() {
  base::AutoLock lock(client_mutex_);
  
  auto init_callback = executable_->Bind<void()>("mainInit");
  if (init_callback) {
    std::move(init_callback).Call();
    auto get_callback = executable_->Bind<EngineClient*()>("mainGetClient");
    if (get_callback) {
      client_ = std::move(get_callback).Call();
    }
  } else {
    //DLOG(ERROR) << "function \"mainInit\" in \"" << name_ << "\" not found";
  }
  if (client_) {
    client_->OnInit(&engine_context_);
    //EventQueue* queue = client_->event_queue();
    //DCHECK(queue);
    //queue->task_runner()->PostTask(
    //  FROM_HERE, 
    //  base::BindOnce(&EngineClient::OnRun, base::Unretained(client_)));
  }
}

void ExecutionModule::Unload() {
  base::AutoLock lock(client_mutex_);
  if (client_) {
    // send the exit loop mesage first
  //  EventQueue* queue = client_->event_queue();
   //  Event* message = new Event(EventType::kCONTROL_QUEUE_SHUTDOWN);
   //  queue->Push(message);
    // TODO: this ref is not thread safe and the client module
    //       also has a reference to it, so we might get in trouble here ...
    //       how to lock?
    //EventLoop* loop = client_->event_loop();
    //loop->Shutdown();
    client_->OnShutdown();
    client_ = nullptr;
  }  
  
  auto unload_callback = executable_->Bind<void()>("mainDestroy");
  if (unload_callback) {
    std::move(unload_callback).Call();
  } else {
    //DLOG(ERROR) << "function \"mainDestroy\" in \"" << name_ << "\" not found";
  }
}

//void ExecutionModule::SendEventForTest() {
  // base::AutoLock lock(client_mutex_);
  // if (client_) {
  //   printf("ExecutionModule::SendEventForTest: sending some event..\n");
  //   EventQueue* queue = client_->event_queue();
  //   Event* message = nullptr;
  //   if (event_count_ == 0) {
  //     message = new Event(EventType::kCALL_BEGIN);
  //   } else if (event_count_ == 1) {
  //     message = new Event(EventType::kCALL_END);
  //   } else {
  //     message = new Event(EventType::kCONTROL_QUEUE_SHUTDOWN);
  //   }
  //   queue->Push(message);
  //   event_count_++;
  // }
//}

void ExecutionModule::OnBind(const std::string& concept_name, ConceptNode::Handler* handler) {
  // base::AutoLock lock(client_mutex_);
  // if (client_) {
  //   EventLoop* loop = client_->event_loop();
  //   EventMessage* message = new EventMessage(EventType::kBindHandler);
  //   loop->PushEvent(message);
  // }
}

void ExecutionModule::OnStateChanged(ConceptNode* concept, ConceptState new_state) {
  // base::AutoLock lock(client_mutex_);
  // if (client_) {
  //   EventLoop* loop = client_->event_loop();
  //   EventMessage* message = new EventMessage(new_state == ConceptState::Up ? EventType::kConceptUp : EventType::kConceptDown);
  //   loop->PushEvent(message);
  // }
}

void ExecutionModule::OnSub(ConceptNode* concept, StreamSession* session) {
  // base::AutoLock lock(client_mutex_);
  // if (client_) {
  //   EventLoop* loop = client_->event_loop();
  //   // TODO: attach the session
  //   EventMessage* message = new EventMessage(EventType::kConceptSub);
  //   loop->PushEvent(message);
  // }
}

void ExecutionModule::OnUnsub(ConceptNode* concept, StreamSession* session) {
  // base::AutoLock lock(client_mutex_);
  // if (client_) {
  //   EventLoop* loop = client_->event_loop();
  //   // TODO: attach the session
  //   EventMessage* message = new EventMessage(EventType::kConceptUnsub);
  //   loop->PushEvent(message);
  // }
}

}