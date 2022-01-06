// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/common/web_helper.h"

MessageEventListenerImpl::MessageEventListenerImpl(void* state, void(*on_event)(void *, void *, void **, int, void **, int)):
    EventListener(blink::EventListener::kCPPEventListenerType),
    state_(state),
    on_event_(on_event) {}
  
MessageEventListenerImpl::~MessageEventListenerImpl() {

}

bool MessageEventListenerImpl::BelongsToTheCurrentWorld(blink::ExecutionContext* context) const {
  return true;
}

void MessageEventListenerImpl::handleEvent(blink::ExecutionContext* context, blink::Event* event) {
  blink::MessageEvent* message_event = static_cast<blink::MessageEvent*>(event);
  blink::MessagePortArray ports = message_event->ports();
  int port_count = ports.size();
  blink::MessagePort* port_refs[port_count];
  for (int i = 0; i < port_count; ++i) {
    port_refs[i] = ports[i].Get();
  }
  on_event_(state_, event, reinterpret_cast<void**>(&port_refs), port_count, nullptr, 0);
}

ExtendableMessageEventListenerImpl::ExtendableMessageEventListenerImpl(void* state, void(*on_event)(void *, void *, void **, int, void **, int)):
    EventListener(blink::EventListener::kCPPEventListenerType),
    state_(state),
    on_event_(on_event) {}
  
ExtendableMessageEventListenerImpl::~ExtendableMessageEventListenerImpl() {

}

bool ExtendableMessageEventListenerImpl::BelongsToTheCurrentWorld(blink::ExecutionContext* context) const {
  return true;
}

void ExtendableMessageEventListenerImpl::handleEvent(blink::ExecutionContext* context, blink::Event* event) {
  blink::ExtendableMessageEvent* message_event = static_cast<blink::ExtendableMessageEvent*>(event);
  blink::MessagePortArray ports = message_event->ports();
  int port_count = ports.size();
  blink::MessagePort* port_refs[port_count];
  for (int i = 0; i < port_count; ++i) {
    port_refs[i] = ports[i].Get();
  }
  on_event_(state_, event, reinterpret_cast<void**>(&port_refs), port_count, nullptr, 0);
}

WorkerNativeClientImpl::WorkerNativeClientImpl(WorkerNativeClientType type, void* state, const WorkerNativeClientCallbacks& callbacks): 
    type_(type),
    thread_id_(-1),
    initialized_(false),
    state_(state),
    callbacks_(callbacks) {

}

WorkerNativeClientImpl::~WorkerNativeClientImpl() {

}

blink::EventListener* WorkerNativeClientImpl::GetEventListener(blink::WorkerGlobalScope* global) {
  if (type_ == kWorkerNativeClientTypeWorker && !bag_->message_listener) {
    bag_->message_listener = new MessageEventListenerImpl(state_, callbacks_.OnMessage);
    return bag_->message_listener.Get();
  }
  if (type_ == kWorkerNativeClientTypeServiceWorker && !bag_->extendable_message_listener) {
    bag_->extendable_message_listener = new ExtendableMessageEventListenerImpl(state_, callbacks_.OnMessage);
    return bag_->extendable_message_listener.Get();
  }
  return nullptr;
}

void WorkerNativeClientImpl::OnWorkerInit(blink::WorkerGlobalScope* global) {
  // its important to only create these on the worker thread
  thread_id_ = base::PlatformThread::CurrentId();
  bag_ = std::make_unique<Bag>();
  bag_->global = global;
  callbacks_.OnInit(state_, global);
  initialized_ = true;
}

void WorkerNativeClientImpl::OnWorkerTerminate() {
  callbacks_.OnTerminate(state_);
}