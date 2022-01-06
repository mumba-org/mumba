// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_WEB_HELPER_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_WEB_HELPER_H_

#include "core/shared/common/content_export.h"

#include "base/logging.h"
#include "base/macros.h"
#include "base/bind.h"
#include "base/callback.h"
#include "base/callback_forward.h"
#include "base/callback_internal.h"
#define INSIDE_BLINK 1
#include "third_party/blink/renderer/platform/wtf/assertions.h"
#include "third_party/blink/renderer/platform/wtf/compiler.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/public/platform/web_common.h"
#include "third_party/blink/public/platform/web_cursor_info.h"
#include "third_party/blink/public/platform/web_private_ptr.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/platform/web_url_response.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/renderer/core/events/message_event.h"
#include "third_party/blink/renderer/core/workers/dedicated_worker.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/core/workers/worker_native_client.h"
#include "third_party/blink/renderer/platform/heap/handle.h"
#include "third_party/blink/renderer/platform/wtf/type_traits.h"
#include "third_party/blink/public/platform/modules/serviceworker/web_service_worker_network_provider.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/transferables.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_service_worker_registration.h"
#include "core/shared/common/service_worker/service_worker_provider_host_info.h"
#include "core/shared/common/service_worker/service_worker_utils.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_object.mojom.h"
#include "third_party/blink/public/platform/modules/serviceworker/web_service_worker_network_provider.h"
#include "third_party/blink/renderer/modules/serviceworkers/service_worker_container.h"
#include "third_party/blink/renderer/modules/serviceworkers/service_worker.h"
#include "third_party/blink/renderer/modules/serviceworkers/extendable_message_event.h"
#include "third_party/blink/renderer/modules/serviceworkers/service_worker_registration.h"
#include "runtime/MumbaShims/WebDefinitions.h"

class CONTENT_EXPORT MessageEventListenerImpl : public blink::EventListener {
public:  
  MessageEventListenerImpl(void* state, void(*on_event)(void *, void *, void **, int, void **, int));
  ~MessageEventListenerImpl() override;

  bool operator==(const blink::EventListener& other) const override {
    return this == &other;
  }
  void handleEvent(blink::ExecutionContext* context, blink::Event* event) override;
  bool BelongsToTheCurrentWorld(blink::ExecutionContext* context) const override;

private:
  //scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
  void* state_;
  void(*on_event_)(void *, void *, void **, int, void **, int);
};

class CONTENT_EXPORT ExtendableMessageEventListenerImpl : public blink::EventListener {
public:  
  ExtendableMessageEventListenerImpl(void* state, void(*on_event)(void *, void *, void **, int, void **, int));
  ~ExtendableMessageEventListenerImpl() override;

  bool operator==(const blink::EventListener& other) const override {
    return this == &other;
  }
  void handleEvent(blink::ExecutionContext* context, blink::Event* event) override;
  bool BelongsToTheCurrentWorld(blink::ExecutionContext* context) const override;

private:
  //scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
  void* state_;
  void(*on_event_)(void *, void *, void **, int, void **, int);
};

enum WorkerNativeClientType {
  kWorkerNativeClientTypeWorker = 0,
  kWorkerNativeClientTypeServiceWorker = 1
};

class CONTENT_EXPORT WorkerNativeClientImpl : public blink::WorkerNativeClient {
public:
  struct Bag {
    blink::WeakMember<blink::WorkerGlobalScope> global;
    blink::Member<MessageEventListenerImpl> message_listener;
    blink::Member<ExtendableMessageEventListenerImpl> extendable_message_listener;
  };

  WorkerNativeClientImpl(WorkerNativeClientType type, void* state, const WorkerNativeClientCallbacks& callbacks);
  ~WorkerNativeClientImpl() override;

  int thread_id() const {
    return thread_id_;
  }

  bool initialized() const {
    return initialized_;
  }

  blink::WorkerGlobalScope* worker_global_scope() const {
    return bag_->global.Get();
  }

  blink::EventListener* GetEventListener(blink::WorkerGlobalScope* global) override;
  void OnWorkerInit(blink::WorkerGlobalScope* global) override;
  void OnWorkerTerminate() override;

private:
  WorkerNativeClientType type_;
  int thread_id_;
  bool initialized_;
  std::unique_ptr<Bag> bag_;
  void* state_;
  WorkerNativeClientCallbacks callbacks_;
};

#endif