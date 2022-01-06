// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ChannelRegistryShims.h"
#include "EngineHelper.h"

#include "base/sha1.h"
#include "base/strings/utf_string_conversions.h"
#include "base/strings/string_number_conversions.h"
#include "base/single_thread_task_runner.h"
#include "core/shared/domain/module/module_state.h"
#include "core/shared/domain/application/application.h"
#include "core/shared/application/application_thread.h"
#include "core/shared/application/application_process.h"
#include "core/shared/common/mojom/channel.mojom.h"
#include "core/shared/common/service_manager/service_manager_connection_impl.h"
#include "core/shared/common/child.mojom.h"
#include "core/shared/common/connection_filter.h"
#include "core/shared/common/service_names.mojom.h"
#include "mojo/public/cpp/bindings/binding_set.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/system/message_pipe.h"
#include "services/service_manager/embedder/embedded_service_runner.h"
#include "services/service_manager/public/cpp/service.h"
#include "services/service_manager/public/cpp/service_context.h"
#include "services/service_manager/public/mojom/constants.mojom.h"
#include "services/service_manager/public/mojom/service_factory.mojom.h"
#include "core/shared/common/blink_cloneable_message.h"

#include "WebStructsPrivate.h"

struct ChannelHaveCallbackState {
  void* state;
  void(*cb)(void*, int);
};

struct ChannelConnectCallbackState {
  void* state;
  void(*cb)(void*, int, void*);
};

struct ChannelMessageCallbackState {
  void* state;
  void(*cb)(void*, void*);
};

struct ChannelLookupCallbackState {
  void* state;
  void(*cb)(void*, int, const char*, const char*, const char*);
};

struct ChannelListCallbackState {
  void* state;
  void(*cb)(void*, int, int, const char**, const char**, const char**);
};

void OnStatusChannelResult(ChannelHaveCallbackState cb_state, common::mojom::ChannelStatusCode reply);

struct ChannelClientWrapper : public common::mojom::ChannelClient {
  ChannelClientWrapper(void* state, void(*cb)(void*, void *), scoped_refptr<base::SingleThreadTaskRunner> io_task_runner): 
    state(state), cb(cb), binding(this), task_runner(io_task_runner), weak_factory(this) {}
  ~ChannelClientWrapper() {
    Close();
  }

  void OnMessage(common::CloneableMessage data) override {
    scoped_refptr<blink::SerializedScriptValue> message = blink::SerializedScriptValue::Create(
      reinterpret_cast<const char*>(data.encoded_message.data()), data.encoded_message.size());

    // note: we spect the handler to own this after its called
    SerializedScriptValueWrapper* wrapper = new SerializedScriptValueWrapper(std::move(message));

    task_runner->PostTask(FROM_HERE, base::BindOnce(cb, base::Unretained(state), base::Unretained(wrapper)));
  }

  void OnError() {
    Close();
  }

  void Close() {
    remote_client.reset();
    if (binding.is_bound())
      binding.Close();
  }

  void* state;
  void(*cb)(void*, void*);

  mojo::AssociatedBinding<common::mojom::ChannelClient> binding;
  common::mojom::ChannelClientAssociatedPtr remote_client;
  scoped_refptr<base::SingleThreadTaskRunner> task_runner;
  base::WeakPtrFactory<ChannelClientWrapper> weak_factory;
};

void OnStatusChannelResult(ChannelHaveCallbackState cb_state, common::mojom::ChannelStatusCode reply) {
  //DLOG(INFO) << "ChannelRegistry: OnStatusChannelResult returned with code " << static_cast<int>(reply);
  cb_state.cb(cb_state.state, static_cast<int>(reply));
}

void OnCreateChannelResult(ChannelConnectCallbackState cb_state, ChannelClientWrapper* client, common::mojom::ChannelStatusCode reply) {
  //DLOG(INFO) << "ChannelRegistry: createChannel returned with code " << static_cast<int>(reply) << ". FIXME: the returned entry is a mojo ptr that is deleting itself";
  cb_state.cb(cb_state.state, static_cast<int>(reply), client);
}

void OnGetChannelResult(ChannelLookupCallbackState cb_state, const scoped_refptr<base::SingleThreadTaskRunner>& task_runner, common::mojom::ChannelStatusCode r, common::mojom::ChannelHandlePtr info) {
  if (r == common::mojom::ChannelStatusCode::kCHANNEL_STATUS_OK) {
    cb_state.cb(cb_state.state, static_cast<int>(r), info->uuid.c_str(), info->scheme.c_str(), info->name.c_str());
  } else {
    cb_state.cb(cb_state.state, static_cast<int>(r), nullptr, nullptr, nullptr);
  }
}

void OnHaveChannelResult(ChannelHaveCallbackState cb_state, bool r) {
  cb_state.cb(cb_state.state, r ? 1 : 0);
}

void OnCountChannelsResult(ChannelHaveCallbackState cb_state, uint32_t count) {
  cb_state.cb(cb_state.state, static_cast<int>(count));
}

void OnListChannelsResult(ChannelListCallbackState cb_state, std::vector<common::mojom::ChannelHandlePtr> handles) {
  if (handles.size() > 0) {
    size_t count = handles.size();
    const char* uuids[count];
    const char* names[count];
    const char* schemes[count];
    
    for (size_t i = 0; i < count; ++i) {
      schemes[i] = handles[i]->scheme.c_str();
      names[i] = handles[i]->name.c_str();
      uuids[i] = handles[i]->uuid.c_str();
    }
    cb_state.cb(
      cb_state.state, 
      0,
      count,
      uuids,
      schemes,
      names);
  } else {
    cb_state.cb(cb_state.state, 2, 0, nullptr, nullptr, nullptr);
  }
}

struct ChannelRegistryWrapper {

  ChannelRegistryWrapper(
    common::mojom::ChannelRegistry* registry,
    //service_manager::Connector* connector,
    const scoped_refptr<base::SingleThreadTaskRunner>& task_runner): 
    registry(registry),
    task_runner_(task_runner) {}

  common::mojom::ChannelRegistry* registry;
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
  //service_manager::Connector* connector;

  //common::mojom::ChannelRegistryPtr provider;

  // common::mojom::ChannelRegistryPtr& GetProvider() {
  //   if (!provider.is_bound()) {
  //     connector->BindInterface(common::mojom::kHostServiceName, &provider);
  //   }
  //   return provider;
  // }

  void HaveChannel(std::string scheme, std::string name, ChannelHaveCallbackState cb_state) {
    task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&ChannelRegistryWrapper::HaveChannelImpl, 
        base::Unretained(this),
        base::Passed(std::move(scheme)),
        base::Passed(std::move(name)),
        base::Passed(std::move(cb_state))));
  }

  void HaveChannelByUUID(std::string uuid, ChannelHaveCallbackState cb_state) {
    task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&ChannelRegistryWrapper::HaveChannelByUUIDImpl, 
        base::Unretained(this),
        base::Passed(std::move(uuid)),
        base::Passed(std::move(cb_state))));
  }

  void CountChannels(ChannelHaveCallbackState cb_state) {
    task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&ChannelRegistryWrapper::CountChannelsImpl, 
        base::Unretained(this),
        base::Passed(std::move(cb_state))));
  }

  void LookupChannel(std::string scheme, std::string name, ChannelLookupCallbackState cb_state) {
    task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&ChannelRegistryWrapper::LookupChannelImpl, 
        base::Unretained(this), 
        base::Passed(std::move(scheme)),
        base::Passed(std::move(name)),
        base::Passed(std::move(cb_state))));
  }
  
  void LookupChannelByUUID(std::string uuid, ChannelLookupCallbackState cb_state) {
    task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&ChannelRegistryWrapper::LookupChannelByUUIDImpl, 
        base::Unretained(this), 
        base::Passed(std::move(uuid)),
        base::Passed(std::move(cb_state))));
  }

  void ConnectChannel(
    scoped_refptr<base::SingleThreadTaskRunner> io_task_runner,
    const std::string& scheme, 
    const std::string& name, 
    ChannelConnectCallbackState cb_state, 
    ChannelMessageCallbackState message_state) {
    task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&ChannelRegistryWrapper::ConnectChannelImpl, 
        base::Unretained(this),
        std::move(io_task_runner),
        scheme,
        name,
        base::Passed(std::move(cb_state)),
        base::Passed(std::move(message_state))));
  }

  void RemoveChannel(std::string scheme, std::string name, ChannelHaveCallbackState cb_state) {
    task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&ChannelRegistryWrapper::RemoveChannelImpl, 
        base::Unretained(this), 
        base::Passed(std::move(scheme)),
        base::Passed(std::move(name)),
        base::Passed(std::move(cb_state))));
  }

  void RemoveChannelByUUID(std::string uuid, ChannelHaveCallbackState cb_state) {
    task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&ChannelRegistryWrapper::RemoveChannelByUUIDImpl, 
        base::Unretained(this), 
        base::Passed(std::move(uuid)),
        base::Passed(std::move(cb_state))));
  }

  void ListChannels(std::string scheme, ChannelListCallbackState cb_state) {
    task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&ChannelRegistryWrapper::ListChannelsWithSchemeImpl, 
        base::Unretained(this), 
        base::Passed(std::move(scheme)),
        base::Passed(std::move(cb_state))));
  }

  void ListChannels(ChannelListCallbackState cb_state) {
    task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&ChannelRegistryWrapper::ListAllChannelsImpl, 
        base::Unretained(this),
        base::Passed(std::move(cb_state))));
  }

  void ConnectChannelImpl(scoped_refptr<base::SingleThreadTaskRunner> io_task_runner, const std::string& scheme, const std::string& name, ChannelConnectCallbackState cb_state, ChannelMessageCallbackState message_state) {
    ChannelClientWrapper* client = new ChannelClientWrapper(message_state.state, message_state.cb, std::move(io_task_runner));
    common::mojom::ChannelClientAssociatedPtrInfo local_client_info;
    client->binding.Bind(mojo::MakeRequest(&local_client_info));
    client->binding.set_connection_error_handler(
      base::BindOnce(&ChannelClientWrapper::OnError, client->weak_factory.GetWeakPtr()));
    auto remote_cient_request = mojo::MakeRequest(&client->remote_client);
    client->remote_client.set_connection_error_handler(
       base::BindOnce(&ChannelClientWrapper::OnError, client->weak_factory.GetWeakPtr()));
    registry->ConnectToChannel(
      scheme, 
      name,
      std::move(local_client_info),
      std::move(remote_cient_request),
      base::BindOnce(&OnCreateChannelResult, base::Passed(std::move(cb_state)), base::Unretained(client)));
  }

  void RemoveChannelImpl(std::string scheme, std::string name, ChannelHaveCallbackState cb_state) {
    registry->RemoveChannel(scheme, name, base::BindOnce(&OnStatusChannelResult, base::Passed(std::move(cb_state))));
  }

  void RemoveChannelByUUIDImpl(std::string uuid, ChannelHaveCallbackState cb_state) {
    registry->RemoveChannelByUUID(uuid, base::BindOnce(&OnStatusChannelResult, base::Passed(std::move(cb_state))));
  }

  void HaveChannelImpl(std::string scheme, std::string name, ChannelHaveCallbackState cb_state) {
    registry->HaveChannel(scheme, name, base::BindOnce(&OnHaveChannelResult, base::Passed(std::move(cb_state))));
  }

  void HaveChannelByUUIDImpl(std::string uuid, ChannelHaveCallbackState cb_state) {
    registry->HaveChannelByUUID(uuid, base::BindOnce(&OnHaveChannelResult, base::Passed(std::move(cb_state))));
  }

  void CountChannelsImpl(ChannelHaveCallbackState cb_state) {
    registry->GetChannelCount(base::BindOnce(&OnCountChannelsResult, base::Passed(std::move(cb_state))));
  }

  void LookupChannelImpl(std::string scheme, std::string name, ChannelLookupCallbackState cb_state) {
    registry->LookupChannel(scheme, name, base::BindOnce(&OnGetChannelResult, base::Passed(std::move(cb_state)), task_runner_));
  }

  void LookupChannelByUUIDImpl(std::string uuid, ChannelLookupCallbackState cb_state) {
    registry->LookupChannelByUUID(uuid, base::BindOnce(&OnGetChannelResult, base::Passed(std::move(cb_state)), task_runner_));
  }

  void ListChannelsWithSchemeImpl(std::string scheme, ChannelListCallbackState cb_state) {
    DCHECK(false);
    //registry->ListChannelsForScheme(scheme, base::BindOnce(&OnListEntriesResult, base::Passed(std::move(cb_state))));
  }

  void ListAllChannelsImpl(ChannelListCallbackState cb_state) {
    registry->ListChannels(base::BindOnce(&OnListChannelsResult, base::Passed(std::move(cb_state))));
  }

};

ChannelRegistryRef _ChannelRegistryCreateFromEngine(EngineInstanceRef handle) {
  domain::ModuleState* module = reinterpret_cast<_EngineInstance *>(handle)->module_state();
  return new ChannelRegistryWrapper(module->channel_registry(), module->GetMainTaskRunner());
}

ChannelRegistryRef _ChannelRegistryCreateFromApp(ApplicationInstanceRef handle) {
  application::ApplicationThread* thread = reinterpret_cast<application::ApplicationProcess *>(handle)->main_thread();
  return new ChannelRegistryWrapper(thread->GetChannelRegistry(), thread->main_thread_runner());
}

void _ChannelRegistryDestroy(ChannelRegistryRef handle) {
  delete reinterpret_cast<ChannelRegistryWrapper *>(handle);
}

void _ChannelRegistryConnectChannel(
  ChannelRegistryRef registry,
  const char* scheme, 
  const char* name,
  void* state,
  void* client_state,
  void(*cb)(void*, int, ChannelClientRef),
  void(*on_message)(void*, void*)) {
  ChannelConnectCallbackState cb_state{state, cb};
  ChannelMessageCallbackState message_state{client_state, on_message};
  common::mojom::ChannelHandlePtr entry = common::mojom::ChannelHandle::New();
  scoped_refptr<base::SingleThreadTaskRunner> io_task_runner = base::ThreadTaskRunnerHandle::Get();
  reinterpret_cast<ChannelRegistryWrapper *>(registry)->ConnectChannel(std::move(io_task_runner), std::string(scheme), std::string(name), std::move(cb_state), std::move(message_state));
}

void _ChannelRegistryRemoveChannel(ChannelRegistryRef registry, const char* scheme, const char* name, void* state, void(*cb)(void*, int)) {
  ChannelHaveCallbackState cb_state{state, cb};
  reinterpret_cast<ChannelRegistryWrapper *>(registry)->RemoveChannel(std::string(scheme), std::string(name), std::move(cb_state));
}

void _ChannelRegistryRemoveChannelByUUID(ChannelRegistryRef registry, const char* uuid, void* state, void(*cb)(void*, int)) {
  ChannelHaveCallbackState cb_state{state, cb};
  reinterpret_cast<ChannelRegistryWrapper *>(registry)->RemoveChannelByUUID(std::string(uuid), std::move(cb_state));
}

void _ChannelRegistryHaveChannel(ChannelRegistryRef registry, const char* scheme, const char* name, void* state, void(*cb)(void*, int)) {
  ChannelHaveCallbackState cb_state{state, cb};
  reinterpret_cast<ChannelRegistryWrapper *>(registry)->HaveChannel(std::string(scheme), std::string(name), std::move(cb_state));
}

void _ChannelRegistryHaveChannelByUUID(ChannelRegistryRef registry, const char* uuid, void* state, void(*cb)(void*, int)) {
  ChannelHaveCallbackState cb_state{state, cb};
  reinterpret_cast<ChannelRegistryWrapper *>(registry)->HaveChannelByUUID(std::string(uuid), std::move(cb_state));
}

void _ChannelRegistryLookupChannel(ChannelRegistryRef registry, const char* scheme, const char* name, void* state, void(*cb)(void*, int, const char*, const char*, const char*)) {
  ChannelLookupCallbackState cb_state{state, cb};
  reinterpret_cast<ChannelRegistryWrapper *>(registry)->LookupChannel(std::string(scheme), std::string(name), std::move(cb_state));
}

void _ChannelRegistryLookupChannelByUUID(ChannelRegistryRef registry, const char* uuid, void* state, void(*cb)(void*, int, const char*, const char*, const char*)) {
  ChannelLookupCallbackState cb_state{state, cb};
  reinterpret_cast<ChannelRegistryWrapper *>(registry)->LookupChannelByUUID(std::string(uuid), std::move(cb_state));
}

void _ChannelRegistryListChannelsWithScheme(ChannelRegistryRef registry, const char* scheme, void* state, void(*cb)(void*, int, int, const char**, const char**, const char**)) {
  //DLOG(INFO) << "_ChannelRegistryListChannelsWithScheme";
  //ChannelListCallbackState cb_state{state, cb};
  //reinterpret_cast<ChannelRegistryWrapper *>(registry)->ListChannelsWithScheme(std::string(scheme), std::move(cb_state));
}

void _ChannelRegistryListAllChannels(ChannelRegistryRef registry, void* state, void(*cb)(void*, int, int, const char**, const char**, const char**)) {
  ChannelListCallbackState cb_state{state, cb};
  reinterpret_cast<ChannelRegistryWrapper *>(registry)->ListChannels(std::move(cb_state));
}

void _ChannelRegistryGetChannelCount(ChannelRegistryRef registry, void* state, void(*cb)(void*, int)) {
  ChannelHaveCallbackState cb_state{state, cb};
  reinterpret_cast<ChannelRegistryWrapper *>(registry)->CountChannels(std::move(cb_state));
}

// void _ChannelDestroy(ChannelRef feed) {
//   delete reinterpret_cast<ChannelWrapper*>(feed);
// }

// void _ChannelAddSubscriber(ChannelRef feed, ChannelClientRef sub, void* state, void(*cb)(void*, int)) {
//   ChannelHaveCallbackState cb_state{state, cb};
//   ChannelWrapper* wrapper = reinterpret_cast<ChannelWrapper*>(feed);
//   ChannelClientWrapper* sub_wrapper = reinterpret_cast<ChannelClientWrapper*>(sub);
//   wrapper->AddSubscriber(sub_wrapper, std::move(cb_state));
// }

// void _ChannelRemoveSubscriber(ChannelRef feed, const char* uuid, void* state, void(*cb)(void*, int)) {
//   ChannelHaveCallbackState cb_state{state, cb};
//   ChannelWrapper* wrapper = reinterpret_cast<ChannelWrapper*>(feed);
//   wrapper->RemoveSubscriber(std::string(uuid), std::move(cb_state));
// }

// ChannelClientRef _ChannelClientCreate(ChannelRef feed, void* state, void(*cb)(void*, const char*, int, void *)) {
//   return new ChannelClientWrapper(state, cb);
// }

void _ChannelClientDestroy(ChannelClientRef client) {
  delete reinterpret_cast<ChannelClientWrapper*>(client);
}

void _ChannelClientPostMessageString(ChannelClientRef handle, WebLocalDomWindowRef window, const char* message) {
  ChannelClientWrapper* client = reinterpret_cast<ChannelClientWrapper*>(handle);
  SerializedScriptValueWrapper serialized;
  serialized.Serialize(reinterpret_cast<blink::LocalDOMWindow*>(window), String::FromUTF8(message));
  common::CloneableMessage msg;
  msg.encoded_message = serialized.handle->GetWireData();
  msg.EnsureDataIsOwned();
  client->remote_client->OnMessage(std::move(msg));
}

void _ChannelClientPostMessageStringFromWorker(ChannelClientRef handle, WebWorkerRef worker, const char* message) {
  ChannelClientWrapper* client = reinterpret_cast<ChannelClientWrapper*>(handle);
  SerializedScriptValueWrapper serialized;
  serialized.Serialize(reinterpret_cast<WebWorkerShim*>(worker), String::FromUTF8(message));
  common::CloneableMessage msg;
  msg.encoded_message = serialized.handle->GetWireData();
  msg.EnsureDataIsOwned();
  client->remote_client->OnMessage(std::move(msg));
}

void _ChannelClientPostMessageStringFromServiceWorker(ChannelClientRef handle, ServiceWorkerGlobalScopeRef scope, const char* message) {
  ChannelClientWrapper* client = reinterpret_cast<ChannelClientWrapper*>(handle);
  SerializedScriptValueWrapper serialized;
  serialized.Serialize(reinterpret_cast<blink::ServiceWorkerGlobalScope*>(scope), String::FromUTF8(message));
  common::CloneableMessage msg;
  msg.encoded_message = serialized.handle->GetWireData();
  msg.EnsureDataIsOwned();
  client->remote_client->OnMessage(std::move(msg));
}

void _ChannelClientClose(ChannelClientRef handle) {
  ChannelClientWrapper* client = reinterpret_cast<ChannelClientWrapper*>(handle);
  client->Close();
}