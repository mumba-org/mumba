// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/services/service_list_handler.h"

#include <vector>

#include "base/strings/string_split.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/workspace/workspace.h"
#include "core/host/host_controller.h"
#include "core/host/host_main_loop.h"
#include "core/host/application/domain.h"
#include "core/host/application/domain_manager.h"
#include "net/rpc/server/rpc_socket_client.h"
#include "net/rpc/server/proxy_rpc_handler.h"
#include "core/host/rpc/server/host_rpc_service.h"
#include "core/host/rpc/server/rpc_manager.h"
#include "core/host/rpc/service_registry.h"
#include "core/host/schema/schema_registry.h"
#include "core/host/schema/schema.h"
#include "url/gurl.h"
#include "third_party/protobuf/src/google/protobuf/compiler/parser.h"
#include "third_party/protobuf/src/google/protobuf/io/tokenizer.h"
#include "third_party/protobuf/src/google/protobuf/io/zero_copy_stream_impl.h"
#include "third_party/protobuf/src/google/protobuf/stubs/strutil.h"
#include "third_party/protobuf/src/google/protobuf/io/zero_copy_stream_impl_lite.h"
#include "third_party/protobuf/src/google/protobuf/arena.h"
#include "third_party/protobuf/src/google/protobuf/arenastring.h"
#include "third_party/protobuf/src/google/protobuf/generated_message_table_driven.h"
#include "third_party/protobuf/src/google/protobuf/generated_message_util.h"
#include "third_party/protobuf/src/google/protobuf/inlined_string_field.h"
#include "third_party/protobuf/src/google/protobuf/metadata.h"
#include "third_party/protobuf/src/google/protobuf/message.h"
#include "third_party/protobuf/src/google/protobuf/dynamic_message.h"

namespace host {

const char ServiceListHandler::kFullname[] = "/mumba.Mumba/ServiceList";

ServiceListHandler::ServiceListHandler(): 
  fullname_(ServiceListHandler::kFullname) {
  Init();
}

ServiceListHandler::~ServiceListHandler() {}

base::StringPiece ServiceListHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void ServiceListHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  HostThread::PostTask(HostThread::UI,
    FROM_HERE,
    base::Bind(&ServiceListHandler::ProcessServiceListOnUI, 
      base::Unretained(this),
      base::Passed(std::move(cb))));
}

void ServiceListHandler::ProcessServiceListOnUI(base::Callback<void(int)> cb) {
  DLOG(INFO) << "listing services ";

  scoped_refptr<Workspace> workspace = Workspace::GetCurrent();
  RpcManager* rpc_manager = workspace->rpc_manager();
  SchemaRegistry* schema_registry = workspace->schema_registry();
  Schema* mumba_schema = schema_registry->GetSchemaByName("mumba.proto");
  if (!mumba_schema) {
    DLOG(INFO) << "main 'mumba.proto' schema not found";
    if (!cb.is_null()) {
      HostThread::PostTask(HostThread::IO, FROM_HERE, base::BindOnce(cb, net::ERR_FAILED));
    }
    return;
  } 
  const google::protobuf::Descriptor* message_descriptor = mumba_schema->GetMessageDescriptorNamed("ListServiceResult");
  if (!message_descriptor) {
    DLOG(INFO) << "output message for ServiceList() 'ListServiceResult' not found";
    if (!cb.is_null()) {
      HostThread::PostTask(HostThread::IO, FROM_HERE, base::BindOnce(cb, net::ERR_FAILED));
    }
    return;
  }
  const google::protobuf::Descriptor* service_descriptor = mumba_schema->GetMessageDescriptorNamed("ServiceInfo");
  if (!service_descriptor) {
    DLOG(INFO) << " descriptor message for 'ServiceInfo' not found";
    if (!cb.is_null()) {
      HostThread::PostTask(HostThread::IO, FROM_HERE, base::BindOnce(cb, net::ERR_FAILED));
    }
    return;
  }

  google::protobuf::DescriptorPool* descriptor_pool = schema_registry->descriptor_pool();
  google::protobuf::DynamicMessageFactory factory(descriptor_pool);
  const google::protobuf::Message* message = factory.GetPrototype(message_descriptor);
  google::protobuf::Message* mutable_message = message->New();
  const google::protobuf::Reflection* output_reflection = mutable_message->GetReflection();
  const google::protobuf::FieldDescriptor* services_field = message_descriptor->FindFieldByName("services");
  DCHECK(services_field);
  const std::unordered_map<base::UUID, HostRpcService *>& services = rpc_manager->services();

  for (auto it = services.begin(); it != services.end(); ++it) {
    DLOG(INFO) << "adding service " << it->second->container() << " . " << it->second->name() << " port: " << it->second->port();
    //const google::protobuf::Message* service = factory.GetPrototype(service_descriptor);
    //const google::protobuf::Reflection* service_reflection = service->GetReflection();
    //google::protobuf::Message* service_message = service->New();
    google::protobuf::Message* service_entry = output_reflection->AddMessage(mutable_message, services_field);
    const google::protobuf::Reflection* entry_reflection = service_entry->GetReflection();
    const google::protobuf::FieldDescriptor* pkg_field = service_entry->GetDescriptor()->FindFieldByName("package");
    const google::protobuf::FieldDescriptor* name_field = service_entry->GetDescriptor()->FindFieldByName("name");
    const google::protobuf::FieldDescriptor* port_field = service_entry->GetDescriptor()->FindFieldByName("port");
    entry_reflection->SetString(service_entry, pkg_field, it->second->container());
    entry_reflection->SetString(service_entry, name_field, it->second->name());
    entry_reflection->SetInt32(service_entry, port_field, it->second->port());
  }

  const google::protobuf::FieldDescriptor* status_field = message_descriptor->FindFieldByName("status");
  output_reflection->SetInt32(mutable_message, status_field, 200);

  if (!mutable_message->SerializeToString(&output_)) {
    DLOG(INFO) << "failed to serialize the message to string";
    if (!cb.is_null()) {
      HostThread::PostTask(HostThread::IO, FROM_HERE, base::BindOnce(cb, net::ERR_FAILED));
    }
    return;
  }
  if (!cb.is_null()) {
    HostThread::PostTask(HostThread::IO, FROM_HERE, base::BindOnce(cb, net::OK));
  }
}

void ServiceListHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

}