// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/services/service_start_handler.h"

#include <vector>

#include "base/strings/string_split.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/workspace/workspace.h"
#include "core/host/host_controller.h"
#include "core/host/host_main_loop.h"
#include "core/host/application/domain.h"
#include "core/host/application/domain_manager.h"
#include "core/host/schema/schema_registry.h"
#include "core/host/schema/schema.h"
#include "net/rpc/server/rpc_socket_client.h"
#include "net/rpc/server/proxy_rpc_handler.h"
#include "core/host/rpc/server/host_rpc_service.h"
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

const char ServiceStartHandler::kFullname[] = "/mumba.Mumba/ServiceStart";

ServiceStartHandler::ServiceStartHandler(): 
  fullname_(ServiceStartHandler::kFullname) {
  Init();
}

ServiceStartHandler::~ServiceStartHandler() {}

base::StringPiece ServiceStartHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void ServiceStartHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  std::string service_name(data.data(), data.size());
  HostThread::PostTask(HostThread::UI,
    FROM_HERE,
    base::Bind(&ServiceStartHandler::ProcessServiceStartOnUI, 
      base::Unretained(this),
      service_name,
      base::Passed(std::move(cb))));
}

void ServiceStartHandler::ProcessServiceStartOnUI(const std::string& service_name, base::Callback<void(int)> cb) {
  DLOG(INFO) << "starting app service '" << service_name << "'";
  scoped_refptr<Workspace> workspace = Workspace::GetCurrent();
  workspace->LaunchDomain(service_name, base::Bind(&ServiceStartHandler::OnApplicationInstanceLaunched, base::Unretained(this), base::Passed(std::move(cb))));
}

void ServiceStartHandler::OnApplicationInstanceLaunched(base::Callback<void(int)> cb, int r) {
  scoped_refptr<Workspace> workspace = Workspace::GetCurrent();
  SchemaRegistry* schema_registry = workspace->schema_registry();
  Schema* mumba_schema = schema_registry->GetSchemaByName("mumba.proto");
  if (!mumba_schema) {
    DLOG(INFO) << "main 'mumba.proto' schema not found";
    if (!cb.is_null()) {
      HostThread::PostTask(HostThread::IO, FROM_HERE, base::BindOnce(cb, net::ERR_FAILED));
    }
    return;
  }
  const google::protobuf::Descriptor* message_descriptor = mumba_schema->GetMessageDescriptorNamed("ReplyStatus");
  if (!message_descriptor) {
    DLOG(INFO) << "output message for ServiceStart() 'ReplyStatus' not found";
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
  const google::protobuf::FieldDescriptor* status_field = message_descriptor->FindFieldByName("status");
  DCHECK(status_field);
  const google::protobuf::FieldDescriptor* message_field = message_descriptor->FindFieldByName("message");
  DCHECK(message_field);
  output_reflection->SetInt32(mutable_message, status_field, 200);
  output_reflection->SetString(mutable_message, message_field, "OK");
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

void ServiceStartHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

}