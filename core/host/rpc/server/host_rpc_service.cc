// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/server/host_rpc_service.h"

#include "base/strings/string_util.h"
#include "base/task_scheduler/task_traits.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/host_thread.h"
#include "core/host/schema/schema_registry.h"
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

class RpcMessageEncoderImpl : public net::RpcMessageEncoder {
public:
  RpcMessageEncoderImpl(Schema* schema): schema_(schema) {}
  ~RpcMessageEncoderImpl() override {}

  bool CanEncode(const std::string& service_name, const std::string& method_name) override {
    const google::protobuf::ServiceDescriptor* service = schema_->GetServiceDescriptorNamed(service_name);
    if (!service) {
      DLOG(ERROR) << "CanEncode: failed while trying to find service '" << service_name << "' in proto '" << schema_->package() << "'";
      return false;
    }
    
    const google::protobuf::MethodDescriptor* method = service->FindMethodByName(method_name);
    if (!method) {
      DLOG(ERROR) << "CanEncode: failed while trying to find '" << method_name << "' in service '" << service_name << "' proto '" << schema_->package() << "'";
      return false;
    }
    return true;
  }

  const google::protobuf::Descriptor* GetMethodOutputType(const std::string& service_name, const std::string& method_name) override {
    const google::protobuf::ServiceDescriptor* service = schema_->GetServiceDescriptorNamed(service_name);
    if (!service) {
      DLOG(ERROR) << "GetMethodOutputType: failed while trying to find service '" << service_name << "' in proto '" << schema_->package() << "'";
      return nullptr;
    }
    
    const google::protobuf::MethodDescriptor* method = service->FindMethodByName(method_name);
    if (!method) {
      DLOG(ERROR) << "GetMethodOutputType: failed while trying to find '" << method_name << "' in service '" << service_name << "' proto '" << schema_->package() << "'";
      return nullptr;
    }

    const google::protobuf::Descriptor* message_descriptor = method->output_type();
    if (!message_descriptor) {
      DLOG(ERROR) << "GetMethodOutputType: failed while trying to get the input type of '" << method_name << "' in proto '" << schema_->package() << "'";
      return nullptr;
    }

    return message_descriptor;
  }

  const google::protobuf::Descriptor* GetMethodInputType(const std::string& service_name, const std::string& method_name) override {
    const google::protobuf::ServiceDescriptor* service = schema_->GetServiceDescriptorNamed(service_name);
    if (!service) {
      DLOG(ERROR) << "GetMethodInputType: failed while trying to find service '" << service_name << "' in proto '" << schema_->package() << "'";
      return nullptr;
    }
    
    const google::protobuf::MethodDescriptor* method = service->FindMethodByName(method_name);
    if (!method) {
      DLOG(ERROR) << "GetMethodInputType: failed while trying to find '" << method_name << "' in service '" << service_name << "' proto '" << schema_->package() << "'";
      return nullptr;
    }

    const google::protobuf::Descriptor* message_descriptor = method->input_type();
    if (!message_descriptor) {
      DLOG(ERROR) << "GetMethodInputType: failed while trying to get the input type of '" << method_name << "' in proto '" << schema_->package() << "'";
      return nullptr;
    }

    return message_descriptor;
  }
  
  bool EncodeArguments(const std::string& service_name, const std::string& method_name, const std::map<std::string, std::string>& kvmap, std::string* out) override {
    const google::protobuf::ServiceDescriptor* service = schema_->GetServiceDescriptorNamed(service_name);
    if (!service) {
      DLOG(ERROR) << "EncodeArguments: failed while trying to find service '" << service_name << "' in proto '" << schema_->package() << "'";
      return false;
    }
    
    const google::protobuf::MethodDescriptor* method = service->FindMethodByName(method_name);
    if (!method) {
      DLOG(ERROR) << "EncodeArguments: failed while trying to find '" << method_name << "' in service '" << service_name << "' proto '" << schema_->package() << "'";
      return false;
    }

    const google::protobuf::Descriptor* message_descriptor = method->input_type();
    if (!message_descriptor) {
      DLOG(ERROR) << "EncodeArguments: failed while trying to get the input type of '" << method_name << "' in proto '" << schema_->package() << "'";
      return false;
    }

    SchemaRegistry* protocol_registry = schema_->registry();
    google::protobuf::DescriptorPool* descriptor_pool = protocol_registry->descriptor_pool();    
    google::protobuf::DynamicMessageFactory factory(descriptor_pool);
    const google::protobuf::Message* message = factory.GetPrototype(message_descriptor);
    google::protobuf::Message* mutable_message = message->New();
    const google::protobuf::Reflection* reflection = mutable_message->GetReflection();
    // theres parameters in url? try to find fields with the same name
    if (kvmap.size() > 0) {
      for (auto it = kvmap.begin(); it != kvmap.end(); ++it) {
        for (int i = 0; i < message_descriptor->field_count(); ++i) {
          const google::protobuf::FieldDescriptor* field_descriptor = message_descriptor->field(i);
          if (field_descriptor && field_descriptor->name() == it->first) {
            switch (field_descriptor->cpp_type()) {
              case google::protobuf::FieldDescriptor::CPPTYPE_STRING: {
                reflection->SetString(mutable_message, field_descriptor, it->second);
                break;
              }
              case google::protobuf::FieldDescriptor::CPPTYPE_INT32: {
                int number = 0;
                DCHECK(base::StringToInt(it->second, &number));
                reflection->SetInt32(mutable_message, field_descriptor, number);
                break;
              }
              case google::protobuf::FieldDescriptor::CPPTYPE_INT64: {
                int64_t number = 0;
                DCHECK(base::StringToInt64(it->second, &number));
                reflection->SetInt64(mutable_message, field_descriptor, number);
                break;
              }
              case google::protobuf::FieldDescriptor::CPPTYPE_UINT32: {
                unsigned number = 0;
                DCHECK(base::StringToUint(it->second, &number));
                reflection->SetUInt32(mutable_message, field_descriptor, number);
                break;
              }
              case google::protobuf::FieldDescriptor::CPPTYPE_UINT64: {
                uint64_t number = 0;
                DCHECK(base::StringToUint64(it->second, &number));
                reflection->SetUInt64(mutable_message, field_descriptor, number);
                break;
              }
              case google::protobuf::FieldDescriptor::CPPTYPE_DOUBLE: {
                double number = 0;
                DCHECK(base::StringToDouble(it->second, &number));
                reflection->SetDouble(mutable_message, field_descriptor, number);
                break;
              }
              case google::protobuf::FieldDescriptor::CPPTYPE_FLOAT: {
                double number = 0;
                DCHECK(base::StringToDouble(it->second, &number));
                // static_cast will do ? cant remember that other unusual/fancy cast name for those situations
                reflection->SetFloat(mutable_message, field_descriptor, static_cast<float>(number));
                break;
              }
              case google::protobuf::FieldDescriptor::CPPTYPE_BOOL: {
                bool boolean = it->second == "true" ? true : false;
                reflection->SetBool(mutable_message, field_descriptor, boolean);
                break;
              }
              case google::protobuf::FieldDescriptor::CPPTYPE_ENUM: {
                int number = 0;
                DCHECK(base::StringToInt(it->second, &number));
                const google::protobuf::EnumDescriptor* enum_descr = field_descriptor->enum_type();
                const google::protobuf::EnumValueDescriptor* enum_value_descr =  enum_descr->FindValueByNumber(number);
                if (enum_value_descr) {
                  reflection->SetEnum(mutable_message, field_descriptor, enum_value_descr);
                }
                break;
              }
              // do nothing
              case google::protobuf::FieldDescriptor::CPPTYPE_MESSAGE:
              default:
               break;
            }
            break;
          }
        }
      }
    }
  
    if (!mutable_message->SerializeToString(out)) {
      return false;
    }
    
    return true;
  }

private:
  Schema* schema_;
  DISALLOW_COPY_AND_ASSIGN(RpcMessageEncoderImpl);
};

char HostRpcService::kClassName[] = "service";

const char kPluginSeviceName[] = "FetchService";

HostRpcService::HostRpcService(
  const std::string& container,
  const std::string& name,
  const std::string& host,
  int port,
  net::RpcTransportType type,
  const scoped_refptr<base::SingleThreadTaskRunner>& context_thread,
  const scoped_refptr<base::SingleThreadTaskRunner>& delegate_thread,
  const scoped_refptr<base::SingleThreadTaskRunner>& io_thread,
  Schema* schema,
  std::unique_ptr<net::RpcHandler> rpc_handler):
    RpcService(container, 
      name, 
      host, 
      port, 
      type, 
      context_thread, 
      delegate_thread,
      io_thread, 
      std::move(rpc_handler)),
    schema_(schema),
    plugin_service_descriptor_(nullptr) {
  Init();
}

HostRpcService::~HostRpcService() {}

void HostRpcService::Init() {
  const google::protobuf::ServiceDescriptor* found = nullptr;
  const google::protobuf::ServiceDescriptor* plugin_found = nullptr;
  for (size_t i = 0; i < schema()->service_count(); i++) {
    const google::protobuf::ServiceDescriptor* s = schema()->service_at(i);
    if (base::EqualsCaseInsensitiveASCII(s->name(), name())) {
      //DLOG(INFO) << "RpcService::Init: ok, found!";
      found = s;
      //break;
    } else if (base::EqualsCaseInsensitiveASCII(s->name(), kPluginSeviceName)) {
      plugin_found = s;
    }
  }
  DCHECK(found);
  set_service_descriptor(found);

  if (plugin_found) {
    plugin_service_descriptor_ = plugin_found;
  }

  // for (int x = 0; x < service_descriptor_->method_count(); x++) {
  //   const google::protobuf::MethodDescriptor* method_descriptor = service_descriptor_->method(x);
  //   RpcMethodType type = GetMethodType(method_descriptor);
  //   DLOG(INFO) << "adding method: name:" << method_descriptor->name() << " full_name: " << method_descriptor->full_name() << " type: " << GetMethodTypeName(type);
  //   AddMethod(method_descriptor, type);
  // }
}

std::unique_ptr<net::RpcMessageEncoder> HostRpcService::BuildEncoder() {
  return std::make_unique<RpcMessageEncoderImpl>(schema_);
}

scoped_refptr<net::IOBufferWithSize> HostRpcService::Serialize() const {
  return scoped_refptr<net::IOBufferWithSize>();
}

}