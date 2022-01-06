// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/rpc_data_source.h"

#include <stddef.h>

#include "base/containers/hash_tables.h"
#include "base/files/file_path.h"
#include "base/logging.h"
#include "base/rand_util.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/task_scheduler/post_task.h"
#include "base/sequenced_task_runner.h"
#include "base/bind.h"
#include "base/sequenced_task_runner.h"
#include "base/memory/ref_counted_memory.h"
#include "base/strings/string_piece.h"
#include "base/strings/string_util.h"
#include "base/strings/string_split.h"
#include "base/strings/string_number_conversions.h"
#include "core/host/host_thread.h"
#include "core/host/workspace/workspace.h"
#include "core/host/application/domain.h"
#include "core/host/url/place_registry.h"
#include "core/host/url/place_entry.h"
#include "core/host/application/url_data_manager_backend.h"
#include "net/rpc/client/rpc_stream.h"
#include "core/shared/common/client.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/filter/gzip_source_stream.h"
#include "net/filter/source_stream.h"
#include "net/http/http_status_code.h"
#include "net/log/net_log_util.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_error_job.h"
#include "net/url_request/url_request_job.h"
#include "net/url_request/url_request_job_factory.h"
#include "ui/base/template_expressions.h"
#include "ui/base/layout.h"
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

#if defined(OS_WIN)
#include "base/strings/utf_string_conversions.h"
#endif

namespace host {

namespace {

const char kChromeUIResourcesHost[] = "tweedy";
const char kChromeUIScheme[] = "app";

const char kResourceNotFoundErr[] = R"(<!doctype html>
  <html>
  <head>
  </head>
  <body>
  <div>oops.. resource not found</div>
  </body>
  </html>)";

const char kServiceNotFoundErr[] = R"(<!doctype html>
  <html>
  <head>
  </head>
  <body>
  <div>oops.. service not found</div>
  </body>
  </html>)";

const char kRpcFailedErr[] = R"(<!doctype html>
  <html>
  <head>
  </head>
  <body>
  <div>oops.. rpc failed</div>
  </body>
  </html>)";

const char kChromeURLContentSecurityPolicyHeaderBase[] =
    "Content-Security-Policy: ";
const char kChromeURLXFrameOptionsHeader[] = "X-Frame-Options: DENY";

// rpc flags/headers

// "grpc" in our case
const char kMumbaRpcServiceType[] = "Rpc-Service-Type: ";
// the service name
const char kMumbaRpcServiceName[] = "Rpc-Service-Name: ";
// host name
const char kMumbaRpcServiceHost[] = "Rpc-Service-Host: ";
// tcp port
const char kMumbaRpcServicePort[] = "Rpc-Service-Port: ";
// transport
const char kMumbaRpcServiceTransport[] = "Rpc-Service-Transport: ";
// the full service-method url
const char kMumbaRpcServiceMethodURL[] = "Rpc-Service-Method-Url: ";
// the service-method type (normal, server-stream, client-stream or bidi-stream)
const char kMumbaRpcServiceMethodType[] = "Rpc-Service-Method-Type: ";
// encoding, basically 'protobuf-grpc'
const char kMumbaRpcMessageEncodingHeader[] = "Rpc-Message-Encoding: ";

const char* kColors[] = {
  "#ff0000",
  "#00ff00",
  "#0000ff",
  "#0f0f0f"
};

std::string GetMethodTypeName(const google::protobuf::MethodDescriptor* method) {
  if (method->client_streaming() && method->server_streaming()) {
    return "bidi-stream";
  }
  if (method->client_streaming()) {
    return "client-stream";
  }
  if (method->server_streaming()) {
    return "server-stream"; 
  }
  return "normal";
}

std::string GetTransportTypeName(net::RpcTransportType type) {
  if (type == net::RpcTransportType::kIPC){
    return "IPC";
  }
  if (type == net::RpcTransportType::kHTTP) {
    return "HTTP";
  }

  return "";
}

bool EncodeMessage(Protocol* proto, std::map<std::string, std::string> kvmap, std::string* out) {
  ProtocolRegistry* protocol_registry = proto->registry();
  google::protobuf::DescriptorPool* descriptor_pool = protocol_registry->descriptor_pool();
  google::protobuf::DynamicMessageFactory factory(descriptor_pool);
  const google::protobuf::Descriptor* message_descriptor = proto->GetMessageDescriptorNamed("EntryRequest");
  if (!message_descriptor) {
    DLOG(INFO) << "EncodeMessage(Request): failed while trying to find 'EntryRequest' in proto '" << proto->package() << "'";
    return false;
  }
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
              int number;
              DCHECK(base::StringToInt(it->second, &number));
              reflection->SetInt32(mutable_message, field_descriptor, number);
              break;
            }
            case google::protobuf::FieldDescriptor::CPPTYPE_INT64: {
              int64_t number;
              DCHECK(base::StringToInt64(it->second, &number));
              reflection->SetInt64(mutable_message, field_descriptor, number);
              break;
            }
            case google::protobuf::FieldDescriptor::CPPTYPE_UINT32: {
              unsigned number;
              DCHECK(base::StringToUint(it->second, &number));
              reflection->SetUInt32(mutable_message, field_descriptor, number);
              break;
            }
            case google::protobuf::FieldDescriptor::CPPTYPE_UINT64: {
              uint64_t number;
              DCHECK(base::StringToUint64(it->second, &number));
              reflection->SetUInt64(mutable_message, field_descriptor, number);
              break;
            }
            case google::protobuf::FieldDescriptor::CPPTYPE_DOUBLE: {
              double number;
              DCHECK(base::StringToDouble(it->second, &number));
              reflection->SetDouble(mutable_message, field_descriptor, number);
              break;
            }
            case google::protobuf::FieldDescriptor::CPPTYPE_FLOAT: {
              double number;
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
              int number;
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
/*
  message PageOutput {
   int32 offset = 1;
   int64 size = 2;
   bytes data = 3;
   EntryOutputType output_type = 4;
 }
*/

// bool DecodeContents(Protocol* proto, scoped_refptr<base::RefCountedMemory> in, const unsigned char* offset, size_t readed, std::vector<std::unique_ptr<EntryContent>>* out) {
//   ProtocolRegistry* protocol_registry = proto->registry();
//   google::protobuf::DescriptorPool* descriptor_pool = protocol_registry->descriptor_pool();
//   google::protobuf::DynamicMessageFactory factory(descriptor_pool);
//   const google::protobuf::Descriptor* message_descriptor = proto->GetMessageDescriptorNamed("EntryReply");
//   if (!message_descriptor) {
//     DLOG(INFO) << "DecodeContents: failed to find 'EntryReply' in proto " << proto->package();
//     return false;
//   }

//   const google::protobuf::Descriptor* content_message_descriptor = proto->GetMessageDescriptorNamed("EntryContent");
//   if (!content_message_descriptor) {
//     DLOG(INFO) << "DecodeContents: failed to find 'EntryContent' in proto " << proto->package();
//     return false;
//   }

//   const google::protobuf::FieldDescriptor* status_code_descriptor = message_descriptor->FindFieldByName("status_code");
//   const google::protobuf::FieldDescriptor* content_count_descriptor = message_descriptor->FindFieldByName("content_count");
//   const google::protobuf::FieldDescriptor* content_descriptor = message_descriptor->FindFieldByName("content");
//   if (!status_code_descriptor || !content_count_descriptor || !content_descriptor) {
//     DLOG(INFO) << "DecodeContents: failed. inconsistent proto decl/malformed message type -> '" << message_descriptor->name() << "'";
//     return false;
//   }

//   const google::protobuf::Message* message = factory.GetPrototype(message_descriptor);
  
//   google::protobuf::Message* mutable_message = message->New();
//   if(!mutable_message->ParseFromArray(offset, readed)) {
//     DLOG(INFO) << "DecodeContents: failed. error while parsing message ParseFromArray() for '" << message_descriptor->name() << "' message";
//     return false;
//   }
  
//   const google::protobuf::Reflection* reflection = mutable_message->GetReflection();

//   const google::protobuf::FieldDescriptor* offset_descriptor = content_message_descriptor->FindFieldByName("offset");
//   const google::protobuf::FieldDescriptor* size_descriptor = content_message_descriptor->FindFieldByName("size");
//   const google::protobuf::FieldDescriptor* data_descriptor = content_message_descriptor->FindFieldByName("data");
//   const google::protobuf::FieldDescriptor* content_type_descriptor = content_message_descriptor->FindFieldByName("content_type");
//   if (!offset_descriptor || !size_descriptor || !data_descriptor || !content_type_descriptor) {
//     DLOG(INFO) << "DecodeContents: failed. inconsistent proto decl/malformed message type -> '" << message_descriptor->name() << "'";
//     return false;
//   }

//   int content_count = reflection->GetInt32(*mutable_message, content_count_descriptor);

//   for (int i = 0; i < content_count; i++) {
//     const google::protobuf::Message& content = reflection->GetRepeatedMessage(*mutable_message, content_descriptor, i);
//     const google::protobuf::Reflection* content_reflection = content.GetReflection();
    
//     std::unique_ptr<EntryContent> entry_content = std::make_unique<EntryContent>();
//     scoped_refptr<base::RefCountedString> data = new base::RefCountedString();
//     data->data().assign(content_reflection->GetString(content, data_descriptor));
//     entry_content->set_size((size_t)content_reflection->GetInt64(content, size_descriptor));
//     entry_content->set_offset(content_reflection->GetInt32(content, offset_descriptor));
//     entry_content->set_data(std::move(data));
//     entry_content->set_content_type(EntryContentTypeFromEnumValue(content_reflection->GetEnumValue(content, content_type_descriptor)));
    
//     DLOG(INFO) << "DecodeContents: decoded data [" << i << "] :\n  offset = " << entry_content->offset() << "\n  size = " << entry_content->size() << "\n  content = " << entry_content->data()->front();
//     out->push_back(std::move(entry_content));
//   }
  
//   delete mutable_message;
//   return true; 
// }

//message EntryCatalog {
//  int32 entry_count = 1;
//  repeated EntryInfo entries = 2;
//}

bool DecodeEntries(Protocol* proto, scoped_refptr<base::RefCountedMemory> in, const unsigned char* offset, size_t readed, std::vector<Place *>* entries) {
  ProtocolRegistry* protocol_registry = proto->registry();
  google::protobuf::DescriptorPool* descriptor_pool = protocol_registry->descriptor_pool();
  google::protobuf::DynamicMessageFactory factory(descriptor_pool);
  const google::protobuf::Descriptor* message_descriptor = proto->message_at(2);
  //DLOG(INFO) << "DecodeEntryInfo: name of message 2 from protocol: " << message_descriptor->name();
  if (message_descriptor->name() != "EntryCatalog") {
    //DLOG(INFO) << "DecodeEntryInfo: failed. we expect a 'EntryCatalog' message as reply but got '" << message_descriptor->name() << "' instead";
    return false;
  }

  const google::protobuf::Descriptor* entry_message_descriptor = proto->message_at(0);
  //DLOG(INFO) << "DecodeEntryInfo: name of message 0 from protocol: " << entry_message_descriptor->name();
  if (entry_message_descriptor->name() != "EntryInfo") {
    //DLOG(INFO) << "DecodeEntryInfo: failed. we expect a 'EntryInfo' message as reply but got '" << message_descriptor->name() << "' instead";
    return false;
  }

  const google::protobuf::FieldDescriptor* entry_count_descriptor = message_descriptor->FindFieldByName("entry_count");
  const google::protobuf::FieldDescriptor* entries_descriptor = message_descriptor->FindFieldByName("entries");
  if (!entry_count_descriptor || !entries_descriptor) {
    //DLOG(INFO) << "DecodeEntryInfo: failed. inconsistent proto decl/malformed message type -> '" << message_descriptor->name() << "'";
    return false;
  }

  const google::protobuf::Message* message = factory.GetPrototype(message_descriptor);  
  google::protobuf::Message* mutable_message = message->New();
  if(!mutable_message->ParseFromArray(offset, readed)) {
    //DLOG(INFO) << "DecodeEntryInfo: failed. error while parsing message ParseFromArray() for '" << message_descriptor->name() << "' message";
    return false;
  }

  const google::protobuf::Reflection* reflection = mutable_message->GetReflection();
  int entry_count = reflection->GetInt32(*mutable_message, entry_count_descriptor);
  
  const google::protobuf::FieldDescriptor* name_descriptor = entry_message_descriptor->FindFieldByName("name");
  const google::protobuf::FieldDescriptor* title_descriptor = entry_message_descriptor->FindFieldByName("title");
  const google::protobuf::FieldDescriptor* mime_descriptor = entry_message_descriptor->FindFieldByName("mime_type");
  const google::protobuf::FieldDescriptor* content_type_descriptor = entry_message_descriptor->FindFieldByName("content_type");
  const google::protobuf::FieldDescriptor* content_mode_descriptor = entry_message_descriptor->FindFieldByName("content_mode");
  const google::protobuf::FieldDescriptor* output_type_descriptor = entry_message_descriptor->FindFieldByName("output_type");
  const google::protobuf::FieldDescriptor* icon_data_descriptor = entry_message_descriptor->FindFieldByName("icon_data");
  const google::protobuf::FieldDescriptor* input_message_descriptor = entry_message_descriptor->FindFieldByName("input_message");

  if (!name_descriptor || !title_descriptor || !content_type_descriptor || !content_mode_descriptor || 
      !output_type_descriptor || !icon_data_descriptor || !input_message_descriptor) {
    //DLOG(INFO) << "DecodeEntryInfo: failed. inconsistent proto decl/malformed message type -> '" << message_descriptor->name() << "'";
    return false;
  }

  //const google::protobuf::Message* entry_message = factory.GetPrototype(entry_message_descriptor);  
  for (int i = 0; i < entry_count; i++) {
    const google::protobuf::Message& entry = reflection->GetRepeatedMessage(*mutable_message, entries_descriptor, i);
    const google::protobuf::Reflection* entry_reflection = entry.GetReflection();
    // EntryInfos      
    //google::protobuf::Message* mutable_entry_message = entry_message->New();
    //const google::protobuf::Reflection* entry_reflection = mutable_entry_message->GetReflection();
    //std::unique_ptr<EntryInfo> entry_info = std::make_unique<EntryInfo>();
    std::string str_data = entry_reflection->GetString(entry, icon_data_descriptor);
    scoped_refptr<base::RefCountedBytes> icon_data = new base::RefCountedBytes(reinterpret_cast<const unsigned char *>(str_data.data()), str_data.size());
    std::string entry_name = entry_reflection->GetString(entry, name_descriptor);
    for (auto it = entries->begin(); it != entries->end(); it++) {
      Place* entry_node = *it;
      if (base::EqualsCaseInsensitiveASCII(entry_node->name(), entry_name)) {
        entry_node->set_title(base::ASCIIToUTF16(entry_reflection->GetString(entry, title_descriptor)));
        entry_node->set_content_type(entry_reflection->GetString(entry, mime_descriptor));
        //entry_node->set_input_message(entry_reflection->GetString(entry, input_message_descriptor));
        //entry_node->set_icon_data(std::move(icon_data));
        //entry_node->set_content_type(EntryContentTypeFromEnumValue(entry_reflection->GetEnumValue(entry, content_type_descriptor)));
        //entry_node->set_content_mode(EntryContentModeFromEnumValue(entry_reflection->GetEnumValue(entry, content_type_descriptor)));
        //entry_node->set_output_type(EntryOutputTypeFromEnumValue(entry_reflection->GetEnumValue(entry, content_type_descriptor)));
        break;
      }
    }
    //delete mutable_entry_message;
  }
  
  delete mutable_message;
  return true; 
}

// TODO: use StringPiece here for efficiency
bool CreateKVMapFromPath(const GURL& url, std::map<std::string, std::string>* kvmap) {
  //size_t offset = path.find("?");
  //if (offset != std::string::npos) {
  const url::Parsed& parsed = url.parsed_for_possibly_invalid_spec();
  // there are no params on url
  if (parsed.query.len <= 0) {
    return true;
  }
  int offset = parsed.CountCharactersBefore(url::Parsed::QUERY, false);
  std::string params_str = url.spec().substr(offset);
  std::vector<std::string> params = base::SplitString(params_str, "&", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  for (const auto& param : params) {
    std::vector<std::string> kv = base::SplitString(param, "=", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
    if (kv.size() == 1) {
      kvmap->emplace(std::make_pair(kv[0], ""));
    } else if (kv.size() == 2) {
      kvmap->emplace(std::make_pair(kv[0], kv[1]));
    } else {
      DLOG(ERROR) << "invalid key-value separator in '" << param << "'";
    }
  }
  return true;
}

void CreateEmptyKVMap(std::map<std::string, std::string>* kvmap) {
  kvmap->emplace(std::make_pair("path", "/"));
}

}  // namespace

RpcDataSource::RpcDataSource(PlaceRegistry* place_registry, Domain* application):
  backend_(nullptr),
  place_registry_(place_registry),
  application_(application),
  rpc_client_(nullptr),
  weak_factory_(this) {
  Init();
}

RpcDataSource::~RpcDataSource() {

}

void RpcDataSource::Init() {
  application_->BindDataSource(this);
  rpc_client_ = rpc_host_.NewClient();
  if (!task_runner_) {
    task_runner_ = base::CreateSingleThreadTaskRunnerWithTraits(
       {base::TaskPriority::USER_BLOCKING, base::MayBlock(),
       base::TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN},
       base::SingleThreadTaskRunnerThreadMode::SHARED);
  } 
  PopulateAndScheduleEntryCatalogCall(); 
}

std::string RpcDataSource::GetSource() const {
  return kChromeUIResourcesHost;
}

// RpcDataSource::ApplicationMethod* RpcDataSource::GetMethodForPath(const std::string& path) const {
//   auto it = method_map_.find(path);
//   if (it != method_map_.end()) {
//     return it->second.get();
//   }
//   return nullptr;
// }

void RpcDataSource::AddPlace(const std::string& scheme,
                                 const std::string& path,
                                 HostRpcService* service,
                                 const net::RpcDescriptor& descr) {
  //std::unique_ptr<ApplicationMethod> method = std::make_unique<ApplicationMethod>(service, descr.name, descr.full_name, descr.method_type, "text/html");
  //method_map_.emplace(std::make_pair(path, std::move(method)));

  // std::unique_ptr<Place, HostThread::DeleteOnIOThread> entry(new Place());
  // entry->set_service(service);
  // entry->set_name(base::ToLowerASCII(descr.name));
  // entry->set_path(path);
  // entry->set_url(GURL(scheme + ":/" + path));
  // entry->set_fullname(descr.full_name);
  // entry->set_rpc_method_type(GetEntryFromRpcMethodType(descr.method_type));
  // entry->set_content_type("text/html");
  // place_registry_->AddEntry(std::move(entry));
}

void RpcDataSource::StartDataRequest(
    const GURL& url,
    const std::string& path,
    const ResourceRequestInfo::ApplicationContentsGetter& wc_getter,
    URLDataSource::GotDataCallback callback) {
  //DLOG(INFO) << "RpcDataSource::StartDataRequest";
  
  std::map<std::string, std::string> kvmap;
  std::string service_name = url.scheme();
  std::string method_name;
  std::string entry_name;
  std::string method_params;

  // strip the first "/"
  std::string clean_path = path.substr(1); 
  auto offset = clean_path.find("/");
  if (offset != std::string::npos) {
    // the offset is relative to clean_path, so add one on path
    method_name = path.substr(1, offset+1);
    entry_name = path.substr(0, offset+1);
  } else {
    method_name = clean_path;
    entry_name = path;
  }

  Place* entry = place_registry_->model()->GetEntry(service_name, entry_name);
  if (!entry) {
    OnServiceNotFound(entry_name, callback);
    return;
  }

  HostRpcService* service = entry->service();
  Protocol* proto = service->proto();

  CreateKVMapFromPath(url, &kvmap);
  EncodeMessage(proto, std::move(kvmap), &method_params);
  std::string port = base::NumberToString(service->port());

  CallData* call = CreateCall(
    path, 
    proto,
    entry,
    GetRpcMethodTypeFromEntry(entry->rpc_method_type()), 
    std::move(callback),
    service->host(),
    port,
    method_name,
    method_params);

  DCHECK(call);
  
  ScheduleCall(call); 
  
  //DLOG(INFO) << "RpcDataSource::StartDataRequest end";
}

void RpcDataSource::ScheduleCall(
  int call_id) {
  CallData* call = GetCall(call_id);
  ScheduleCall(call);
}

void RpcDataSource::ScheduleCall(
  CallData* call) {
  DCHECK(false);
  //net::RpcStream* caller = call->caller.get();
  //DCHECK(caller);
  //caller->BindStreamReadDataAvailable(
  //  base::Bind(&RpcDataSource::OnRpcContinuation, base::Unretained(this)));
  //caller->Call(base::Bind(&RpcDataSource::OnRpcContinuation, base::Unretained(this)), call);
}

void RpcDataSource::OnResourceNotFound(const CallData& call) {
  DLOG(INFO) << "resource for '" << call.path << "' not found";
  //scoped_refptr<base::RefCountedMemory> bytes = new base::RefCountedStaticMemory(kResourceNotFoundErr, arraysize(kResourceNotFoundErr));
  std::move(call.callback).Run(call.id, scoped_refptr<base::RefCountedMemory>(), true);
}

void RpcDataSource::OnServiceNotFound(const std::string& path, const URLDataSource::GotDataCallback& callback) {
  DLOG(INFO) << "service for '" << path << "' not found";
  //std::string data = kServiceNotFoundErr;
  //scoped_refptr<base::RefCountedMemory> bytes = new base::RefCountedStaticMemory(kServiceNotFoundErr, arraysize(kServiceNotFoundErr));
  callback.Run(-1, scoped_refptr<base::RefCountedMemory>(), true);
}

bool RpcDataSource::AllowCaching() const {
  // Should not be cached to reflect dynamically-generated contents that may
  // depend on the current locale.
  return false;
}

std::string RpcDataSource::GetMimeType(
    const std::string& scheme,
    const std::string& path) const {
  Place* entry = place_registry_->model()->GetEntry(scheme, path);
  if (!entry)
    return "";
  
  return entry->content_type();
}

scoped_refptr<base::SingleThreadTaskRunner>
RpcDataSource::TaskRunnerForRequestPath(
  const std::string& scheme,
  const std::string& path) {
  if (!task_runner_) {
    task_runner_ = base::CreateSingleThreadTaskRunnerWithTraits(
       {base::TaskPriority::USER_BLOCKING, base::MayBlock(),
       base::TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN},
       base::SingleThreadTaskRunnerThreadMode::SHARED);
  } 
  return task_runner_;
}

std::string
RpcDataSource::GetAccessControlAllowOriginForOrigin(
    const std::string& origin) const {
  // For now we give access only for "chrome://*" origins.
  // According to CORS spec, Access-Control-Allow-Origin header doesn't support
  // wildcards, so we need to set its value explicitly by passing the |origin|
  // back.
  std::string allowed_origin_prefix = kChromeUIScheme;
  allowed_origin_prefix += "://";
  if (!base::StartsWith(origin, allowed_origin_prefix,
                        base::CompareCase::SENSITIVE)) {
    return "null";
  }
  return origin;
}

void RpcDataSource::SetBackend(URLDataManagerBackend* backend) {
  backend_ = backend;
}

bool RpcDataSource::IsGzipped(const std::string& scheme, const std::string& path) const {
  return false;
}

void RpcDataSource::OnDataSent(int call_id, size_t bytes, URLDataSource::GotDataCallback callback) {
  //DLOG(INFO) << "RpcDataSource::OnDataSent";
  //std::string color = kColors[base::RandInt(0, 3)];
  //std::string data = "<div style=\"background: " + color + ";text-align: center; font-size: 18px; height: 80px; font-family: \"Source Code Pro\"; font-weight: bold;font-style: normal;margin-top: 20px\">hello world</div>\n";
  CallData* call = GetCall(call_id);
  if (call) {
    if (call->state != kCALL_COMPLETED)
      call->state = kCALL_DATA_SENT;
    //call->data->data().append(data);
    //sleep(5);
    //callback.Run(call->data);
    //DLOG(INFO) << "RpcDataSource::OnDataSent: setting a new callback for call " << call;
//    call->data = new base::RefCountedString();
    call->callback = std::move(callback);
    //ScheduleCallInternal(call);
  }
}

bool RpcDataSource::ShouldServeMimeTypeAsContentTypeHeader() const {
  return true;
}

PlaceRegistry* RpcDataSource::GetPlaceRegistry() const {
  return place_registry_;
}

void RpcDataSource::SetPlaceRegistry(PlaceRegistry* place_registry) {
  place_registry_ = place_registry;
}

RpcDataSource::CallData* RpcDataSource::CreateCall(
  const std::string& path,
  Protocol* proto,
  Place* entry,
  net::RpcMethodType method_type,
  URLDataSource::GotDataCallback callback,
  const std::string& host,
  const std::string& port,
  const std::string& method_name,
  const std::string& method_params) {

  CallData* result = nullptr;
  int call_id = call_id_gen_.GetNext();
  std::unique_ptr<CallData> new_call = std::make_unique<CallData>(
    call_id, path, proto, entry, method_type,
    std::move(callback));
  result = new_call.get();
  call_map_.emplace(std::make_pair(call_id, std::move(new_call)));
  rpc_client_->NewStream(host, port, method_name, method_params,
    base::Bind(&RpcDataSource::OnCallStreamCreated, 
      base::Unretained(this),
      base::Unretained(result)));
  return result; 
}

void RpcDataSource::OnCallStreamCreated(CallData* call, net::Error code, std::unique_ptr<net::RpcStream> stream) {
  if (code != net::OK) {
    DLOG(ERROR) << "OnCallStreamCreated: error creating rpc stream";
    return;
  }
  call->caller = std::move(stream);
}

bool RpcDataSource::ShouldCompleteRequest(int call_id) {
  CallData* call = GetCall(call_id);
  if (call) {
    //DLOG(INFO) << "RpcDataSource::ShouldCompleteRequest: method type = " << (int)call->method_type;
    return call->method_type == net::RpcMethodType::kNORMAL;
  } 
  return true;
}

void RpcDataSource::OnRpcContinuation(net::Error status, void* data, bool should_complete) {
  //DLOG(INFO) << "RpcDataSource::OnRpcContinuation";
  CallData* call = reinterpret_cast<CallData*>(data);
  if (status == net::OK) {
    DLOG(INFO) << "RpcDataSource::OnRpcContinuation: processing call " << call << ".  len = " << call->caller->output_length();
    size_t readed = call->caller->output_length();
    if (readed) {
      scoped_refptr<base::RefCountedBytes> encoded_data = new base::RefCountedBytes(readed);
      call->caller->Read(encoded_data, readed);
      //call->caller->output();
      call->callback.Run(call->id, encoded_data, should_complete);
      return;
      //} else {
      //  DLOG(ERROR) << "RpcDataSource::OnRpcContinuation: error decoding entry";
      //}
    }
    call->callback.Run(call->id, scoped_refptr<base::RefCountedMemory>(), should_complete);
  } else {
    call->callback.Run(call->id, scoped_refptr<base::RefCountedMemory>(), should_complete);
    //DLOG(ERROR) << "OnRpcContinuation: failed.";
  }
}

RpcDataSource::CallData* RpcDataSource::GetCall(int call_id) {
  auto it = call_map_.find(call_id);
  if (it != call_map_.end()) {
    return it->second.get();
  }
  return nullptr;
}

void RpcDataSource::RemoveCall(int call_id) {
  auto it = call_map_.find(call_id);
  if (it != call_map_.end()) {
    call_map_.erase(it);
  }
}

void RpcDataSource::SendResponse(
    int request_id,
    int call_id,
    scoped_refptr<base::RefCountedMemory> contents,
    bool should_complete) {
  if (URLDataManager::IsScheduledForDeletion(this)) {
    // We're scheduled for deletion. Servicing the request would result in
    // this->AddRef being invoked, even though the ref count is 0 and 'this' is
    // about to be deleted. If the AddRef were allowed through, when 'this' is
    // released it would be deleted again.
    //
    // This scenario occurs with DataSources that make history requests. Such
    // DataSources do a history query in |StartDataRequest| and the request is
    // live until the object is deleted (history requests don't up the ref
    // count). This means it's entirely possible for the DataSource to invoke
    // |SendResponse| between the time when there are no more refs and the time
    // when the object is deleted.
    return;
  }
  HostThread::PostTask(
      HostThread::IO, FROM_HERE,
      base::BindOnce(&RpcDataSource::SendResponseOnIOThread, this,
                     request_id, std::move(contents), should_complete));
}

void RpcDataSource::SendResponseOnIOThread(
    int request_id,
    scoped_refptr<base::RefCountedMemory> contents,
    bool should_complete) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  if (backend_)
    backend_->DataAvailable(request_id, std::move(contents), should_complete);
}


scoped_refptr<net::HttpResponseHeaders> RpcDataSource::GetHeaders(
    const std::string& scheme,
    const std::string& path,
    const std::string& origin) {
  //DLOG(INFO) << "RpcDataSource::GetHeaders";

  std::string method_name;
  std::string entry_name;

  // TODO: create at least a inner function for this
  std::string clean_path = path.substr(1); 
  auto offset = clean_path.find("/");
  if (offset != std::string::npos) {
    // the offset is relative to clean_path, so add one on path
    method_name = path.substr(1, offset+1);
    entry_name = path.substr(0, offset+1);
  } else {
    method_name = clean_path;
    entry_name = path;
  }

  Place* entry = place_registry_->model()->GetEntry(scheme, entry_name);
  if (!entry) {
    return new net::HttpResponseHeaders("HTTP/1.1 404 Not Found");
  }

  HostRpcService* service = entry->service();
  if (!service) {
    return new net::HttpResponseHeaders("HTTP/1.1 404 Not Found");
  }
  
  // Set the headers so that requests serviced by ChromeURLDataManager return a
  // status code of 200. Without this they return a 0, which makes the status
  // indistiguishable from other error types. Instant relies on getting a 200.
  scoped_refptr<net::HttpResponseHeaders> headers(
      new net::HttpResponseHeaders("HTTP/1.1 200 OK"));
  // Determine the least-privileged content security policy header, if any,
  // that is compatible with a given WebUI URL, and append it to the existing
  // response headers.
  if (ShouldAddContentSecurityPolicy()) {
    std::string base = kChromeURLContentSecurityPolicyHeaderBase;
    base.append(GetContentSecurityPolicyScriptSrc());
    base.append(GetContentSecurityPolicyObjectSrc());
    base.append(GetContentSecurityPolicyChildSrc());
    base.append(GetContentSecurityPolicyStyleSrc());
    base.append(GetContentSecurityPolicyImgSrc());
    headers->AddHeader(base);
  }

  if (ShouldDenyXFrameOptions())
    headers->AddHeader(kChromeURLXFrameOptionsHeader);

  if (!AllowCaching())
    headers->AddHeader("Cache-Control: no-cache");
  

  std::string mime_type = GetMimeType(scheme, path);
  if (ShouldServeMimeTypeAsContentTypeHeader() && !mime_type.empty()) {
    std::string content_type = base::StringPrintf(
        "%s:%s", net::HttpRequestHeaders::kContentType, mime_type.c_str());
    headers->AddHeader(content_type);
  }

  if (!origin.empty()) {
    std::string header = GetAccessControlAllowOriginForOrigin(origin);
    DCHECK(header.empty() || header == origin || header == "*" ||
           header == "null");
    if (!header.empty()) {
      headers->AddHeader("Access-Control-Allow-Origin: " + header);
      headers->AddHeader("Vary: Origin");
    }
  }

  // NOTE: added here. this is fixed, as for now its the only way we are serving
  // those requests. (through Rpc with protobuf encoding)

  // the application clients will act upon seeing this header
  // luckily a customized protobuf decoder will launch and 
  // decode the data back to the IDL designed the developer 

  headers->AddHeader(kMumbaRpcServiceType + std::string("grpc"));
  headers->AddHeader(kMumbaRpcServiceName + service->name());
  headers->AddHeader(kMumbaRpcServiceHost + service->host());
  headers->AddHeader(kMumbaRpcServicePort + base::NumberToString(service->port()));
  headers->AddHeader(kMumbaRpcServiceTransport +  GetTransportTypeName(service->transport_type()));
  
  // TODO: see if theres a inexpensive way (eg. how about cache those in the net::RpcService instance?)  
  const google::protobuf::ServiceDescriptor* service_descr = service->service_descriptor();
  for (int i = 0; i < service_descr->method_count(); ++i) {
    const google::protobuf::MethodDescriptor* method_descr = service_descr->method(i);
    if (method_name == base::ToLowerASCII(method_descr->name())) {
      headers->AddHeader(kMumbaRpcServiceMethodURL + method_descr->full_name());
      headers->AddHeader(kMumbaRpcServiceMethodType + GetMethodTypeName(method_descr));
      break;
    }
  }

  // this header is a way to flag, the message is of that kind.
  // TODO: see if theres a better/proper way for this eg. (whats used for gzip for instance)
  // 'protobuf-grpc' -> protobuf with grpc plugins
  headers->AddHeader(kMumbaRpcMessageEncodingHeader + std::string("protobuf-grpc"));

  return headers;
}

void RpcDataSource::PopulateAndScheduleEntryCatalogCall() {
  bool entry_catalog_found = false;
  HostRpcService* entry_catalog_service = nullptr;
  net::RpcDescriptor entry_catalog_method;
  
  for (auto it = application_->services().begin(); it != application_->services().end(); ++it) {
    HostRpcService* service = *it;
    Protocol* proto = service->proto();
    std::vector<net::RpcDescriptor> descriptors = service->GetMethodDescriptors();
    for (auto it = descriptors.begin(); it != descriptors.end(); ++it) {
      std::string method_name = base::ToLowerASCII(it->name);
      std::string path_url = "/" + method_name;
     AddPlace(proto->package(), path_url, service, *it);
      if (method_name == "listentries") {
        entry_catalog_service = service;
        entry_catalog_method = *it;
        entry_catalog_found = true;
      }
    }
    rpc_host_.AddNodes(std::move(descriptors));
  }
  if (entry_catalog_found) {
    Protocol* proto = entry_catalog_service->proto();
    task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&RpcDataSource::ScheduleEntryCatalogCall,
                     base::Unretained(this),
                     base::Unretained(entry_catalog_service),
                     entry_catalog_method));
    //ScheduleEntryCatalogCall(entry_catalog_service, entry_catalog_method);
  } else {
    DLOG(ERROR) << "Page Catalog Rpc method not found";
  }
}

void RpcDataSource::ScheduleEntryCatalogCall(HostRpcService* entry_catalog_service, const net::RpcDescriptor& entry_catalog_method) {
  DLOG(ERROR) << "RpcDataSource::ScheduleEntryCatalogCall";
  std::string method_params;
  std::map<std::string, std::string> kvmap;
  CreateEmptyKVMap(&kvmap);
  EncodeMessage(entry_catalog_service->proto(), std::move(kvmap), &method_params);
  rpc_client_->NewStream(entry_catalog_service->host(), base::NumberToString(entry_catalog_service->port()), base::ToLowerASCII(entry_catalog_method.name), method_params,
    base::Bind(&RpcDataSource::OnEntryCatalogStreamCreated, base::Unretained(this), base::Unretained(entry_catalog_service)));
  DLOG(ERROR) << "RpcDataSource::ScheduleEntryCatalogCall END";  
}

void RpcDataSource::OnEntryCatalogStreamCreated(HostRpcService* entry_catalog_service, net::Error code, std::unique_ptr<net::RpcStream> stream) {
  DLOG(ERROR) << "RpcDataSource::OnEntryCatalogStreamCreated";
  if (code != net::OK) {
    DLOG(ERROR) << "OnEntryCatalogStreamCreated: error creating rpc stream";
    return;
  }
  entry_catalog_ = std::move(stream);
  entry_catalog_->BindStreamReadDataAvailable(
    base::Bind(&RpcDataSource::OnEntryCatalogAvailable, base::Unretained(this), base::Unretained(entry_catalog_service)));
  entry_catalog_->Init();
  //entry_catalog_->Call(base::Bind(&RpcDataSource::OnEntryCatalogAvailable, base::Unretained(this), base::Unretained(entry_catalog_service)));
  DLOG(ERROR) << "RpcDataSource::OnEntryCatalogStreamCreated END";
}

void RpcDataSource::OnEntryCatalogAvailable(HostRpcService* entry_catalog_service, int status) {
  //base::ScopedAllowBaseSyncPrimitivesForTesting allow_wait;
  
  if (status == net::OK) {
    size_t readed = entry_catalog_->output_length();
    if (readed) {
      DLOG(INFO) << "RpcDataSource::OnEntryCatalogAvailable: readed " << readed << ". processing..";
      std::string scheme = entry_catalog_service->proto()->package();
      std::vector<Place *> entry_vec = place_registry_->ListEntriesForScheme(scheme);
      scoped_refptr<base::RefCountedBytes> encoded_data = new base::RefCountedBytes(readed);
      entry_catalog_->Read(encoded_data, readed);
      const unsigned char* offset = (encoded_data->front() + encoded_data->size()) - readed;
      if (!DecodeEntries(entry_catalog_service->proto(), encoded_data, offset, readed, &entry_vec)) {
        DLOG(ERROR) << "RpcDataSource::OnEntryCatalogAvailable: getting entry catalog for '" << application_->name() << "' failed. decode EntryInfo";
      }
    } else {
      DLOG(ERROR) << "RpcDataSource::OnEntryCatalogAvailable: getting entry catalog for '" << application_->name() << "' failed with no data. bytes readed = " << readed;
    }
  } else {
    DLOG(ERROR) << "RpcDataSource::OnEntryCatalogAvailable: getting entry catalog for '" << application_->name() << "' failed! status: " << status;
  }
  entry_catalog_->Shutdown();
  OnEntryCatalogShutdown();
}

void RpcDataSource::OnEntryCatalogShutdown() {
  entry_catalog_.reset();
}

}  // namespace host
