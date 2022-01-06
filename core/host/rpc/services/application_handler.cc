// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/services/application_handler.h"

#include <vector>

#include "base/strings/string_number_conversions.h"
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
#include "core/host/application/application_controller.h"
#include "core/host/ui/tablist/tablist.h"
#include "core/host/ui/tablist/dock_tablist.h"
#include "core/host/ui/dock.h"
#include "core/host/ui/dock_window.h"
#include "core/host/ui/navigator_params.h"
#include "core/host/ui/dock.h"
#include "core/host/ui/dock_commands.h"
#include "core/host/application/application_contents.h"
#include "url/gurl.h"

namespace host {

// FIXME: reuse for all messages
bool EncodeMessage(SchemaRegistry* protocol_registry, const google::protobuf::Descriptor* message_descriptor, const std::string& type_name, std::map<std::string, std::string> kvmap, std::string* out) {
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

const char ApplicationInstanceCloseHandler::kFullname[] = "/mumba.Mumba/ApplicationInstanceClose";

ApplicationInstanceCloseHandler::ApplicationInstanceCloseHandler(): 
  fullname_(ApplicationInstanceCloseHandler::kFullname) {
  Init();
}

ApplicationInstanceCloseHandler::~ApplicationInstanceCloseHandler() {}

base::StringPiece ApplicationInstanceCloseHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void ApplicationInstanceCloseHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  std::string encoded_data(data.data(), data.size());
  scoped_refptr<Workspace> workspace = Workspace::GetCurrent();
  
  // decode message
  const google::protobuf::Descriptor* message_descriptor = GetDescriptorFor(workspace, "ApplicationCloseRequest");
  if (!message_descriptor) {
    DLOG(INFO) << "protobuf message for 'ApplicationCloseRequest' not found";
    return;
  }
  SchemaRegistry* schema_registry = workspace->schema_registry();
  google::protobuf::DescriptorPool* descriptor_pool = schema_registry->descriptor_pool();
  google::protobuf::DynamicMessageFactory factory(descriptor_pool);
  const google::protobuf::Message* message_descr = factory.GetPrototype(message_descriptor);
  google::protobuf::Message* message = message_descr->New();
  if (!message->ParseFromString(encoded_data)) {
    DLOG(ERROR) << "close: failed to parse the incoming protobuf message";
    HostThread::PostTask(HostThread::IO, FROM_HERE, base::BindOnce(cb, net::ERR_FAILED));
    return;
  }
  const google::protobuf::FieldDescriptor* field = message_descriptor->FindFieldByName("id");
  if (!field) {
    DLOG(ERROR) << "close: not a valid app id found";
    HostThread::PostTask(HostThread::IO, FROM_HERE, base::BindOnce(cb, net::ERR_FAILED));
    return;
  }

  int app_id = message->GetReflection()->GetInt32(*message, field);
  //HostThread::PostTask(HostThread::UI, 
  //  FROM_HERE, 
  //  base::BindOnce(&ApplicationInstanceCloseHandler::CloseApplicationOnUI, base::Unretained(this), app_id));
  DLOG(ERROR) << "application close: closing application " << app_id;
  CloseApplicationOnUI(app_id, std::move(cb));

  delete message;
}

void ApplicationInstanceCloseHandler::CloseApplicationOnUI(int app_id, base::Callback<void(int)> cb) {
  scoped_refptr<Workspace> workspace = Workspace::GetCurrent();
  bool ok = workspace->application_controller()->CloseApplication(app_id);
  HostThread::PostTask(HostThread::IO, FROM_HERE, base::BindOnce(cb, ok ? net::OK : net::ERR_FAILED));
}

void ApplicationInstanceCloseHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const char ApplicationInstanceLaunchHandler::kFullname[] = "/mumba.Mumba/ApplicationInstanceLaunch";

ApplicationInstanceLaunchHandler::ApplicationInstanceLaunchHandler(): fullname_(ApplicationInstanceLaunchHandler::kFullname) {
  Init();
}

ApplicationInstanceLaunchHandler::~ApplicationInstanceLaunchHandler() {}

base::StringPiece ApplicationInstanceLaunchHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void ApplicationInstanceLaunchHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  LaunchOptions options;
 
  std::string encoded_data(data.data(), data.size());
  scoped_refptr<Workspace> workspace = Workspace::GetCurrent();

  // decode message
  const google::protobuf::Descriptor* message_descriptor = GetDescriptorFor(workspace, "ApplicationLaunchRequest");
  if (!message_descriptor) {
    DLOG(INFO) << "protobuf message for 'ApplicationLaunchRequest' not found";
    return;
  }
  SchemaRegistry* schema_registry = workspace->schema_registry();
  google::protobuf::DescriptorPool* descriptor_pool = schema_registry->descriptor_pool();
  google::protobuf::DynamicMessageFactory factory(descriptor_pool);
  const google::protobuf::Message* message_descr = factory.GetPrototype(message_descriptor);
  google::protobuf::Message* message = message_descr->New();
  message->ParseFromString(encoded_data);
  std::string url_string = GetStringField(workspace, message, "ApplicationLaunchRequest", "url");
  GURL url(url_string);
  int app_id = workspace->generate_next_application_id();
  // FIXME: this is the reply.. its crude and we could also make it async
  //        instead..
  std::map<std::string, std::string> kvmap;
  kvmap.emplace(std::make_pair("status_code", "200"));
  kvmap.emplace(std::make_pair("application_id", base::IntToString(app_id)));
  const google::protobuf::Descriptor* output_message_descriptor = GetDescriptorFor(workspace, "ApplicationLaunchResponse");
  if (!message_descriptor) {
    DLOG(INFO) << "protobuf message for 'ApplicationLaunchResponse' not found";
    return;
  }
  if (!EncodeMessage(schema_registry, output_message_descriptor, "ApplicationLaunchResponse", kvmap, &output_)) {
    DLOG(ERROR) << "ApplicationInstanceLaunchHandler::HandleCall: failed to encode the output message";  
  }
  delete message;

  //options.headless = true;
  workspace->application_controller()->LaunchApplication(url, options, std::move(cb), app_id);
}

void ApplicationInstanceLaunchHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
  fullname_,
  "/",
  base::KEEP_WHITESPACE,
  base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& ApplicationInstanceLaunchHandler::output() const {
  return output_;
}

const char ApplicationInstanceListHandler::kFullname[] = "/mumba.Mumba/ApplicationInstanceList";

ApplicationInstanceListHandler::ApplicationInstanceListHandler():
  fullname_(ApplicationInstanceListHandler::kFullname) {

  Init();
}

ApplicationInstanceListHandler::~ApplicationInstanceListHandler() {}

base::StringPiece ApplicationInstanceListHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void ApplicationInstanceListHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // std::string str_payload(data.data(), data.size());
  // scoped_refptr<HostController> controller = HostController::Instance(); 
  // Workspace* workspace = controller->current_workspace();
  // workspace->application_controller()->ListApplications(std::move(cb));
}

void ApplicationInstanceListHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& ApplicationInstanceListHandler::output() const {
  // FIXME
  return fullname_;
}

const char ApplicationInstanceScheduleHandler::kFullname[] = "/mumba.Mumba/ApplicationInstanceSchedule";

ApplicationInstanceScheduleHandler::ApplicationInstanceScheduleHandler():
  fullname_(ApplicationInstanceScheduleHandler::kFullname) {

  Init();
}

ApplicationInstanceScheduleHandler::~ApplicationInstanceScheduleHandler() {}

base::StringPiece ApplicationInstanceScheduleHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void ApplicationInstanceScheduleHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // std::string str_payload(data.data(), data.size());
  // base::UUID app_uuid;
  // base::TimeTicks when;
  // scoped_refptr<HostController> controller = HostController::Instance(); 
  // Workspace* workspace = controller->current_workspace();
  // workspace->application_controller()->ScheduleApplication(app_uuid, when, std::move(cb));
}

void ApplicationInstanceScheduleHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& ApplicationInstanceScheduleHandler::output() const {
  // FIXME
  return fullname_;
}

const char ApplicationListHandler::kFullname[] = "/mumba.Mumba/ApplicationList";

ApplicationListHandler::ApplicationListHandler():
  fullname_(ApplicationListHandler::kFullname) {

  Init();
}

ApplicationListHandler::~ApplicationListHandler() {}

base::StringPiece ApplicationListHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void ApplicationListHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // std::string str_payload(data.data(), data.size());
  // scoped_refptr<HostController> controller = HostController::Instance(); 
  // Workspace* workspace = controller->current_workspace();
  // workspace->application_controller()->ListDomains(std::move(cb));
}

void ApplicationListHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& ApplicationListHandler::output() const {
  // FIXME
  return fullname_;
}

const char ApplicationManifestHandler::kFullname[] = "/mumba.Mumba/ApplicationManifest";

ApplicationManifestHandler::ApplicationManifestHandler():
  fullname_(ApplicationManifestHandler::kFullname) {

  Init();
}

ApplicationManifestHandler::~ApplicationManifestHandler() {}

base::StringPiece ApplicationManifestHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void ApplicationManifestHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // std::string str_payload(data.data(), data.size());
  // scoped_refptr<HostController> controller = HostController::Instance(); 
  // Workspace* workspace = controller->current_workspace();
  // workspace->application_controller()->ListDomains(std::move(cb));
}

void ApplicationManifestHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& ApplicationManifestHandler::output() const {
  // FIXME
  return fullname_;
}

const char ApplicationPinHandler::kFullname[] = "/mumba.Mumba/ApplicationPin";

ApplicationPinHandler::ApplicationPinHandler():
  fullname_(ApplicationPinHandler::kFullname) {

  Init();
}

ApplicationPinHandler::~ApplicationPinHandler() {}

base::StringPiece ApplicationPinHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void ApplicationPinHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // std::string str_payload(data.data(), data.size());
  // base::UUID app_uuid;
  // scoped_refptr<HostController> controller = HostController::Instance(); 
  // Workspace* workspace = controller->current_workspace();
  // workspace->application_controller()->PinApplication(app_uuid, std::move(cb));
}

void ApplicationPinHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& ApplicationPinHandler::output() const {
  // FIXME
  return fullname_;
}

const char ApplicationStartHandler::kFullname[] = "/mumba.Mumba/ApplicationStart";

ApplicationStartHandler::ApplicationStartHandler():
  fullname_(ApplicationStartHandler::kFullname) {

  Init();
}

ApplicationStartHandler::~ApplicationStartHandler() {}

base::StringPiece ApplicationStartHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void ApplicationStartHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // std::string str_payload(data.data(), data.size());
  // base::UUID domain_uuid;
  // scoped_refptr<HostController> controller = HostController::Instance(); 
  // Workspace* workspace = controller->current_workspace();
  // workspace->domain_manager()->StartDomain(domain_uuid, std::move(cb));
}

void ApplicationStartHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& ApplicationStartHandler::output() const {
  // FIXME
  return fullname_;
}

const char ApplicationStatusHandler::kFullname[] = "/mumba.Mumba/ApplicationStatus";

ApplicationStatusHandler::ApplicationStatusHandler():
  fullname_(ApplicationStatusHandler::kFullname) {

  Init();
}

ApplicationStatusHandler::~ApplicationStatusHandler() {}

base::StringPiece ApplicationStatusHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void ApplicationStatusHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // std::string str_payload(data.data(), data.size());
  // base::UUID app_uuid;
  // scoped_refptr<HostController> controller = HostController::Instance(); 
  // Workspace* workspace = controller->current_workspace();
  // workspace->domain_manager()->GetDomainStatus(domain_uuid, std::move(cb));
}

void ApplicationStatusHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& ApplicationStatusHandler::output() const {
  // FIXME
  return fullname_;
}

const char ApplicationStopHandler::kFullname[] = "/mumba.Mumba/ApplicationStop";

ApplicationStopHandler::ApplicationStopHandler():
  fullname_(ApplicationStopHandler::kFullname) {

  Init();
}

ApplicationStopHandler::~ApplicationStopHandler() {}

base::StringPiece ApplicationStopHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void ApplicationStopHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // std::string str_payload(data.data(), data.size());
  // base::UUID domain_uuid;
  // scoped_refptr<HostController> controller = HostController::Instance(); 
  // Workspace* workspace = controller->current_workspace();
  // workspace->domain_manager()->StopDomain(domain_uuid, std::move(cb));
}

void ApplicationStopHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& ApplicationStopHandler::output() const {
  // FIXME
  return fullname_;
}

const char ApplicationUnpinHandler::kFullname[] = "/mumba.Mumba/ApplicationUnpin";

ApplicationUnpinHandler::ApplicationUnpinHandler():
  fullname_(ApplicationUnpinHandler::kFullname) {

  Init();
}

ApplicationUnpinHandler::~ApplicationUnpinHandler() {}

base::StringPiece ApplicationUnpinHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void ApplicationUnpinHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // std::string str_payload(data.data(), data.size());
  // base::UUID app_uuid;
  // scoped_refptr<HostController> controller = HostController::Instance(); 
  // Workspace* workspace = controller->current_workspace();
  // workspace->application_controller()->UnpinApplication(app_uuid, std::move(cb));
}

void ApplicationUnpinHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& ApplicationUnpinHandler::output() const {
  // FIXME
  return fullname_;
}

}