// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/services/bundle_handler.h"

#include <vector>

#include "base/strings/string_split.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/workspace/workspace.h"
#include "core/host/bundle/bundle_manager.h"
#include "core/host/application/application_controller.h"
#include "core/host/host_controller.h"
#include "core/host/host_main_loop.h"

namespace host {


const char BundleBuildHandler::kFullname[] = "/mumba.Mumba/BundleBuild";
const char BundleInfoHandler::kFullname[] = "/mumba.Mumba/BundleInfo";
const char BundleInstallHandler::kFullname[] = "/mumba.Mumba/BundleInstall";
const char BundleSignHandler::kFullname[] = "/mumba.Mumba/BundleSign";
const char BundleUninstallHandler::kFullname[] = "/mumba.Mumba/BundleUninstall";
const char BundleUpdateHandler::kFullname[] = "/mumba.Mumba/BundleUpdate";
const char BundlePackHandler::kFullname[] = "/mumba.Mumba/BundlePack";
const char BundleInitHandler::kFullname[] = "/mumba.Mumba/BundleInit";

BundleBuildHandler::BundleBuildHandler():
  fullname_(BundleBuildHandler::kFullname) {

  Init();
}

BundleBuildHandler::~BundleBuildHandler() {}

base::StringPiece BundleBuildHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void BundleBuildHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void BundleBuildHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& BundleBuildHandler::output() const {
  // FIXME
  return fullname_;
}

BundleInfoHandler::BundleInfoHandler():
  fullname_(BundleInfoHandler::kFullname) {

  Init();
}

BundleInfoHandler::~BundleInfoHandler() {}

base::StringPiece BundleInfoHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void BundleInfoHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void BundleInfoHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& BundleInfoHandler::output() const {
  // FIXME
  return fullname_;
}

BundleInstallHandler::BundleInstallHandler()://(const scoped_refptr<base::SequencedTaskRunner>& service_worker): 
  fullname_(BundleInstallHandler::kFullname) {//,
  //service_worker_(service_worker) {

  Init();
}

BundleInstallHandler::~BundleInstallHandler() {}

base::StringPiece BundleInstallHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void BundleInstallHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: use a BundleController now for this
  std::string str_payload(data.data(), data.size());
  scoped_refptr<Workspace> workspace = Workspace::GetCurrent();

  // decode message
  const google::protobuf::Descriptor* message_descriptor = GetDescriptorFor(workspace, "BundleInstallRequest");
  if (!message_descriptor) {
    DLOG(INFO) << "protobuf message for 'BundleInstallRequest' not found";
    return;
  }
  SchemaRegistry* schema_registry = workspace->schema_registry();
  google::protobuf::DescriptorPool* descriptor_pool = schema_registry->descriptor_pool();
  google::protobuf::DynamicMessageFactory factory(descriptor_pool);
  const google::protobuf::Message* message_descr = factory.GetPrototype(message_descriptor);
  google::protobuf::Message* message = message_descr->New();
  message->ParseFromString(str_payload);
  std::string url = GetStringField(workspace, message, "BundleInstallRequest", "url");
  //DLOG(INFO) << "installing application '" << url << "' from protobuf payload [" << str_payload.size() << "] => '" << str_payload << "'";
  if (url.empty() && str_payload.size()) {
    // FIXME: convert clients sending plaintext to use protobuf encoding
    url = str_payload;
  }
  if (!url.empty()) {
    workspace->application_controller()->InstallApplication(url, std::move(cb));
  } else {
    DLOG(ERROR) << "error installing application: url is empty";
  }
  delete message;
}

void BundleInstallHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& BundleInstallHandler::output() const {
  scoped_refptr<Workspace> workspace = Workspace::GetCurrent();
  return workspace->application_controller()->install_output();
}

BundleSignHandler::BundleSignHandler():
  fullname_(BundleSignHandler::kFullname) {

  Init();
}

BundleSignHandler::~BundleSignHandler() {}

base::StringPiece BundleSignHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void BundleSignHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  DLOG(INFO) << "BundleSignHandler::HandleCall";
  std::string str_payload(data.data(), data.size());
  scoped_refptr<Workspace> workspace = Workspace::GetCurrent();
  // decode message
  const google::protobuf::Descriptor* message_descriptor = GetDescriptorFor(workspace, "BundleSignRequest");
  if (!message_descriptor) {
    DLOG(INFO) << "protobuf message for 'BundleSignRequest' not found";
    return;
  }
  SchemaRegistry* schema_registry = workspace->schema_registry();
  google::protobuf::DescriptorPool* descriptor_pool = schema_registry->descriptor_pool();
  google::protobuf::DynamicMessageFactory factory(descriptor_pool);
  const google::protobuf::Message* message_descr = factory.GetPrototype(message_descriptor);
  google::protobuf::Message* message = message_descr->New();
  message->ParseFromString(str_payload);
  std::string public_signature = GetStringField(workspace, message, "BundleSignRequest", "public_signature");
  std::string bundle_path = GetStringField(workspace, message, "BundleSignRequest", "bundle_path");
  if (!public_signature.empty()) {
    std::vector<uint8_t> data(public_signature.begin(), public_signature.end());
    workspace->bundle_manager()->SignBundle(base::FilePath(bundle_path), data, std::move(cb));
  } else {
    DLOG(ERROR) << "error signing bundle: public_signature is empty";
  }
  delete message;
}

void BundleSignHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& BundleSignHandler::output() const {
  // FIXME
  return fullname_;
}

BundleUninstallHandler::BundleUninstallHandler():
  fullname_(BundleUninstallHandler::kFullname) {

  Init();
}

BundleUninstallHandler::~BundleUninstallHandler() {}

base::StringPiece BundleUninstallHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void BundleUninstallHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void BundleUninstallHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& BundleUninstallHandler::output() const {
  // FIXME
  return fullname_;
}

BundleUpdateHandler::BundleUpdateHandler():
  fullname_(BundleUpdateHandler::kFullname) {

  Init();
}

BundleUpdateHandler::~BundleUpdateHandler() {}

base::StringPiece BundleUpdateHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void BundleUpdateHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void BundleUpdateHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& BundleUpdateHandler::output() const {
  // FIXME
  return fullname_;
}

// 

BundlePackHandler::BundlePackHandler():
  fullname_(BundlePackHandler::kFullname) {

  Init();
}

BundlePackHandler::~BundlePackHandler() {

}

base::StringPiece BundlePackHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void BundlePackHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  std::string str_payload(data.data(), data.size());
  bool no_frontend = false;
  scoped_refptr<Workspace> workspace = Workspace::GetCurrent();

  // decode message
  const google::protobuf::Descriptor* message_descriptor = GetDescriptorFor(workspace, "BundlePackRequest");
  if (!message_descriptor) {
    DLOG(INFO) << "protobuf message for 'BundlePackRequest' not found";
    return;
  }
  SchemaRegistry* schema_registry = workspace->schema_registry();
  google::protobuf::DescriptorPool* descriptor_pool = schema_registry->descriptor_pool();
  google::protobuf::DynamicMessageFactory factory(descriptor_pool);
  const google::protobuf::Message* message_descr = factory.GetPrototype(message_descriptor);
  google::protobuf::Message* message = message_descr->New();
  message->ParseFromString(str_payload);
  std::string name = GetStringField(workspace, message, "BundlePackRequest", "name");
  std::string path = GetStringField(workspace, message, "BundlePackRequest", "path");
  no_frontend = GetStringField(workspace, message, "BundlePackRequest", "no_frontend") == "true";
  if (!path.empty() && !name.empty()) {
    workspace->bundle_manager()->PackBundle(name, base::FilePath(path), no_frontend, std::move(cb));
  } else {
    DLOG(ERROR) << "error unpacking application: path is empty";
  }
  delete message;
}

void BundlePackHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& BundlePackHandler::output() const {
  // FIXME
  return fullname_;
}

//

BundleInitHandler::BundleInitHandler():
  fullname_(BundleInitHandler::kFullname) {

  Init();
}

BundleInitHandler::~BundleInitHandler() {

}

base::StringPiece BundleInitHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void BundleInitHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  std::string str_payload(data.data(), data.size());
  scoped_refptr<Workspace> workspace = Workspace::GetCurrent();

  // decode message
  const google::protobuf::Descriptor* message_descriptor = GetDescriptorFor(workspace, "BundleInitRequest");
  if (!message_descriptor) {
    DLOG(INFO) << "protobuf message for 'BundleInitRequest' not found";
    return;
  }
  SchemaRegistry* schema_registry = workspace->schema_registry();
  google::protobuf::DescriptorPool* descriptor_pool = schema_registry->descriptor_pool();
  google::protobuf::DynamicMessageFactory factory(descriptor_pool);
  const google::protobuf::Message* message_descr = factory.GetPrototype(message_descriptor);
  google::protobuf::Message* message = message_descr->New();
  message->ParseFromString(str_payload);
  std::string name = GetStringField(workspace, message, "BundleInitRequest", "name");
  std::string path = GetStringField(workspace, message, "BundleInitRequest", "path");
  if (!path.empty() && !name.empty()) {
    workspace->bundle_manager()->InitBundle(name, base::FilePath(path), std::move(cb));
  } else {
    DLOG(ERROR) << "error initializing bundle: path is empty";
  }
  delete message;
}

void BundleInitHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& BundleInitHandler::output() const {
  // FIXME
  return fullname_;
}

}