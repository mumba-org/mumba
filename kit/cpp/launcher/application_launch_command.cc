// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/application_launch_command.h"

#include "base/at_exit.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/message_loop/message_loop.h"
#include "base/strings/string_number_conversions.h"
#include "launcher/application_close_command.h"
#include "launcher/rpc_client.h"
#include "launcher/command_executor.h"
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

static std::string EncodeLaunchArguments(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  std::string encoded;
  
  if (args.size() < 1) {
    printf("error while encoding message: input 'url' argument missing\n");
    return encoded;
  }

  const google::protobuf::Descriptor* message_descriptor = executor->GetMessageDescriptorNamed("ApplicationLaunchRequest");
  if (!message_descriptor) {
    printf("error while encoding message: 'ApplicationLaunchRequest' protobuf message descriptor not found\n");
    return encoded;
  }
  const google::protobuf::Message* request_message_descr = executor->GetMessageNamed(message_descriptor, "ApplicationLaunchRequest");
  google::protobuf::Message* request_message = request_message_descr->New();
  const google::protobuf::Reflection* request_reflection = request_message->GetReflection();
  const google::protobuf::FieldDescriptor* url_field = message_descriptor->FindFieldByName("url");
  if (!url_field) {
    printf("error while encoding message: failed to serialize 'ApplicationLaunchRequest': url field not found\n");
    return encoded;
  }
  request_reflection->SetString(request_message, url_field, args[0]);
  if (!request_message->SerializeToString(&encoded)) {
    printf("error while encoding message: failed to serialize 'ApplicationLaunchRequest'\n");
    return encoded;
  }
  return encoded;
}

bool GetApplicationIdFromResponse(CommandExecutor* executor, char* data, size_t data_size, int* id) {
  const google::protobuf::Descriptor* message_descriptor = executor->GetMessageDescriptorNamed("ApplicationLaunchResponse");
  if (!message_descriptor) {
    printf("error while decoding message: 'ApplicationLaunchRequest' protobuf message descriptor not found\n");
    return false;
  }
  const google::protobuf::Message* request_message_descr = executor->GetMessageNamed(message_descriptor, "ApplicationLaunchResponse");
  google::protobuf::Message* reply_message = request_message_descr->New();
  if (!reply_message->ParseFromArray(data, data_size)) {
    printf("error while decoding message: failed to parse the incoming protobuf message\n");
    return false;
  }
  const google::protobuf::Reflection* reply_reflection = reply_message->GetReflection();
  const google::protobuf::FieldDescriptor* app_field = message_descriptor->FindFieldByName("application_id");
  if (!app_field) {
    printf("error while decoding message: failed to deserialize 'ApplicationLaunchResponse': application_id field not found\n");
    return false;
  }
  *id = reply_reflection->GetInt32(*reply_message, app_field);
  return true;
}

std::unique_ptr<ApplicationLaunchCommand> ApplicationLaunchCommand::Create() {
  return std::make_unique<ApplicationLaunchCommand>();
}

ApplicationLaunchCommand::ApplicationLaunchCommand(): 
  is_running_(false) {

}

ApplicationLaunchCommand::~ApplicationLaunchCommand() {

}

std::string ApplicationLaunchCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ApplicationInstanceLaunch";
}

int ApplicationLaunchCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  // if this is a app profile, push the app name as the first argument to the launch command
  // note: app profile means that the executable is the application name, and we need to automate
  // some things as if its the application process
  if (executor->profile()->GetType() == kPROFILE_APPLICATION) {
    ApplicationCloseCommand close_command;
    base::CommandLine::StringVector args_copy = args;
    const std::string& app_name = executor->profile()->GetName();
    std::string app_url = app_name + "://hello?path=2";
    args_copy.insert(args_copy.begin(), app_url);
    std::unique_ptr<RPCUnaryCall> launch_caller = executor->CreateRPCUnaryCall(GetCommandMethod());
    std::string encoded_data = EncodeLaunchArguments(executor, args_copy);
    launch_caller->Call(args, encoded_data);
    // after sending the launch command, run the main loop
    daemon_.reset(new LauncherDaemon(this, executor->own_message_loop()));
    is_running_ = true;
    daemon_->Run();

    if (launch_caller->output_data() == nullptr) {
      printf("cannot call close: no application id received\n");
      return 1;
    }

    // get the application id
    int app_id = -1;
    if (!GetApplicationIdFromResponse(executor, launch_caller->output_data(), launch_caller->output_data_size(), &app_id)) {
      printf("cannot call close: no valid application id received while decoding output from launch\n");
      return 1;
    }
    // format args for close
    base::CommandLine::StringVector close_args = args;
    close_args.insert(close_args.begin(), base::IntToString(app_id));
    close_command.Run(executor, close_args);
    return 0;
  }
  // if its 'system' profile just call launch normally
  std::unique_ptr<RPCUnaryCall> launch_caller = executor->CreateRPCUnaryCall(GetCommandMethod());
  std::string encoded_data = EncodeLaunchArguments(executor, args);
  launch_caller->Call(args, encoded_data, 0);  
  return 0;
}

void ApplicationLaunchCommand::ProcessSigint(int sig) {
  if (daemon_) {
    daemon_->Quit();
  }
}

void ApplicationLaunchCommand::OnBeforeRun() {
  is_running_ = true;
}

void ApplicationLaunchCommand::OnAfterRun() {
  is_running_ = false;
  Cleanup();
}

void ApplicationLaunchCommand::Cleanup() {

}