// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/application_close_command.h"

#include "base/strings/string_number_conversions.h"
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

static std::string EncodeArguments(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  std::string encoded;
  bool close_now = false;
  int app_id = -1;

  const google::protobuf::Descriptor* message_descriptor = executor->GetMessageDescriptorNamed("ApplicationCloseRequest");
  if (!message_descriptor) {
    printf("error while encoding message: 'ApplicationCloseRequest' protobuf message descriptor not found\n");
    return encoded;
  }
  const google::protobuf::Message* request_message_descr = executor->GetMessageNamed(message_descriptor, "ApplicationCloseRequest");
  google::protobuf::Message* request_message = request_message_descr->New();
  const google::protobuf::Reflection* request_reflection = request_message->GetReflection();

  const google::protobuf::FieldDescriptor* id_field = message_descriptor->FindFieldByName("id");
  if (!id_field) {
    printf("error while encoding message: failed to serialize 'ApplicationCloseRequest': id field not found\n");
    return encoded;
  }
  if (!base::StringToInt(args[0], &app_id)) {
    printf("error while encoding message: first argument is not the app id [int]\n");
    return encoded;
  }
  request_reflection->SetInt32(request_message, id_field, app_id);

  const google::protobuf::FieldDescriptor* close_now_field = message_descriptor->FindFieldByName("close_now");
  if (!close_now_field) {
    printf("error while encoding message: failed to serialize 'ApplicationCloseRequest': close_now field not found\n");
    return encoded;
  }
  request_reflection->SetBool(request_message, close_now_field, close_now);
  if (!request_message->SerializeToString(&encoded)) {
    printf("error while encoding message: failed to serialize 'ApplicationCloseRequest'\n");
    return encoded;
  }
  return encoded;
}

std::unique_ptr<ApplicationCloseCommand> ApplicationCloseCommand::Create() {
  return std::make_unique<ApplicationCloseCommand>();
}

ApplicationCloseCommand::ApplicationCloseCommand() {

}

ApplicationCloseCommand::~ApplicationCloseCommand() {

}

std::string ApplicationCloseCommand::GetCommandMethod() const {
  return "/mumba.Mumba/ApplicationInstanceClose";
}

int ApplicationCloseCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  std::unique_ptr<RPCUnaryCall> caller = executor->CreateRPCUnaryCall(GetCommandMethod());
  std::string encoded_data = EncodeArguments(executor, args);
  caller->Call(args, encoded_data);
  return 0;
}