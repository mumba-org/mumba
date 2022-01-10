// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/bundle_sign_command.h"

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

std::unique_ptr<BundleSignCommand> BundleSignCommand::Create() {
  return std::make_unique<BundleSignCommand>();
}

BundleSignCommand::BundleSignCommand() {

}
 
BundleSignCommand::~BundleSignCommand() {

}

std::string BundleSignCommand::GetCommandMethod() const {
  return "/mumba.Mumba/BundleSign";
}

int BundleSignCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  std::map<std::string, std::string> input_map;
  std::string encoded_input;
  if (args.size() < 4) {
    printf("bundle sign: expected args [bundle path] and [signature]\n");
    return 1;
  }
  std::unique_ptr<RPCUnaryCall> sign_caller = executor->CreateRPCUnaryCall(GetCommandMethod());
  input_map.emplace(std::make_pair("bundle_path", args[2].c_str()));
  input_map.emplace(std::make_pair("public_signature", args[3].c_str()));
  if(!executor->EncodeMessage("BundleSignRequest", input_map, &encoded_input)) {
    printf("bundle sign: failed while encoding request\n");
    return 1;
  }
  sign_caller->Call(args, encoded_input);
  return 0;
}