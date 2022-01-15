// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/bundle_init_command.h"

#include "base/files/file_path.h"
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


std::unique_ptr<BundleInitCommand> BundleInitCommand::Create() {
  return std::make_unique<BundleInitCommand>();
}

BundleInitCommand::BundleInitCommand() {

}
 
BundleInitCommand::~BundleInitCommand() {

}

std::string BundleInitCommand::GetCommandMethod() const {
  return "/mumba.Mumba/BundleInit";
}

int BundleInitCommand::Run(CommandExecutor* executor, const base::CommandLine::StringVector& args) {
  std::map<std::string, std::string> input_map;
  std::string encoded_input;

  if (args.size() < 3) {
    printf("bundle init: wrong number of arguments: need [path]\n");
    return 1;
  }

  std::unique_ptr<RPCUnaryCall> install_caller = executor->CreateRPCUnaryCall(GetCommandMethod());
  base::FilePath path(args[2].c_str());
  std::string name = path.BaseName().value();
  input_map.emplace(std::make_pair("name", name.c_str()));
  input_map.emplace(std::make_pair("path", path.value().c_str()));
  if(!executor->EncodeMessage("BundleInitRequest", input_map, &encoded_input)) {
    printf("bundle init: failed while encoding request\n");
    return 1;
  }
  install_caller->Call(args, encoded_input);
  return 0;
}