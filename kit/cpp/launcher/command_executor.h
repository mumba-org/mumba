// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_KIT_CPP_LAUNCHER_COMMAND_EXECUTOR_H_
#define MUMBA_KIT_CPP_LAUNCHER_COMMAND_EXECUTOR_H_

#include <memory>

#include "base/command_line.h"
#include "base/run_loop.h"
#include "base/message_loop/message_loop.h"
#include "kit/cpp/launcher/command.h"
#include "third_party/protobuf/src/google/protobuf/descriptor.h"
#include "third_party/protobuf/src/google/protobuf/dynamic_message.h"
/*
 */ 
class Bootstrapper;
class Command;
class RPCClient;
class RPCUnaryCall;

enum ProfileType {
 kPROFILE_APPLICATION = 0,
 kPROFILE_SYSTEM = 1
};

class Profile {
public:
 virtual ~Profile() {} 
 virtual CommandCode GetCommandCode(const std::string& name) = 0;
 virtual ProfileType GetType() const = 0;
 virtual const std::string& GetName() const = 0;
};

/*
 * The application profile is targeted for 'application frontends'
 * and its much more simple with commands that are important to the application
 *
 * $ tweedy launch
 * $ tweedy stop
 */
class ApplicationProfile : public Profile {
public:
  ApplicationProfile(const std::string& app_name);
  ~ApplicationProfile() override;

  CommandCode GetCommandCode(const std::string& name) override;

  ProfileType GetType() const override {
    return kPROFILE_APPLICATION;
  }
  
  const std::string& GetName() const override {
    return name_;
  }

private:
  std::string name_;
};

/*
 * The system profile is targeted at the sysctl

   $ klubber index-create my-index
   $ klubber predictor-create sentiment-analysis
   $ klubber init /home/user/my-app
   $ klubber build /home/user/my-app
   $ klubber install /home/user/my-app
 */
class SystemProfile : public Profile {
public:
  SystemProfile();
  ~SystemProfile() override;
  
  CommandCode GetCommandCode(const std::string& name) override;
  ProfileType GetType() const override {
    return kPROFILE_SYSTEM;
  }
  const std::string& GetName() const override {
    return name_;
  }

private:
  std::string name_;
};

class CommandExecutor {
public:   
 CommandExecutor(Bootstrapper* bootstrapper, Profile* profile, std::unique_ptr<base::MessageLoop> main_message_loop);
 ~CommandExecutor();

 RPCClient* rpc_client() const {
  return rpc_client_.get();
 }

 Profile* profile() const {
  return profile_;
 }

 int Run(base::CommandLine* cmd);

 std::unique_ptr<RPCUnaryCall> CreateRPCUnaryCall(const std::string& method_name);
 size_t GetMessageDescriptorCount() const;
 const google::protobuf::Descriptor* GetMessageDescriptorAt(size_t index);
 const google::protobuf::Descriptor* GetMessageDescriptorNamed(const std::string& name);
 const google::protobuf::Message* GetMessageNamed(const std::string& name);
 const google::protobuf::Message* GetMessageNamed(const google::protobuf::Descriptor* descriptor, const std::string& name);
 bool EncodeMessage(
  const std::string& message_name, 
  std::map<std::string, std::string> kvmap,
  std::string* out);

 std::unique_ptr<base::MessageLoop> own_message_loop() {
   return std::move(main_message_loop_);
 }

#if defined(OS_POSIX)
 void ProcessSigint(int sig);
#endif

private:

 CommandCode GetCommandCode(const std::string& name);
 int Execute(CommandCode command, const base::CommandLine::StringVector& args);

 const google::protobuf::FileDescriptor* LoadProtobufFromResourceBundle();
 const google::protobuf::FileDescriptor* BuildFile(const google::protobuf::FileDescriptorProto& schema);
 
 Bootstrapper* bootstrapper_;
 Profile* profile_;
 std::unique_ptr<RPCClient> rpc_client_;
 std::unique_ptr<Command> command_;
 std::unique_ptr<google::protobuf::DescriptorPool> descriptor_pool_;
 std::unique_ptr<base::MessageLoop> main_message_loop_;
 google::protobuf::DynamicMessageFactory factory_;
 const google::protobuf::FileDescriptor* file_proto_;
};

#endif