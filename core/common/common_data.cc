// Copyright 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/common/common_data.h"

#include "base/strings/string_split.h"

namespace common {

namespace {

bool IsIntegerArg(const std::string& arg) {
  for (auto it = arg.begin(); it != arg.end(); it++) {
    if (!base::IsAsciiDigit(*it))
      return false;
  }

  return true;
}  

bool IsDoubleArg(const std::string& arg) {
  for (auto it = arg.begin(); it != arg.end(); it++) {
    if (!base::IsAsciiDigit(*it) && *it != '.') // very poor algo eg. if "0..4" it will pass
                                                // also: is int and is double will both be true 
      return false;
  }

  return true;
}

bool IsStringArg(const std::string& arg) {
  return base::IsStringUTF8(arg);
}

bool IsBoolArg(const std::string& arg) {
  return base::IsStringUTF8(arg) && (arg == "false" || arg == "true");
}

}  

std::string BlobTypeString(BlobType type) {
  switch (type) {
    case BlobType::BINARY:
      return "binary";
    case BlobType::TEXT:
      return "text";
    case BlobType::DOCUMENT:
      return "document";
    case BlobType::DOCUMENT_ARRAY:
      return "document array";
    default:
      return std::string();
  }
}

PackageInfo::PackageInfo(): 
  id(), 
  shell(), 
  pack(), 
  pack_size(0), 
  pack_hash(), 
  ns(), 
  name(), 
  type(-1){

}

PackageInfo::PackageInfo(const PackageInfo& info):
  id(info.id), 
  shell(info.shell), 
  pack(info.pack), 
  pack_size(info.pack_size), 
  pack_hash(info.pack_hash), 
  ns(info.ns), 
  name(info.name), 
  type(info.type) {

}

CallInfo::CallInfo(): disposed(false), _last_idx(0) {}
CallInfo::CallInfo(const std::string& ns, 
           const std::string& api, 
           const std::string& method): 
      ns(ns),
      api(api),
      method(method),
      disposed(false),
      _last_idx(0) {}

CallInfo::CallInfo(const std::string& method): 
      method(method),
      disposed(false),
      _last_idx(0) {}    

CallInfo::~CallInfo(){}

void CallInfo::Init(const std::string& command_line) {
  auto str_args = base::SplitString(
    command_line, " ", 
    base::TRIM_WHITESPACE, 
    base::SPLIT_WANT_NONEMPTY);

  Init(str_args, 0);
}

void CallInfo::Init(const std::vector<std::string>& input, size_t start_index) {

  //if (input.size() > 1) {
    //std::string::size_type first_pos = input[start_index].find(":");
    //std::string::size_type last_pos = input[start_index].rfind("/");

    //if (first_pos != std::string::npos) {
    //  ns = input[start_index].substr(0, first_pos);
    //  if (last_pos != std::string::npos) {
    //    api = input[start_index].substr(first_pos + 1, (last_pos - first_pos - 1));
    //    method = input[start_index].substr(last_pos + 1);
    //  } else {
    //    api = input[start_index].substr(first_pos + 1);
        // if (input.size() > 2) {
        //   method = input[start_index+1];
        // }
    //  }
    //}

    //DLOG(INFO) << "call: " << ns << ":" << api << ( method.empty() ? "" : ("." + method));

    //for (size_t i = start_index + 1; i < input.size(); i++) {
    for (size_t i = start_index; i < input.size(); i++) {
      CallArg* arg = new CallArg{};
      if (IsIntegerArg(input[i])) {
        int ival = -1;
        base::StringToInt(input[i], &ival);
        arg->key = base::IntToString(i-1);
        arg->value.type = kINT_ARG;
        arg->value.entry.i = ival;
        arg->pos = i-1;
        //DLOG(INFO) << "arg[" << i-1 << "]: " << arg->key << " at (" << arg->pos << "): " << arg->value.entry.i  << " (int)";
      } else if (IsDoubleArg(input[i])) {
        double dval = -1;
        base::StringToDouble(input[i], &dval);
        arg->key = base::IntToString(i-1);
        arg->value.type = kDOUBLE_ARG;
        arg->value.entry.d = dval;
        arg->pos = i-1;
        //DLOG(INFO) << "arg[" << i-1 << "]: " << arg->key << " at (" << arg->pos << "): " << arg->value.entry.d << " (double)";
      } else if (IsBoolArg(input[i])) {
        bool bval = (input[i] == "true" ? true : false);
        arg->key = base::IntToString(i-1);
        arg->value.type = kBOOL_ARG;
        arg->value.entry.b = bval;
        arg->pos = i-1;
        //DLOG(INFO) << "arg[" << i-1 << "]: " << arg->key << " at (" << arg->pos << "): " << arg->value.entry.b << " (bool)";
      } else if (IsStringArg(input[i])) {
        arg->key = base::IntToString(i-1);
        arg->value.type = kSTRING_ARG;
        arg->value.entry_string = input[i];
        arg->pos = i-1;
        //DLOG(INFO) << "arg[" << i-1 << "]: " << arg->key << " at (" << arg->pos << "): " << arg->value.entry_string << " (string)";
      } else {
        DLOG(ERROR) << "error: arg is not int, double or string"; 
      }
      args.push_back(arg);
    }
  //} //else {
    //DLOG(ERROR) << "bad input: size(" << input.size() << ")";
  //}
}

void CallInfo::PushInt(int val) {
  CallArg* arg = new CallArg{};
  arg->key = base::IntToString(_last_idx);
  arg->value.type = kINT_ARG;
  arg->value.entry.i = val;
  arg->pos = _last_idx;
  args.push_back(arg);
  _last_idx++;
}

void CallInfo::PushDouble(double val) {
  CallArg* arg = new CallArg{};
  arg->key = base::IntToString(_last_idx);
  arg->value.type = kDOUBLE_ARG;
  arg->value.entry.d = val;
  arg->pos = _last_idx;
  args.push_back(arg);
  _last_idx++;
}

void CallInfo::PushBool(bool val) {
  CallArg* arg = new CallArg{};
  arg->key = base::IntToString(_last_idx);
  arg->value.type = kBOOL_ARG;
  arg->value.entry.b = val;
  arg->pos = _last_idx;
  args.push_back(arg);
  _last_idx++;
}

void CallInfo::PushString(const std::string& val) {
  CallArg* arg = new CallArg{};
  arg->key = base::IntToString(_last_idx);
  arg->value.type = kSTRING_ARG;
  arg->value.entry_string = val;
  arg->pos = _last_idx;
  args.push_back(arg);
  _last_idx++;
}

void CallInfo::PushString(std::string&& val) {
  CallArg* arg = new CallArg{};
  arg->key = base::IntToString(_last_idx);
  arg->value.type = kSTRING_ARG;
  arg->value.entry_string = std::move(val);
  arg->pos = _last_idx;
  args.push_back(arg);
  _last_idx++;
}

void CallInfo::Dispose() {
  for (auto it = args.begin(); it != args.end(); ++it) {
    delete *it;
  }
  disposed = true;
} 

CallResult::CallResult():
  ns(),
  api(),
  method(),
  is_error(false),
  value() {}

CallResult::~CallResult() {}

ShellManifest::ShellManifest(){}
ShellManifest::ShellManifest(const ShellManifest& other):
 uuid(other.uuid),
 name(other.name),
 vendor(other.vendor),
 version(other.version) {

}
 
ShellManifest::ShellManifest(const base::UUID& uuid, const std::string& name): uuid(uuid), name(name) {}
ShellManifest::ShellManifest(const base::UUID& uuid, const std::string& name, const std::string& vendor, const std::string& version): 
  uuid(uuid), name(name), vendor(vendor), version(version) {}

ShellManifest::~ShellManifest() {}

BlobHeader::BlobHeader(): content_length(0), type(BlobType::UNDEFINED), refcount(-1) {}

BlobHeader::BlobHeader(const BlobHeader& other):
 uuid(other.uuid),
 disk(other.disk),
 name(other.name),
 content_hash(other.content_hash),
 content_type(other.content_type),
 content_length(other.content_length),
 type(other.type),
 refcount(other.refcount) {}

BlobHeader::~BlobHeader() {}

}