// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/common/common_param_traits.h"

#include <string>

#include "base/containers/stack_container.h"
#include "core/common/content_constants.h"
#include "core/shared/common/page_state.h"
#include "core/shared/common/referrer.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/http/http_util.h"

namespace IPC {

void ParamTraits<RequestOpcode>::Write(base::Pickle* m, const RequestOpcode& p) {
  WriteParam(m, static_cast<int>(p));
 }

 bool ParamTraits<RequestOpcode>::Read(const base::Pickle* m,
  base::PickleIterator* iter,
  RequestOpcode* p) {
  
  int opcode;

  if (!ReadParam(m, iter, &opcode)) {
   *p = static_cast<RequestOpcode>(0);
   return false;
  }

  *p = static_cast<RequestOpcode>(opcode);

  return true;
 }

 void ParamTraits<RequestOpcode>::Log(const RequestOpcode& p, std::string* l) {
  std::string message("RequestOpcode: ");
  message.append(base::IntToString(static_cast<int>(p)));
  LogParam(message, l);
 }

 void ParamTraits<ResultStatus>::Write(base::Pickle* m, const ResultStatus& p) {
  WriteParam(m, static_cast<int>(p));
 }

 bool ParamTraits<ResultStatus>::Read(const base::Pickle* m,
  base::PickleIterator* iter,
  ResultStatus* p) {
  
  int opcode;

  if (!ReadParam(m, iter, &opcode)) {
   *p = static_cast<ResultStatus>(0);
   return false;
  }

  *p = static_cast<ResultStatus>(opcode);

  return true;
 }

 void ParamTraits<ResultStatus>::Log(const ResultStatus& p, std::string* l) {
  std::string message("ResultStatus: ");
  message.append(base::IntToString(static_cast<int>(p)));
  LogParam(message, l);
 }

void ParamTraits<RequestInfo>::Write(base::Pickle* m, const RequestInfo& p) {
  WriteParam(m, p.op);
  WriteParam(m, p.request_id);
  WriteParam(m, p.session_id);
 }

 bool ParamTraits<RequestInfo>::Read(const base::Pickle* m,
  base::PickleIterator* iter,
  RequestInfo* p) {
  
  RequestOpcode op;
  int request_id;
  base::UUID session_id;

  if (!ReadParam(m, iter, &op) || !ReadParam(m, iter, &request_id) ||
   !ReadParam(m, iter, &session_id)) {
   *p = RequestInfo();
   return false;
  }

  *p = RequestInfo(op, request_id, session_id);

  return true;
 }

 void ParamTraits<RequestInfo>::Log(const RequestInfo& p, std::string* l) {
  std::string message("RequestInfo: {}");
  //message.append(reinterpret_cast<const char *>(p.buf.data()), p.size);
  LogParam(message, l);
 }

void ParamTraits<base::UUID>::Write(base::Pickle* m, const param_type& p) {
 m->WriteBytes(p.data, 16);
}

bool ParamTraits<base::UUID>::Read(const base::Pickle* m,
                               base::PickleIterator* iter,
                               param_type* r) {
 const char* data;
 if (!iter->ReadBytes(&data, 16)) {
  NOTREACHED();
  return false;
 } 
 param_type uuid(reinterpret_cast<const uint8_t*>(data));
 *r = uuid;
 return true;
}

void ParamTraits<base::UUID>::Log(const param_type& p, std::string* l) {
 l->append(p.to_string());
}

void ParamTraits<common::DomainInfo>::Write(base::Pickle* m, const common::DomainInfo& p) {
  WriteParam(m, p.uuid);
  WriteParam(m, p.name);
 }

 bool ParamTraits<common::DomainInfo>::Read(const base::Pickle* m,
  base::PickleIterator* iter,
  common::DomainInfo* p) {
  
  common::DomainInfo info;

  if (!ReadParam(m, iter, &info.uuid) || !ReadParam(m, iter, &info.name)) {
   *p = common::DomainInfo{};
   return false;
  }

  *p = info;

  return true;
 }

 void ParamTraits<common::DomainInfo>::Log(const common::DomainInfo& p, std::string* l) {
  std::string message("common::DomainInfo: {}");
  //message.append(reinterpret_cast<const char *>(p.buf.data()), p.size);
  LogParam(message, l);
 }

void ParamTraits<common::ShellManifest>::Write(base::Pickle* m, const common::ShellManifest& p) {
  WriteParam(m, p.uuid);
  WriteParam(m, p.name);
  WriteParam(m, p.vendor);
  WriteParam(m, p.version);
 }

 bool ParamTraits<common::ShellManifest>::Read(const base::Pickle* m,
  base::PickleIterator* iter,
  common::ShellManifest* p) {
  
  base::UUID uuid;
  std::string name;
  std::string vendor;
  std::string version;

  if (!ReadParam(m, iter, &uuid) ||
      !ReadParam(m, iter, &name) ||
      !ReadParam(m, iter, &vendor) ||
      !ReadParam(m, iter, &version)) {
   
   *p = common::ShellManifest{};
   return false;
  }

  *p = common::ShellManifest{uuid, name, vendor, version};

  return true;
 }

 void ParamTraits<common::ShellManifest>::Log(const common::ShellManifest& p, std::string* l) {
  std::string message("common::ShellManifest: {uuid: , name: , vendor: , version: }");
  LogParam(message, l);
 }
 
// void ParamTraits<content::PageState>::Write(base::Pickle* m,
//                                             const param_type& p) {
//   WriteParam(m, p.ToEncodedData());
// }

// bool ParamTraits<content::PageState>::Read(const base::Pickle* m,
//                                            base::PickleIterator* iter,
//                                            param_type* r) {
//   std::string data;
//   if (!ReadParam(m, iter, &data))
//     return false;
//   *r = content::PageState::CreateFromEncodedData(data);
//   return true;
// }

// void ParamTraits<content::PageState>::Log(
//     const param_type& p, std::string* l) {
//   l->append("(");
//   LogParam(p.ToEncodedData(), l);
//   l->append(")");
// }

}  // namespace IPC

// Generate param traits write methods.
#include "ipc/param_traits_write_macros.h"
namespace IPC {
#undef CONTENT_PUBLIC_COMMON_COMMON_PARAM_TRAITS_MACROS_H_
#include "core/common/common_param_traits_macros.h"
}  // namespace IPC

// Generate param traits read methods.
#include "ipc/param_traits_read_macros.h"
namespace IPC {
#undef CONTENT_PUBLIC_COMMON_COMMON_PARAM_TRAITS_MACROS_H_
#include "core/common/common_param_traits_macros.h"
}  // namespace IPC

// Generate param traits log methods.
#include "ipc/param_traits_log_macros.h"
namespace IPC {
#undef CONTENT_PUBLIC_COMMON_COMMON_PARAM_TRAITS_MACROS_H_
#include "core/common/common_param_traits_macros.h"
}  // namespace IPC
