// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/common/content_param_traits.h"

#include "base/strings/string_number_conversions.h"
//#include "core/common/input/web_input_event_traits.h"
#include "net/base/ip_endpoint.h"

namespace IPC {

//void ParamTraits<WebInputEventPointer>::Write(Message* m, const param_type& p) {
//  m->WriteData(reinterpret_cast<const char*>(p), p->size);
//}
//
//bool ParamTraits<WebInputEventPointer>::Read(const Message* m,
//                                             base::PickleIterator* iter,
//                                             param_type* r) {
//  const char* data;
//  int data_length;
//  if (!iter->ReadData(&data, &data_length)) {
//    NOTREACHED();
//    return false;
//  }
//  if (data_length < static_cast<int>(sizeof(blink::WebInputEvent))) {
//    NOTREACHED();
//    return false;
//  }
//  param_type event = reinterpret_cast<param_type>(data);
//  // Check that the data size matches that of the event.
//  if (data_length != static_cast<int>(event->size)) {
//    NOTREACHED();
//    return false;
//  }
//  const size_t expected_size_for_type =
//      common::WebInputEventTraits::GetSize(event->type);
//  if (data_length != static_cast<int>(expected_size_for_type)) {
//    NOTREACHED();
//    return false;
//  }
//  *r = event;
//  return true;
//}
//
//void ParamTraits<WebInputEventPointer>::Log(const param_type& p,
//                                            std::string* l) {
//  l->append("(");
//  LogParam(p->size, l);
//  l->append(", ");
//  LogParam(p->type, l);
//  l->append(", ");
//  LogParam(p->timeStampSeconds, l);
//  l->append(")");
//}

}  // namespace IPC

// Generate param traits write methods.
#include "ipc/param_traits_write_macros.h"
namespace IPC {
#undef CONTENT_COMMON_CONTENT_PARAM_TRAITS_MACROS_H_
#include "core/common/content_param_traits_macros.h"
}  // namespace IPC

// Generate param traits read methods.
#include "ipc/param_traits_read_macros.h"
namespace IPC {
#undef CONTENT_COMMON_CONTENT_PARAM_TRAITS_MACROS_H_
#include "core/common/content_param_traits_macros.h"
}  // namespace IPC

// Generate param traits log methods.
#include "ipc/param_traits_log_macros.h"
namespace IPC {
#undef CONTENT_COMMON_CONTENT_PARAM_TRAITS_MACROS_H_
#include "core/common/content_param_traits_macros.h"
}  // namespace IPC
