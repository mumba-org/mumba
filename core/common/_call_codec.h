// Copyright 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_COMMON_CALL_H_
#define MUMBA_COMMON_CALL_H_

#include <string>
#include <map>
#include <vector>

#include "base/macros.h"
#include "core/common/common_data.h"

namespace arangodb {
namespace velocypack {
class Builder;
}  
}

namespace common {

class CallEncoder {
public:
 CallEncoder();
 
 bool EncodeInfo(CallInfo* call, std::string* out);
 bool EncodeResult(CallResult* result, std::string* out);

private: 
 
 bool EncodeCallInfo(arangodb::velocypack::Builder* builder, CallInfo* call);

 DISALLOW_COPY_AND_ASSIGN(CallEncoder);
};

class CallDecoder {
public:
 CallDecoder();

 bool DecodeInfo(const std::string& data, CallInfo* call);
 bool DecodeInfo(const char* data, size_t len, CallInfo* call);
 bool DecodeResult(const std::string& data, CallResult* result);

private:

 DISALLOW_COPY_AND_ASSIGN(CallDecoder); 
};

}

#endif